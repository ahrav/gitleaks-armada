package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"go.uber.org/automaxprocs/maxprocs"

	"github.com/ahrav/gitleaks-armada/internal/api"
	"github.com/ahrav/gitleaks-armada/internal/api/debug"
	"github.com/ahrav/gitleaks-armada/internal/api/mux"
	"github.com/ahrav/gitleaks-armada/internal/api/routes"
	"github.com/ahrav/gitleaks-armada/internal/app/commands/scanning"
	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/infra/eventbus/kafka"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
	"github.com/ahrav/gitleaks-armada/pkg/common/otel"
)

var build = "develop"

const (
	serviceType = "api-gateway"
)

func main() {
	// Set the correct number of threads for the service
	_, _ = maxprocs.Set()

	hostname, err := os.Hostname()
	if err != nil {
		log.Fatalf("failed to get hostname: %v", err)
	}

	var log *logger.Logger

	logEvents := logger.Events{
		Error: func(ctx context.Context, r logger.Record) {
			errorAttrs := map[string]any{
				"error_message": r.Message,
				"error_time":    r.Time.UTC().Format(time.RFC3339),
				"trace_id":      otel.GetTraceID(ctx),
			}

			// Add any error-specific attributes.
			for k, v := range r.Attributes {
				errorAttrs[k] = v
			}

			errorAttrsJSON, err := json.Marshal(errorAttrs)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to marshal error attributes: %v\n", err)
				return
			}

			// Output the error event with valid JSON details.
			fmt.Fprintf(os.Stderr, "Error event: %s, details: %s\n",
				r.Message, errorAttrsJSON)
		},
	}

	traceIDFn := func(ctx context.Context) string {
		return otel.GetTraceID(ctx)
	}

	svcName := fmt.Sprintf("API-GATEWAY-%s", hostname)
	metadata := map[string]string{
		"service":   svcName,
		"hostname":  hostname,
		"pod":       os.Getenv("POD_NAME"),
		"namespace": os.Getenv("POD_NAMESPACE"),
		"app":       serviceType,
	}

	log = logger.NewWithMetadata(os.Stdout, logger.LevelInfo, svcName, traceIDFn, logEvents, metadata)

	ctx := context.Background()

	if err := run(ctx, log); err != nil {
		log.Error(ctx, "startup", "err", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, log *logger.Logger) error {
	// -------------------------------------------------------------------------
	// GOMAXPROCS

	log.Info(ctx, "startup", "GOMAXPROCS", runtime.GOMAXPROCS(0))

	// -------------------------------------------------------------------------
	// Configuration

	cfg := struct {
		// conf.Version
		Web struct {
			ReadTimeout        time.Duration `conf:"default:5s"`
			WriteTimeout       time.Duration `conf:"default:10s"`
			IdleTimeout        time.Duration `conf:"default:120s"`
			ShutdownTimeout    time.Duration `conf:"default:20s"`
			APIHost            string        `conf:"default:0.0.0.0"`
			APIPort            string        `conf:"default:6000"`
			DebugHost          string        `conf:"default:0.0.0.0:6010"`
			CORSAllowedOrigins []string      `conf:"default:*"`
		}
		Kafka struct {
			Brokers              []string `conf:"required"`
			GroupID              string   `conf:"required"`
			EnumerationTaskTopic string   `conf:"required"`
			ScanningTaskTopic    string   `conf:"required"`
			ResultsTopic         string   `conf:"required"`
			ProgressTopic        string   `conf:"required"`
			JobMetricsTopic      string   `conf:"required"`
		}
		Tempo struct {
			Host        string  `conf:"default:tempo:4317"`
			ServiceName string  `conf:"default:api-gateway"`
			Probability float64 `conf:"default:0.05"`
		}
	}{
		// Version: conf.Version{
		// 	Build: build,
		// 	Desc:  "GitLeaks Armada API Gateway",
		// },
	}

	// const prefix = "ARMADA"
	// help, err := conf.Parse(prefix, &cfg)
	// if err != nil {
	// 	if errors.Is(err, conf.ErrHelpWanted) {
	// 		fmt.Println(help)
	// 		return nil
	// 	}
	// 	return fmt.Errorf("parsing config: %w", err)
	// }

	// -------------------------------------------------------------------------
	// App Starting

	log.Info(ctx, "starting service", "version", build)
	defer log.Info(ctx, "shutdown complete")

	// out, err := conf.String(&cfg)
	// if err != nil {
	// 	return fmt.Errorf("generating config for output: %w", err)
	// }
	// log.Info(ctx, "startup", "config", out)

	// expvar.NewString("build").Set(cfg.Build)

	// -------------------------------------------------------------------------
	// Initialize Event Bus

	log.Info(ctx, "startup", "status", "initializing event bus")

	kafkaClient, err := kafka.NewClient(&kafka.ClientConfig{
		Brokers:     cfg.Kafka.Brokers,
		GroupID:     cfg.Kafka.GroupID,
		ClientID:    cfg.Tempo.ServiceName,
		ServiceType: "api-gateway",
	})
	if err != nil {
		return fmt.Errorf("creating kafka client: %w", err)
	}
	defer kafkaClient.Close()

	// -------------------------------------------------------------------------
	// Start Tracing Support

	log.Info(ctx, "startup", "status", "initializing tracing support")

	traceProvider, teardown, err := otel.InitTelemetry(log, otel.Config{
		ServiceName:      cfg.Tempo.ServiceName,
		ExporterEndpoint: cfg.Tempo.Host,
		ExcludedRoutes: map[string]struct{}{
			"/v1/health":    {},
			"/v1/readiness": {},
		},
		Probability: cfg.Tempo.Probability,
	})
	if err != nil {
		return fmt.Errorf("starting tracing: %w", err)
	}
	defer teardown(ctx)

	tracer := traceProvider.Tracer(cfg.Tempo.ServiceName)

	// -------------------------------------------------------------------------
	// Start Debug Service

	go func() {
		log.Info(ctx, "startup", "status", "debug router started", "host", cfg.Web.DebugHost)

		if err := http.ListenAndServe(cfg.Web.DebugHost, debug.Mux()); err != nil {
			log.Error(ctx, "shutdown", "status", "debug router closed", "host", cfg.Web.DebugHost, "msg", err)
		}
	}()

	// -------------------------------------------------------------------------
	// Start API Service

	log.Info(ctx, "startup", "status", "initializing API support")

	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, syscall.SIGINT, syscall.SIGTERM)

	mp := otel.GetMeterProvider()
	metricCollector, err := api.NewAPIMetrics(mp)
	if err != nil {
		return fmt.Errorf("creating metrics collector: %w", err)
	}

	bus, err := kafka.ConnectEventBus(&kafka.EventBusConfig{
		Brokers:              cfg.Kafka.Brokers,
		EnumerationTaskTopic: cfg.Kafka.EnumerationTaskTopic,
		ScanningTaskTopic:    cfg.Kafka.ScanningTaskTopic,
		ResultsTopic:         cfg.Kafka.ResultsTopic,
		ProgressTopic:        cfg.Kafka.ProgressTopic,
		JobMetricsTopic:      cfg.Kafka.JobMetricsTopic,
		GroupID:              cfg.Kafka.GroupID,
		ClientID:             cfg.Tempo.ServiceName,
		ServiceType:          "api-gateway",
	}, kafkaClient, log, metricCollector, tracer)
	if err != nil {
		return fmt.Errorf("connecting event bus: %w", err)
	}
	defer bus.Close()

	kafkaPosTranslator := kafka.NewKafkaPositionTranslator()
	domainEventTranslator := events.NewDomainEventTranslator(kafkaPosTranslator)
	eventBus := kafka.NewDomainEventPublisher(bus, domainEventTranslator)

	cmdHandler := scanning.NewCommandHandler(log, tracer, eventBus)

	// Initialize mux configuration
	muxConfig := mux.Config{
		Build:      build,
		Log:        log,
		EventBus:   eventBus,
		CmdHandler: cmdHandler,
		Tracer:     tracer,
	}

	// Construct web API
	webAPI := mux.WebAPI(muxConfig,
		routes.Routes(),
		mux.WithCORS(cfg.Web.CORSAllowedOrigins),
	)

	api := http.Server{
		Addr:         fmt.Sprintf("%s:%s", cfg.Web.APIHost, cfg.Web.APIPort),
		Handler:      webAPI,
		ReadTimeout:  cfg.Web.ReadTimeout,
		WriteTimeout: cfg.Web.WriteTimeout,
		IdleTimeout:  cfg.Web.IdleTimeout,
		ErrorLog:     logger.NewStdLogger(log, logger.LevelError),
	}

	serverErrors := make(chan error, 1)

	go func() {
		log.Info(ctx, "startup", "status", "api router started", "host", api.Addr)
		serverErrors <- api.ListenAndServe()
	}()

	// -------------------------------------------------------------------------
	// Shutdown

	select {
	case err := <-serverErrors:
		return fmt.Errorf("server error: %w", err)

	case sig := <-shutdown:
		log.Info(ctx, "shutdown", "status", "shutdown started", "signal", sig)
		defer log.Info(ctx, "shutdown", "status", "shutdown complete", "signal", sig)

		ctx, cancel := context.WithTimeout(ctx, cfg.Web.ShutdownTimeout)
		defer cancel()

		if err := api.Shutdown(ctx); err != nil {
			return fmt.Errorf("could not stop server gracefully: %w", err)
		}
	}

	return nil
}
