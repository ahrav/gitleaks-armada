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
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/exaring/otelpgx"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/automaxprocs/maxprocs"

	"github.com/ahrav/gitleaks-armada/internal/api"
	"github.com/ahrav/gitleaks-armada/internal/api/debug"
	"github.com/ahrav/gitleaks-armada/internal/api/mux"
	"github.com/ahrav/gitleaks-armada/internal/api/routes"
	"github.com/ahrav/gitleaks-armada/internal/app/commands/scanning"
	appScanning "github.com/ahrav/gitleaks-armada/internal/app/scanning"
	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/infra/eventbus/kafka"
	scanningStore "github.com/ahrav/gitleaks-armada/internal/infra/storage/scanning/postgres"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
	"github.com/ahrav/gitleaks-armada/pkg/common/otel"
)

var build = "develop"

const (
	serviceType = "client-api"
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

	svcName := fmt.Sprintf("CLIENT-API-%s", hostname)
	metadata := map[string]string{
		"service":   svcName,
		"hostname":  hostname,
		"pod":       os.Getenv("POD_NAME"),
		"namespace": os.Getenv("POD_NAMESPACE"),
		"app":       serviceType,
	}

	// TODO: Use env var to set log level.
	log = logger.NewWithMetadata(os.Stdout, logger.LevelDebug, svcName, traceIDFn, logEvents, metadata)

	ctx := context.Background()

	if err := run(ctx, log, hostname); err != nil {
		log.Error(ctx, "startup", "err", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, log *logger.Logger, hostname string) error {
	// -------------------------------------------------------------------------
	// GOMAXPROCS
	log.Info(ctx, "startup", "GOMAXPROCS", runtime.GOMAXPROCS(0))

	// -------------------------------------------------------------------------
	// Configuration
	cfg := struct {
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
			ServiceName string  `conf:"default:client-api"`
			Probability float64 `conf:"default:0.05"`
		}
	}{}

	// -------------------------------------------------------------------------
	// Database Configuration
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		user := os.Getenv("POSTGRES_USER")
		password := os.Getenv("POSTGRES_PASSWORD")
		host := os.Getenv("POSTGRES_HOST")
		dbname := os.Getenv("POSTGRES_DB")

		if user == "" {
			user = "postgres"
		}
		if password == "" {
			password = "postgres"
		}
		if host == "" {
			host = "postgres"
		}
		if dbname == "" {
			dbname = "secretscanner"
		}

		dsn = fmt.Sprintf("postgres://%s:%s@%s:5432/%s?sslmode=disable",
			user, password, host, dbname)
	}

	poolCfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return fmt.Errorf("parsing db config: %w", err)
	}
	poolCfg.MinConns = 5
	poolCfg.MaxConns = 25
	// TODO: Collect metrics for the pool and expose them via prometheus.

	poolCfg.ConnConfig.Tracer = otelpgx.NewTracer()
	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return fmt.Errorf("creating db pool: %w", err)
	}
	defer pool.Close()

	// -------------------------------------------------------------------------
	// Initialize Event Bus
	log.Info(ctx, "startup", "status", "initializing event bus")

	// Create Kafka client using environment variables
	kafkaClient, err := kafka.NewClient(&kafka.ClientConfig{
		Brokers:     strings.Split(os.Getenv("KAFKA_BROKERS"), ","),
		GroupID:     os.Getenv("KAFKA_GROUP_ID"),
		ClientID:    os.Getenv("OTEL_SERVICE_NAME"),
		ServiceType: serviceType,
	})
	if err != nil {
		return fmt.Errorf("creating kafka client: %w", err)
	}
	defer kafkaClient.Close()

	// -------------------------------------------------------------------------
	// Start Tracing Support
	log.Info(ctx, "startup", "status", "initializing tracing support")

	prob, err := strconv.ParseFloat(os.Getenv("OTEL_SAMPLING_RATIO"), 64)
	if err != nil {
		return fmt.Errorf("parsing sampling ratio: %w", err)
	}

	traceProvider, teardown, err := otel.InitTelemetry(log, otel.Config{
		ServiceName:      os.Getenv("OTEL_SERVICE_NAME"),
		ExporterEndpoint: os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"),
		ExcludedRoutes: map[string]struct{}{
			"/v1/readiness": {},
			"/v1/liveness":  {},
			"/debug":        {},
			"/metrics":      {},
		},
		Probability: prob,
		ResourceAttributes: map[string]string{
			"library.language": "go",
			"k8s.pod.name":     os.Getenv("POD_NAME"),
			"k8s.namespace":    os.Getenv("POD_NAMESPACE"),
			"k8s.container.id": hostname,
		},
		InsecureExporter: true, // TODO: Come back to setup TLS
	})
	if err != nil {
		return fmt.Errorf("starting tracing: %w", err)
	}
	defer teardown(ctx)

	tracer := traceProvider.Tracer(os.Getenv("OTEL_SERVICE_NAME"))

	// -------------------------------------------------------------------------
	// Start Debug Service

	go func() {
		debugHost := fmt.Sprintf("%s:%s",
			os.Getenv("DEBUG_HOST"),
			os.Getenv("DEBUG_PORT"),
		)
		log.Info(ctx, "startup", "status", "debug router started", "host", debugHost)

		if err := http.ListenAndServe(debugHost, debug.Mux()); err != nil {
			log.Error(ctx, "shutdown", "status", "debug router closed", "host", debugHost, "msg", err)
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
		Brokers:           strings.Split(os.Getenv("KAFKA_BROKERS"), ","),
		JobLifecycleTopic: os.Getenv("KAFKA_JOB_LIFECYCLE_TOPIC"),
		GroupID:           os.Getenv("KAFKA_GROUP_ID"),
		ClientID:          os.Getenv("OTEL_SERVICE_NAME"),
		ServiceType:       serviceType,
	}, kafkaClient, log, metricCollector, tracer)
	if err != nil {
		return fmt.Errorf("connecting event bus: %w", err)
	}
	defer bus.Close()

	kafkaPosTranslator := kafka.NewKafkaPositionTranslator()
	domainEventTranslator := events.NewDomainEventTranslator(kafkaPosTranslator)
	eventBus := kafka.NewDomainEventPublisher(bus, domainEventTranslator)

	cmdHandler := scanning.NewCommandHandler(log, tracer, eventBus)

	scannerRepo := scanningStore.NewScannerStore(pool, tracer)
	scannerService := appScanning.NewScannerService(hostname, scannerRepo, log, tracer)

	// Initialize centralized mux configuration with all dependencies.
	cfgMux := mux.Config{
		Build:          build,
		Log:            log,
		DB:             pool,
		EventBus:       eventBus,
		CmdHandler:     cmdHandler,
		Tracer:         tracer,
		ScannerService: scannerService,
	}

	// Create the web API with all routes and middleware.
	webAPI := mux.WebAPI(cfgMux,
		routes.Routes(),
		mux.WithCORS(cfg.Web.CORSAllowedOrigins),
	)

	// Configure and start the API server.
	apiAddr := fmt.Sprintf("%s:%s", os.Getenv("API_HOST"), os.Getenv("API_PORT"))
	api := http.Server{
		Addr:         apiAddr,
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
