package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"maps"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	gateway "github.com/ahrav/gitleaks-armada/internal/gateway/service"
	"github.com/ahrav/gitleaks-armada/internal/infra/eventbus/kafka"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
	"github.com/ahrav/gitleaks-armada/pkg/common/otel"
	"github.com/ahrav/gitleaks-armada/pkg/common/timeutil"
	pb "github.com/ahrav/gitleaks-armada/proto"
)

var build = "develop"

const (
	serviceType = "scanner-gateway"
)

func main() {
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
			maps.Copy(errorAttrs, r.Attributes)

			errorAttrsJSON, err := json.Marshal(errorAttrs)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to marshal error attributes: %v\n", err)
				return
			}

			fmt.Fprintf(os.Stderr, "Error event: %s, details: %s\n",
				r.Message, errorAttrsJSON)
		},
	}

	traceIDFn := func(ctx context.Context) string {
		return otel.GetTraceID(ctx)
	}

	svcName := fmt.Sprintf("SCANNER-GATEWAY-%s", hostname)
	metadata := map[string]string{
		"service":   svcName,
		"hostname":  hostname,
		"pod":       os.Getenv("POD_NAME"),
		"namespace": os.Getenv("POD_NAMESPACE"),
		"app":       serviceType,
	}

	// TODO: Adjust the min log level via env var.
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
		GRPC struct {
			Port            string        `conf:"default:9090"`
			ShutdownTimeout time.Duration `conf:"default:20s"`
		}
		HTTP struct {
			Port            string        `conf:"default:8080"`
			ReadTimeout     time.Duration `conf:"default:5s"`
			WriteTimeout    time.Duration `conf:"default:10s"`
			IdleTimeout     time.Duration `conf:"default:120s"`
			ShutdownTimeout time.Duration `conf:"default:20s"`
		}
		Kafka struct {
			Brokers               []string `conf:"required"`
			GroupID               string   `conf:"required"`
			JobLifecycleTopic     string   `conf:"required"`
			ScannerLifecycleTopic string   `conf:"required"`
			TaskCreatedTopic      string   `conf:"required"`
			ScanningTaskTopic     string   `conf:"required"`
			HighPriorityTaskTopic string   `conf:"required"`
			ResultsTopic          string   `conf:"required"`
			ProgressTopic         string   `conf:"required"`
			RulesRequestTopic     string   `conf:"required"`
			RulesResponseTopic    string   `conf:"required"`
			JobBroadcastTopic     string   `conf:"required"`
		}
		Tempo struct {
			Host        string  `conf:"default:tempo:4317"`
			ServiceName string  `conf:"default:scanner-gateway"`
			Probability float64 `conf:"default:0.05"`
		}
	}{}

	// Set configuration from environment variables.
	cfg.GRPC.Port = os.Getenv("GRPC_PORT")
	if cfg.GRPC.Port == "" {
		cfg.GRPC.Port = "9090"
	}

	cfg.HTTP.Port = os.Getenv("HTTP_PORT")
	if cfg.HTTP.Port == "" {
		cfg.HTTP.Port = "8080"
	}

	cfg.HTTP.ReadTimeout = 5 * time.Second
	cfg.HTTP.WriteTimeout = 10 * time.Second
	cfg.HTTP.IdleTimeout = 120 * time.Second
	cfg.HTTP.ShutdownTimeout = 20 * time.Second
	cfg.GRPC.ShutdownTimeout = 20 * time.Second

	// -------------------------------------------------------------------------
	// Initialize Event Bus
	log.Info(ctx, "startup", "status", "initializing event buses")

	// Create Kafka client using environment variables for regular events
	kafkaClient, err := kafka.NewClient(&kafka.ClientConfig{
		Brokers:     strings.Split(os.Getenv("KAFKA_BROKERS"), ","),
		GroupID:     os.Getenv("KAFKA_GROUP_ID"),
		ClientID:    os.Getenv("OTEL_SERVICE_NAME"),
		ServiceType: serviceType,
	})
	if err != nil {
		return fmt.Errorf("creating regular kafka client: %w", err)
	}
	defer kafkaClient.Close()

	// Create a separate client for broadcast events
	broadcastClient, err := kafka.NewClient(&kafka.ClientConfig{
		Brokers:     strings.Split(os.Getenv("KAFKA_BROKERS"), ","),
		GroupID:     fmt.Sprintf("gateway-broadcast-%s", hostname),
		ClientID:    fmt.Sprintf("gateway-broadcast-%s", hostname),
		ServiceType: serviceType,
	})
	if err != nil {
		return fmt.Errorf("creating broadcast kafka client: %w", err)
	}
	defer broadcastClient.Close()

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
			"/health":    {},
			"/readiness": {},
			"/metrics":   {},
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

	// Create gateway metrics - using a no-op implementation for now.
	gatewayMetrics := newGatewayMetrics()

	kafkaCfg := &kafka.EventBusConfig{
		Brokers:               strings.Split(os.Getenv("KAFKA_BROKERS"), ","),
		JobLifecycleTopic:     os.Getenv("KAFKA_JOB_LIFECYCLE_TOPIC"),
		ScannerLifecycleTopic: os.Getenv("KAFKA_SCANNER_LIFECYCLE_TOPIC"),
		TaskCreatedTopic:      os.Getenv("KAFKA_TASK_CREATED_TOPIC"),
		ScanningTaskTopic:     os.Getenv("KAFKA_SCANNING_TASK_TOPIC"),
		HighPriorityTaskTopic: os.Getenv("KAFKA_HIGH_PRIORITY_TASK_TOPIC"),
		ResultsTopic:          os.Getenv("KAFKA_RESULTS_TOPIC"),
		ProgressTopic:         os.Getenv("KAFKA_PROGRESS_TOPIC"),
		RulesRequestTopic:     os.Getenv("KAFKA_RULES_REQUEST_TOPIC"),
		RulesResponseTopic:    os.Getenv("KAFKA_RULES_RESPONSE_TOPIC"),
		GroupID:               os.Getenv("KAFKA_GROUP_ID"),
		ClientID:              os.Getenv("OTEL_SERVICE_NAME"),
		ServiceType:           serviceType,
	}

	broadcastCfg := &kafka.EventBusConfig{
		JobBroadcastTopic: os.Getenv("KAFKA_JOB_BROADCAST_TOPIC"),
		GroupID:           fmt.Sprintf("gateway-broadcast-%s", hostname),
		ClientID:          fmt.Sprintf("gateway-broadcast-%s", hostname),
		ServiceType:       serviceType,
	}

	regularBus, err := kafka.ConnectEventBus(kafkaCfg, kafkaClient, log, gatewayMetrics, tracer)
	if err != nil {
		return fmt.Errorf("connecting regular event bus: %w", err)
	}
	defer regularBus.Close()

	broadcastBus, err := kafka.ConnectEventBus(broadcastCfg, broadcastClient, log, gatewayMetrics, tracer)
	if err != nil {
		return fmt.Errorf("connecting broadcast event bus: %w", err)
	}
	defer broadcastBus.Close()

	domainEventTranslator := events.NewDomainEventTranslator(kafka.NewKafkaPositionTranslator())
	eventPublisher := kafka.NewDomainEventPublisher(regularBus, domainEventTranslator)

	// -------------------------------------------------------------------------
	// Initialize Gateway Service
	log.Info(ctx, "startup", "status", "initializing gateway support")

	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, syscall.SIGINT, syscall.SIGTERM)

	const defaultAckTimeout = 30 * time.Second
	ackTracker := gateway.NewAcknowledgmentTracker(log)
	regSubscriptionHandler := gateway.NewEventSubscriptionHandler(
		regularBus,
		ackTracker,
		defaultAckTimeout,
		timeutil.Default(),
		log,
		tracer,
	)
	broadcastSubscriptionHandler := gateway.NewEventSubscriptionHandler(
		broadcastBus,
		ackTracker,
		defaultAckTimeout,
		timeutil.Default(),
		log,
		tracer,
	)
	// Initialize the gateway service with both event buses.
	authKey := os.Getenv("AUTH_KEY")
	gatewayService := gateway.NewService(
		eventPublisher,
		regSubscriptionHandler,
		broadcastSubscriptionHandler,
		log,
		gatewayMetrics,
		tracer,
		gateway.WithAuthKey(authKey),
	)

	// -------------------------------------------------------------------------
	// Start HTTP Server for health checks

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
	})
	mux.HandleFunc("/readiness", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "Ready")
	})

	httpAddr := fmt.Sprintf("0.0.0.0:%s", cfg.HTTP.Port)
	httpServer := http.Server{
		Addr:         httpAddr,
		Handler:      mux,
		ReadTimeout:  cfg.HTTP.ReadTimeout,
		WriteTimeout: cfg.HTTP.WriteTimeout,
		IdleTimeout:  cfg.HTTP.IdleTimeout,
		ErrorLog:     logger.NewStdLogger(log, logger.LevelError),
	}

	httpServerErrors := make(chan error, 1)

	go func() {
		log.Info(ctx, "startup", "status", "http health server started", "host", httpAddr)
		httpServerErrors <- httpServer.ListenAndServe()
	}()

	// -------------------------------------------------------------------------
	// Start gRPC Server

	// TODO: include metrics provider.
	handler := otelgrpc.NewServerHandler(
		otelgrpc.WithTracerProvider(traceProvider),
	)

	grpcServer := grpc.NewServer(
		grpc.StatsHandler(handler),
	)
	pb.RegisterScannerGatewayServiceServer(grpcServer, gatewayService)

	healthServer := health.NewServer()
	healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(grpcServer, healthServer)

	reflection.Register(grpcServer)

	grpcAddr := fmt.Sprintf("0.0.0.0:%s", cfg.GRPC.Port)
	grpcListener, err := net.Listen("tcp", grpcAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on gRPC port: %w", err)
	}

	grpcServerErrors := make(chan error, 1)

	go func() {
		log.Info(ctx, "startup", "status", "gRPC server started", "host", grpcAddr)
		grpcServerErrors <- grpcServer.Serve(grpcListener)
	}()

	// -------------------------------------------------------------------------
	// Shutdown

	select {
	case err := <-httpServerErrors:
		return fmt.Errorf("http server error: %w", err)

	case err := <-grpcServerErrors:
		return fmt.Errorf("grpc server error: %w", err)

	case sig := <-shutdown:
		log.Info(ctx, "shutdown", "status", "shutdown started", "signal", sig)
		defer log.Info(ctx, "shutdown", "status", "shutdown complete", "signal", sig)

		// Give outstanding requests a deadline for completion.
		ctx, cancel := context.WithTimeout(ctx, cfg.HTTP.ShutdownTimeout)
		defer cancel()

		// Gracefully shut down the HTTP server.
		log.Info(ctx, "shutdown", "status", "stopping HTTP server")
		if err := httpServer.Shutdown(ctx); err != nil {
			httpServer.Close()
			return fmt.Errorf("could not stop HTTP server gracefully: %w", err)
		}

		// Gracefully stop the gRPC server.
		log.Info(ctx, "shutdown", "status", "stopping gRPC server")
		grpcServer.GracefulStop()
	}

	return nil
}

// GatewayMetrics provides a no-op implementation of the metrics interface
type GatewayMetrics struct{}

func newGatewayMetrics() *GatewayMetrics {
	return &GatewayMetrics{}
}

// Implement all the required metrics methods
func (g *GatewayMetrics) IncMessagePublished(ctx context.Context, topic string)       {}
func (g *GatewayMetrics) IncMessageConsumed(ctx context.Context, topic string)        {}
func (g *GatewayMetrics) IncPublishError(ctx context.Context, topic string)           {}
func (g *GatewayMetrics) IncConsumeError(ctx context.Context, topic string)           {}
func (g *GatewayMetrics) IncConnectedScanners(ctx context.Context)                    {}
func (g *GatewayMetrics) DecConnectedScanners(ctx context.Context)                    {}
func (g *GatewayMetrics) SetConnectedScanners(ctx context.Context, count int)         {}
func (g *GatewayMetrics) IncMessagesReceived(ctx context.Context, messageType string) {}
func (g *GatewayMetrics) IncMessagesSent(ctx context.Context, messageType string)     {}
func (g *GatewayMetrics) IncTranslationErrors(ctx context.Context, direction string)  {}
func (g *GatewayMetrics) IncAuthErrors(ctx context.Context)                           {}
func (g *GatewayMetrics) IncScannerRegistrations(ctx context.Context)                 {}
func (g *GatewayMetrics) IncScannerHeartbeats(ctx context.Context)                    {}
func (g *GatewayMetrics) IncScanResults(ctx context.Context)                          {}
func (g *GatewayMetrics) IncTaskProgress(ctx context.Context)                         {}
