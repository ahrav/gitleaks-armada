package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"go.uber.org/automaxprocs/maxprocs"

	"github.com/ahrav/gitleaks-armada/internal/app/scanning"
	"github.com/ahrav/gitleaks-armada/internal/infra/eventbus/kafka"
	progressreporter "github.com/ahrav/gitleaks-armada/internal/infra/progress_reporter"
	"github.com/ahrav/gitleaks-armada/internal/infra/scanner"
	"github.com/ahrav/gitleaks-armada/pkg/common"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
	"github.com/ahrav/gitleaks-armada/pkg/common/otel"
)

func main() {
	_, _ = maxprocs.Set()

	hostname, err := os.Hostname()
	if err != nil {
		log.Fatalf("Failed to get hostname: %v", err)
	}

	var log *logger.Logger

	events := logger.Events{
		Error: func(ctx context.Context, r logger.Record) {
			errorAttrs := map[string]any{
				"error_message": r.Message,
				"error_time":    r.Time.Format(time.RFC3339),
				"trace_id":      otel.GetTraceID(ctx),
			}

			// Add any error-specific attributes.
			for k, v := range r.Attributes {
				errorAttrs[k] = v
			}

			log.Error(ctx, "Error event triggered", "error_details", errorAttrs)
		},
	}

	traceIDFn := func(ctx context.Context) string {
		return otel.GetTraceID(ctx)
	}

	svcName := fmt.Sprintf("SCANNER-%s", hostname)
	metadata := map[string]string{
		"service":   svcName,
		"hostname":  hostname,
		"pod":       os.Getenv("POD_NAME"),
		"namespace": os.Getenv("POD_NAMESPACE"),
		"app":       "scanner",
	}

	log = logger.NewWithMetadata(os.Stdout, logger.LevelInfo, svcName, traceIDFn, events, metadata)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize telemetry.
	prob, err := strconv.ParseFloat(os.Getenv("OTEL_SAMPLING_RATIO"), 64)
	if err != nil {
		log.Error(ctx, "failed to parse TEMPO_PROBABILITY", "error", err)
		os.Exit(1)
	}
	tp, telemetryTeardown, err := otel.InitTelemetry(log, otel.Config{
		ServiceName:      os.Getenv("OTEL_SERVICE_NAME"),
		ExporterEndpoint: os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"),
		ExcludedRoutes: map[string]struct{}{
			"/v1/health":    {},
			"/v1/readiness": {},
		},
		Probability: prob,
		ResourceAttributes: map[string]string{
			"library.language": "go",
			"k8s.pod.name":     os.Getenv("POD_NAME"),
			"k8s.namespace":    os.Getenv("POD_NAMESPACE"),
			"k8s.container.id": hostname,
		},
		InsecureExporter: true, // TODO: Come back to setup TLS.
	})
	if err != nil {
		log.Error(ctx, "failed to initialize telemetry", "error", err)
		os.Exit(1)
	}
	defer telemetryTeardown(ctx)

	tracer := tp.Tracer(os.Getenv("OTEL_SERVICE_NAME"))

	ready := &atomic.Bool{}
	healthServer := common.NewHealthServer(ready)
	defer func() {
		if err := healthServer.Server().Shutdown(ctx); err != nil {
			log.Error(ctx, "Error shutting down health server", "error", err)
		}
	}()

	mp := otel.GetMeterProvider()
	metricsCollector, err := scanning.NewScannerMetrics(mp)
	if err != nil {
		log.Error(ctx, "failed to create metrics collector", "error", err)
		os.Exit(1)
	}

	kafkaCfg := &kafka.Config{
		Brokers:               strings.Split(os.Getenv("KAFKA_BROKERS"), ","),
		EnumerationTaskTopic:  os.Getenv("KAFKA_ENUMERATION_TASK_TOPIC"),
		ScanningTaskTopic:     os.Getenv("KAFKA_SCANNING_TASK_TOPIC"),
		ResultsTopic:          os.Getenv("KAFKA_RESULTS_TOPIC"),
		ProgressTopic:         os.Getenv("KAFKA_PROGRESS_TOPIC"),
		HighPriorityTaskTopic: os.Getenv("KAFKA_HIGH_PRIORITY_TASK_TOPIC"),
		RulesRequestTopic:     os.Getenv("KAFKA_RULES_REQUEST_TOPIC"),
		RulesResponseTopic:    os.Getenv("KAFKA_RULES_RESPONSE_TOPIC"),
		GroupID:               os.Getenv("KAFKA_GROUP_ID"),
		ClientID:              fmt.Sprintf("scanner-%s", hostname),
	}
	broker, err := kafka.ConnectWithRetry(kafkaCfg, log, metricsCollector, tracer)
	if err != nil {
		log.Error(ctx, "failed to create kafka broker", "error", err)
		os.Exit(1)
	}
	log.Info(ctx, "Scanner connected to Kafka")

	eventPublisher := kafka.NewKafkaDomainEventPublisher(broker)
	scannerService := scanning.NewScannerService(
		hostname,
		broker,
		eventPublisher,
		progressreporter.New(eventPublisher, tracer),
		scanner.NewGitLeaks(ctx, eventPublisher, log, tracer, metricsCollector),
		log,
		metricsCollector,
		tracer,
	)

	ready.Store(true)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Info(ctx, "Scanner shutting down...")
		cancel()
	}()

	log.Info(ctx, "Starting scanner...")
	if err := scannerService.Run(ctx); err != nil {
		log.Error(ctx, "Scanner error", "error", err)
	}

	<-ctx.Done()
	log.Info(ctx, "Scanner shutdown complete")
}
