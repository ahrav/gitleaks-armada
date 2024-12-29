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

	"go.uber.org/automaxprocs/maxprocs"

	"github.com/ahrav/gitleaks-armada/pkg/common"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
	"github.com/ahrav/gitleaks-armada/pkg/common/otel"
	"github.com/ahrav/gitleaks-armada/pkg/messaging/kafka"
	"github.com/ahrav/gitleaks-armada/pkg/scanner"
	"github.com/ahrav/gitleaks-armada/pkg/scanner/metrics"
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
			log.Info(ctx, "******* SEND ALERT *******")
		},
	}

	traceIDFn := func(ctx context.Context) string {
		return otel.GetTraceID(ctx)
	}

	svcName := fmt.Sprintf("SCANNER-%s", hostname)
	log = logger.NewWithEvents(os.Stdout, logger.LevelInfo, svcName, traceIDFn, events)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ready := &atomic.Bool{}
	healthServer := common.NewHealthServer(ready)
	defer func() {
		if err := healthServer.Server().Shutdown(ctx); err != nil {
			log.Error(ctx, "Error shutting down health server", "error", err)
		}
	}()

	// Initialize tracing.
	prob, err := strconv.ParseFloat(os.Getenv("TEMPO_PROBABILITY"), 64)
	if err != nil {
		log.Error(ctx, "failed to parse TEMPO_PROBABILITY", "error", err)
		os.Exit(1)
	}

	log.Info(ctx, "Initializing tracing support")
	traceProvider, tracingTeardown, err := otel.InitTracing(log, otel.Config{
		ServiceName: os.Getenv("TEMPO_SERVICE_NAME"),
		Host:        os.Getenv("TEMPO_HOST"),
		ExcludedRoutes: map[string]struct{}{
			"/v1/health":    {},
			"/v1/readiness": {},
		},
		Probability: prob,
		ResourceAttributes: map[string]string{
			"k8s.pod.name":     os.Getenv("POD_NAME"),
			"k8s.namespace":    os.Getenv("POD_NAMESPACE"),
			"k8s.container.id": hostname,
		},
	})
	if err != nil {
		log.Error(ctx, "failed to initialize tracing", "error", err)
		os.Exit(1)
	}
	defer tracingTeardown(ctx)

	tracer := traceProvider.Tracer(os.Getenv("TEMPO_SERVICE_NAME"))

	kafkaCfg := &kafka.Config{
		Brokers:      strings.Split(os.Getenv("KAFKA_BROKERS"), ","),
		TaskTopic:    os.Getenv("KAFKA_TASK_TOPIC"),
		ResultsTopic: os.Getenv("KAFKA_RESULTS_TOPIC"),
		RulesTopic:   os.Getenv("KAFKA_RULES_TOPIC"),
		GroupID:      os.Getenv("KAFKA_GROUP_ID"),
		ClientID:     fmt.Sprintf("scanner-%s", hostname),
	}
	broker, err := kafka.ConnectWithRetry(kafkaCfg, log, tracer)
	if err != nil {
		log.Error(ctx, "failed to create kafka broker", "error", err)
		os.Exit(1)
	}

	log.Info(ctx, "Scanner connected to Kafka")

	metricsCollector := metrics.New()
	scanner := scanner.NewScanner(ctx, hostname, broker, metricsCollector, log, tracer)

	go func() {
		if err := common.RunMetricsServer(":8081"); err != nil {
			log.Error(ctx, "metrics server error", "error", err)
		}
	}()

	ready.Store(true)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Info(ctx, "Scanner shutting down...")
		cancel()
	}()

	log.Info(ctx, "Starting scanner...")
	if err := scanner.Run(ctx); err != nil {
		log.Error(ctx, "Scanner error", "error", err)
	}

	<-ctx.Done()
	log.Info(ctx, "Scanner shutdown complete")
}
