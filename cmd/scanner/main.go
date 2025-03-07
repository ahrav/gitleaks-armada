// Scanner is a component that executes scanning tasks to find secrets in source code.
//
// The scanner supports two communication modes:
//
//  1. System Default Mode (SCANNER_GROUP_NAME=system_default or unset):
//     Uses Kafka for communication with the controller.
//
//  2. On-premise Mode (SCANNER_GROUP_NAME=any other value):
//     In a full implementation, would use gRPC for direct communication with the scanner gateway.
//     Currently, this falls back to Kafka for demonstration purposes.
//
// This allows deploying scanners in central clusters (using Kafka) or in on-premise
// environments where scanners connect directly to the gateway via gRPC.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"go.opentelemetry.io/otel/trace"
	"go.uber.org/automaxprocs/maxprocs"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/ahrav/gitleaks-armada/internal/app/scanning"
	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	grpcbus "github.com/ahrav/gitleaks-armada/internal/infra/eventbus/grpc"
	"github.com/ahrav/gitleaks-armada/internal/infra/eventbus/kafka"
	progressreporter "github.com/ahrav/gitleaks-armada/internal/infra/progress_reporter"
	"github.com/ahrav/gitleaks-armada/internal/infra/scanner"
	"github.com/ahrav/gitleaks-armada/pkg/common"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
	"github.com/ahrav/gitleaks-armada/pkg/common/otel"
	pb "github.com/ahrav/gitleaks-armada/proto"
)

func main() {
	_, _ = maxprocs.Set()

	hostname, err := os.Hostname()
	if err != nil {
		log.Fatalf("Failed to get hostname: %v", err)
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

			fmt.Fprintf(os.Stderr, "Error event: %s, details: %s\n",
				r.Message, errorAttrsJSON)
		},
	}

	traceIDFn := func(ctx context.Context) string {
		return otel.GetTraceID(ctx)
	}

	const svcName = "scanner-service"
	metadata := map[string]string{
		"service":   svcName,
		"hostname":  hostname,
		"pod":       os.Getenv("POD_NAME"),
		"namespace": os.Getenv("POD_NAMESPACE"),
		"app":       "scanner",
	}

	// TODO: Adjust the min log level via env var.
	log = logger.NewWithMetadata(os.Stdout, logger.LevelDebug, svcName, traceIDFn, logEvents, metadata)

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

	scannerID := fmt.Sprintf("scanner-%s", hostname)

	// Create shared Kafka client.
	kafkaClient, err := kafka.NewClient(&kafka.ClientConfig{
		Brokers:     strings.Split(os.Getenv("KAFKA_BROKERS"), ","),
		GroupID:     os.Getenv("KAFKA_GROUP_ID"),
		ClientID:    scannerID,
		ServiceType: "scanner",
	})
	if err != nil {
		log.Error(ctx, "failed to create kafka client", "error", err)
		os.Exit(1)
	}
	defer kafkaClient.Close()

	// Create a Kafka client for broadcast events where every scanner instance
	// needs to receive the message (e.g., job pause events)
	broadcastClient, err := kafka.NewClient(&kafka.ClientConfig{
		Brokers:     strings.Split(os.Getenv("KAFKA_BROKERS"), ","),
		GroupID:     fmt.Sprintf("scanner-broadcast-%s", hostname), // Unique group per pod for broadcast events
		ClientID:    fmt.Sprintf("scanner-broadcast-%s", hostname),
		ServiceType: "scanner",
	})
	if err != nil {
		log.Error(ctx, "failed to create broadcast kafka client", "error", err)
		os.Exit(1)
	}
	defer broadcastClient.Close()

	kafkaCfg := &kafka.EventBusConfig{
		TaskCreatedTopic:      os.Getenv("KAFKA_TASK_CREATED_TOPIC"),
		ScanningTaskTopic:     os.Getenv("KAFKA_SCANNING_TASK_TOPIC"),
		ResultsTopic:          os.Getenv("KAFKA_RESULTS_TOPIC"),
		ProgressTopic:         os.Getenv("KAFKA_PROGRESS_TOPIC"),
		HighPriorityTaskTopic: os.Getenv("KAFKA_HIGH_PRIORITY_TASK_TOPIC"),
		JobLifecycleTopic:     os.Getenv("KAFKA_JOB_LIFECYCLE_TOPIC"),
		ScannerLifecycleTopic: os.Getenv("KAFKA_SCANNER_LIFECYCLE_TOPIC"),
		RulesRequestTopic:     os.Getenv("KAFKA_RULES_REQUEST_TOPIC"),
		RulesResponseTopic:    os.Getenv("KAFKA_RULES_RESPONSE_TOPIC"),
		GroupID:               os.Getenv("KAFKA_GROUP_ID"),
		ClientID:              scannerID,
	}

	// Create a separate config for broadcast events.
	broadcastCfg := &kafka.EventBusConfig{
		JobLifecycleTopic: os.Getenv("KAFKA_JOB_LIFECYCLE_TOPIC"),
		GroupID:           fmt.Sprintf("scanner-broadcast-%s", hostname),
		ClientID:          fmt.Sprintf("scanner-broadcast-%s", hostname),
		ServiceType:       "scanner",
	}

	const defaultScannerGroupName = "system_default"
	scannerGroupName := os.Getenv("SCANNER_GROUP_NAME")

	var (
		eventBus              events.EventBus
		broadcastEventBus     events.EventBus
		eventPublisher        events.DomainEventPublisher
		domainEventTranslator *events.DomainEventTranslator
	)

	if scannerGroupName == defaultScannerGroupName || scannerGroupName == "" {
		// System default scanners use Kafka directly for communication.
		log.Info(ctx, "Using Kafka event bus for system_default scanner group")

		kafkaEventBus, err := kafka.ConnectEventBus(kafkaCfg, kafkaClient, log, metricsCollector, tracer)
		if err != nil {
			log.Error(ctx, "failed to create kafka broker", "error", err)
			os.Exit(1)
		}
		log.Info(ctx, "Scanner connected to Kafka")

		// Create a separate event bus for broadcast events using Kafka.
		kafkaBroadcastBus, err := kafka.ConnectEventBus(broadcastCfg, broadcastClient, log, metricsCollector, tracer)
		if err != nil {
			log.Error(ctx, "failed to create broadcast kafka broker", "error", err)
			os.Exit(1)
		}
		log.Info(ctx, "Scanner connected to broadcast Kafka broker")

		eventBus = kafkaEventBus
		broadcastEventBus = kafkaBroadcastBus
		domainEventTranslator = events.NewDomainEventTranslator(kafka.NewKafkaPositionTranslator())
		eventPublisher = kafka.NewDomainEventPublisher(eventBus, domainEventTranslator)
	} else {
		// On-prem scanners use a gRPC event bus for direct communication with the gateway.
		// This is done via a gRPC stream connection to the gateway.
		// This avoids exposing the Kafka cluster to non-native scanners.
		log.Info(ctx, "Using gRPC event bus for on-prem scanner group", "group", scannerGroupName)

		gatewayAddr := os.Getenv("GATEWAY_ADDR")
		if gatewayAddr == "" {
			gatewayAddr = "scanner-gateway:9090" // Default gateway address
		}

		authToken := os.Getenv("GATEWAY_AUTH_TOKEN")
		if authToken == "" {
			log.Warn(ctx, "No gateway auth token provided, authentication disabled")
		}
		timeoutStr := os.Getenv("GATEWAY_CONNECTION_TIMEOUT")
		connectionTimeout := 30 * time.Second // Default timeout
		if timeoutStr != "" {
			timeout, err := time.ParseDuration(timeoutStr)
			if err == nil && timeout > 0 {
				connectionTimeout = timeout
			}
		}

		// Create main gRPC stream for scanner-specific events.
		grpcEventBusConfig := &grpcbus.EventBusConfig{
			ScannerName:       scannerID,
			ServiceType:       "scanner",
			AuthToken:         authToken,
			ConnectionTimeout: connectionTimeout,
			MaxRetries:        5,
			RetryBaseDelay:    500 * time.Millisecond,
			RetryMaxDelay:     30 * time.Second,
		}

		conn, err := dialGateway(ctx, gatewayAddr)
		if err != nil {
			log.Error(ctx, "failed to dial gateway", "error", err)
			os.Exit(1)
		}
		defer conn.Close()

		// Connect to the gateway using gRPC
		grpcEventBus, err := connectToRegularGateway(
			ctx,
			conn,
			grpcEventBusConfig,
			log,
			tracer,
		)
		if err != nil {
			log.Error(ctx, "failed to connect to gateway", "error", err)
			os.Exit(1)
		}
		log.Info(ctx, "Scanner connected to gateway")

		// Create a separate gRPC stream for broadcast events.
		grpcBroadcastConfig := &grpcbus.EventBusConfig{
			ScannerName:       scannerID,
			ServiceType:       "scanner_broadcast",
			AuthToken:         authToken,
			ConnectionTimeout: connectionTimeout,
			MaxRetries:        5,
			RetryBaseDelay:    500 * time.Millisecond,
			RetryMaxDelay:     30 * time.Second,
		}

		// Connect to the gateway's broadcast stream.
		grpcBroadcastBus, err := connectToBroadcastGateway(
			ctx,
			conn,
			grpcBroadcastConfig,
			log,
			tracer,
		)
		if err != nil {
			log.Error(ctx, "failed to connect to gateway broadcast stream", "error", err)
			os.Exit(1)
		}
		log.Info(ctx, "Scanner connected to gateway broadcast stream")

		// Use gRPC as the event bus implementation.
		eventBus = grpcEventBus
		broadcastEventBus = grpcBroadcastBus
		domainEventTranslator = events.NewDomainEventTranslator(nil) // gRPC doesn't need a position translator
		eventPublisher = grpcbus.NewDomainEventPublisher(eventBus, domainEventTranslator)
	}

	// Now use the selected event bus and publisher for the scanner.

	// Update scannerRegistrar initialization to use the variables.
	scannerRegistrar := scanning.NewScannerRegistrar(scanning.ScannerConfig{
		Name:         scannerID,
		GroupName:    scannerGroupName,
		Hostname:     hostname,
		Version:      os.Getenv("SCANNER_VERSION"),
		Capabilities: strings.Split(os.Getenv("SCANNER_CAPABILITIES"), ","),
	}, eventPublisher, log, tracer)
	if err := scannerRegistrar.Register(ctx); err != nil {
		log.Error(ctx, "failed to register scanner", "error", err)
		os.Exit(1)
	}
	log.Info(ctx, "Scanner registered with controller")

	// Start the scanner heartbeat agent.
	// This will send heartbeat events to the controller(s) to indicate that the scanner is alive.
	scannerHeartbeatAgent := scanning.NewScannerHeartbeatAgent(scannerID, eventPublisher, log, tracer)
	if err := scannerHeartbeatAgent.Start(ctx); err != nil {
		log.Error(ctx, "failed to start scanner heartbeat agent", "error", err)
		os.Exit(1)
	}
	log.Info(ctx, "Scanner heartbeat agent started")

	gitleaksScanner, err := scanner.NewGitLeaks(scannerID, eventPublisher, log, tracer, metricsCollector)
	if err != nil {
		log.Error(ctx, "failed to create gitleaks scanner", "error", err)
		os.Exit(1)
	}

	scanOrchestrator := scanning.NewScanOrchestrator(
		scannerID,
		eventBus,
		broadcastEventBus,
		eventPublisher,
		progressreporter.New(scannerID, eventPublisher, tracer),
		gitleaksScanner,
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
	if err := scanOrchestrator.Run(ctx); err != nil {
		log.Error(ctx, "Scanner error", "error", err)
	}

	<-ctx.Done()
	log.Info(ctx, "Scanner shutdown complete")
}

// dialGateway creates a single connection to the gateway.
// TODO: interceptors, connection opts, etc.
func dialGateway(ctx context.Context, gatewayAddr string) (*grpc.ClientConn, error) {
	conn, err := grpc.NewClient(gatewayAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("failed to dial gateway: %w", err)
	}
	return conn, nil
}

// connectToRegularGateway establishes a regular connection to the gateway.
func connectToRegularGateway(
	ctx context.Context,
	conn *grpc.ClientConn,
	cfg *grpcbus.EventBusConfig,
	log *logger.Logger,
	tracer trace.Tracer,
) (*grpcbus.EventBus, error) {
	client := pb.NewScannerGatewayServiceClient(conn)
	stream, err := client.ConnectScanner(ctx)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to start regular stream: %w", err)
	}

	eventBus, err := grpcbus.NewScannerEventBus(
		stream,
		cfg,
		log,
		tracer,
	)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to create regular gRPC event bus: %w", err)
	}

	return eventBus, nil
}

// connectToBroadcastGateway establishes a broadcast connection to the gateway.
func connectToBroadcastGateway(
	ctx context.Context,
	conn *grpc.ClientConn,
	cfg *grpcbus.EventBusConfig,
	log *logger.Logger,
	tracer trace.Tracer,
) (*grpcbus.EventBus, error) {
	client := pb.NewScannerGatewayServiceClient(conn)
	stream, err := client.SubscribeToBroadcasts(ctx)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to start broadcast stream: %w", err)
	}

	broadcastBus, err := grpcbus.NewBroadcastEventBus(
		stream,
		cfg,
		log,
		tracer,
	)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to create broadcast gRPC event bus: %w", err)
	}

	return broadcastBus, nil
}
