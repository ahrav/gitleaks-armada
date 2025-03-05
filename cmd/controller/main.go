package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/exaring/otelpgx"
	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/pgx"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"go.uber.org/automaxprocs/maxprocs"

	"github.com/ahrav/gitleaks-armada/internal/app/config"
	"github.com/ahrav/gitleaks-armada/internal/app/enumeration"
	"github.com/ahrav/gitleaks-armada/internal/app/orchestration"
	"github.com/ahrav/gitleaks-armada/internal/app/rules"
	"github.com/ahrav/gitleaks-armada/internal/app/scanning"
	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/infra/cluster/kubernetes"
	"github.com/ahrav/gitleaks-armada/internal/infra/eventbus/kafka"
	enumStore "github.com/ahrav/gitleaks-armada/internal/infra/storage/enumeration/postgres"
	rulesStore "github.com/ahrav/gitleaks-armada/internal/infra/storage/rules/postgres"
	scanningStore "github.com/ahrav/gitleaks-armada/internal/infra/storage/scanning/postgres"
	"github.com/ahrav/gitleaks-armada/pkg/common"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
	"github.com/ahrav/gitleaks-armada/pkg/common/otel"
)

const (
	serviceType = "controller"
)

func main() {
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

	svcName := fmt.Sprintf("CONTROLLER-%s", hostname)
	metadata := map[string]string{
		"service":   svcName,
		"hostname":  hostname,
		"pod":       os.Getenv("POD_NAME"),
		"namespace": os.Getenv("POD_NAMESPACE"),
		"app":       serviceType,
	}

	// TODO: Adjust the min log level via env var.
	log = logger.NewWithMetadata(os.Stdout, logger.LevelDebug, svcName, traceIDFn, logEvents, metadata)

	// Setup signal handling
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM, os.Interrupt)
	defer signal.Stop(sigCh)

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
		log.Error(ctx, "failed to parse db config", "error", err)
		os.Exit(1)
	}
	poolCfg.MinConns = 5
	poolCfg.MaxConns = 20
	poolCfg.ConnConfig.Tracer = otelpgx.NewTracer()
	// TODO: Collect metrics for the pool and expose them via prometheus.

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		log.Error(ctx, "failed to open db", "error", err)
		os.Exit(1)
	}
	defer pool.Close()

	if err := runMigrations(ctx, pool); err != nil {
		log.Error(ctx, "failed to run migrations", "error", err)
		os.Exit(1)
	}

	log.Info(ctx, "Migrations applied successfully. Starting application...")

	podName := os.Getenv("POD_NAME")
	if podName == "" {
		log.Error(ctx, "POD_NAME environment variable must be set", "error", err)
		os.Exit(1)
	}

	namespace := os.Getenv("POD_NAMESPACE")
	if namespace == "" {
		log.Error(ctx, "POD_NAMESPACE environment variable must be set", "error", err)
		os.Exit(1)
	}

	cfg := &kubernetes.K8sConfig{
		Namespace:    namespace,
		LeaderLockID: "controller-leader-lock",
		Identity:     podName,
		Name:         serviceType,
		WorkerName:   "worker",
	}

	coord, err := kubernetes.NewCoordinator(hostname, cfg, log, tracer)
	if err != nil {
		log.Error(ctx, "failed to create coordinator", "error", err)
		os.Exit(1)
	}
	defer coord.Stop()

	mp := otel.GetMeterProvider()
	metricCollector, err := orchestration.NewOrchestrationMetrics(mp)
	if err != nil {
		log.Error(ctx, "failed to create metrics collector", "error", err)
		os.Exit(1)
	}

	kafkaClient, err := kafka.NewClient(&kafka.ClientConfig{
		Brokers:     strings.Split(os.Getenv("KAFKA_BROKERS"), ","),
		GroupID:     os.Getenv("KAFKA_GROUP_ID"),
		ClientID:    svcName,
		ServiceType: serviceType,
	})
	if err != nil {
		log.Error(ctx, "failed to create kafka client", "error", err)
		os.Exit(1)
	}
	defer kafkaClient.Close()

	// Create a separate client for broadcast events.
	broadcastClient, err := kafka.NewClient(&kafka.ClientConfig{
		Brokers:     strings.Split(os.Getenv("KAFKA_BROKERS"), ","),
		GroupID:     fmt.Sprintf("controller-broadcast-%s", hostname),
		ClientID:    fmt.Sprintf("controller-broadcast-%s", hostname),
		ServiceType: serviceType,
	})
	if err != nil {
		log.Error(ctx, "failed to create broadcast kafka client", "error", err)
		os.Exit(1)
	}
	defer broadcastClient.Close()

	kafkaCfg := &kafka.EventBusConfig{
		Brokers:               strings.Split(os.Getenv("KAFKA_BROKERS"), ","),
		TaskCreatedTopic:      os.Getenv("KAFKA_TASK_CREATED_TOPIC"),
		ScanningTaskTopic:     os.Getenv("KAFKA_SCANNING_TASK_TOPIC"),
		ResultsTopic:          os.Getenv("KAFKA_RESULTS_TOPIC"),
		ProgressTopic:         os.Getenv("KAFKA_PROGRESS_TOPIC"),
		HighPriorityTaskTopic: os.Getenv("KAFKA_HIGH_PRIORITY_TASK_TOPIC"),
		RulesRequestTopic:     os.Getenv("KAFKA_RULES_REQUEST_TOPIC"),
		RulesResponseTopic:    os.Getenv("KAFKA_RULES_RESPONSE_TOPIC"),
		JobLifecycleTopic:     os.Getenv("KAFKA_JOB_LIFECYCLE_TOPIC"),
		ScannerLifecycleTopic: os.Getenv("KAFKA_SCANNER_LIFECYCLE_TOPIC"),
		GroupID:               os.Getenv("KAFKA_GROUP_ID"),
		ClientID:              svcName,
		ServiceType:           serviceType,
	}

	// Broadcast event bus config.
	broadcastCfg := &kafka.EventBusConfig{
		JobBroadcastTopic: os.Getenv("KAFKA_JOB_BROADCAST_TOPIC"),
		GroupID:           fmt.Sprintf("controller-broadcast-%s", hostname),
		ClientID:          fmt.Sprintf("controller-broadcast-%s", hostname),
		ServiceType:       serviceType,
	}

	eventBus, err := kafka.ConnectEventBus(kafkaCfg, kafkaClient, log, metricCollector, tracer)
	if err != nil {
		log.Error(ctx, "failed to connect event bus", "error", err)
		os.Exit(1)
	}

	broadcastEventBus, err := kafka.ConnectEventBus(broadcastCfg, broadcastClient, log, metricCollector, tracer)
	if err != nil {
		log.Error(ctx, "failed to connect broadcast event bus", "error", err)
		os.Exit(1)
	}

	topicMapper := config.NewTopicMapper(kafkaCfg)

	eventReplayer, err := kafka.NewEventReplayer(
		&kafka.ReplayConfig{
			ClientID:    kafkaCfg.ClientID,
			Brokers:     strings.Split(os.Getenv("KAFKA_BROKERS"), ","),
			TopicMapper: topicMapper,
		},
		log,
		metricCollector,
		tracer,
	)
	if err != nil {
		log.Error(ctx, "failed to create event replayer", "error", err)
		os.Exit(1)
	}

	kafkaPosTranslator := kafka.NewKafkaPositionTranslator()
	domainEventTranslator := events.NewDomainEventTranslator(kafkaPosTranslator)
	domainEventReplayer := kafka.NewDomainEventReplayer(eventReplayer, domainEventTranslator)

	scanTargetRepo := enumStore.NewScanTargetStore(pool, tracer)
	githubTargetRepo := enumStore.NewGithubRepositoryStore(pool, tracer)
	urlTargetRepo := enumStore.NewURLTargetStore(pool, tracer)
	checkpointStorage := enumStore.NewCheckpointStore(pool, tracer)
	enumStateStorage := enumStore.NewEnumerationSessionStateStore(pool, checkpointStorage, tracer)
	eventPublisher := kafka.NewDomainEventPublisher(eventBus, domainEventTranslator)
	broadcastPublisher := kafka.NewDomainEventPublisher(broadcastEventBus, domainEventTranslator)
	enumFactory := enumeration.NewEnumerationFactory(hostname, http.DefaultClient, log, tracer)
	enumTaskStorage := enumStore.NewTaskStore(pool, tracer)
	batchStorage := enumStore.NewBatchStore(pool, checkpointStorage, tracer)
	enumCoord := enumeration.NewCoordinator(
		hostname,
		scanTargetRepo,
		githubTargetRepo,
		urlTargetRepo,
		batchStorage,
		enumStateStorage,
		checkpointStorage,
		enumTaskStorage,
		enumFactory,
		log,
		metricCollector,
		tracer,
	)

	scanJobRepo := scanningStore.NewJobStore(pool, tracer)
	scanTaskRepo := scanningStore.NewTaskStore(pool, tracer)
	scannerRepo := scanningStore.NewScannerStore(pool, tracer)
	scannerService := scanning.NewScannerService(hostname, scannerRepo, log, tracer)

	rulesService := rules.NewService(rulesStore.NewStore(pool, tracer, metricCollector))
	orchestrator, err := orchestration.NewOrchestrator(
		hostname,
		coord,
		eventBus,
		eventPublisher,
		broadcastPublisher,
		domainEventReplayer,
		enumCoord,
		rulesService,
		scanTaskRepo,
		scanJobRepo,
		scannerService,
		log,
		metricCollector,
		tracer,
	)
	if err != nil {
		log.Error(ctx, "failed to create orchestrator", "error", err)
		os.Exit(1)
	}
	defer orchestrator.Stop(ctx)

	log.Info(ctx, "Orchestrator initialized")
	ready.Store(true)

	errCh := make(chan error, 1)
	go func() {
		if err := orchestrator.Run(ctx); err != nil {
			errCh <- err
		}
	}()

	// Wait for either a signal or orchestrator error.
	select {
	case sig := <-sigCh:
		log.Info(ctx, "Received shutdown signal", "signal", sig)
		cancel() // Signal orchestrator to stop

		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer shutdownCancel()

		// Close components in order.
		if err := eventBus.Close(); err != nil {
			log.Error(shutdownCtx, "Failed to close event bus", "error", err)
		}
		if err := broadcastEventBus.Close(); err != nil {
			log.Error(shutdownCtx, "Failed to close broadcast event bus", "error", err)
		}
		if err := orchestrator.Stop(shutdownCtx); err != nil {
			log.Error(shutdownCtx, "Failed to stop orchestrator", "error", err)
		}

	case err := <-errCh:
		log.Error(ctx, "Orchestrator error", "error", err)
		os.Exit(1)
	}
}

// TODO: consider moving this to an init container.
// runMigrations uses golang-migrate to apply all up migrations from "db/migrations".
// runMigrations acquires a single pgx connection from the pool, runs migrations,
// and then releases the connection back to the pool.
func runMigrations(ctx context.Context, pool *pgxpool.Pool) error {
	// Acquire a connection from the pool
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("could not acquire connection: %w", err)
	}
	defer conn.Release() // Ensure the connection is released

	db := stdlib.OpenDBFromPool(pool)
	if err != nil {
		return fmt.Errorf("could not open db from pool: %w", err)
	}

	driver, err := pgx.WithInstance(db, &pgx.Config{})
	if err != nil {
		return fmt.Errorf("could not create pgx driver: %w", err)
	}

	const migrationsPath = "file:///app/db/migrations"
	m, err := migrate.NewWithDatabaseInstance(migrationsPath, "postgres", driver)
	if err != nil {
		return fmt.Errorf("could not create migrate instance: %w", err)
	}

	// Run the migrations
	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("migration up failed: %w", err)
	}

	return nil
}
