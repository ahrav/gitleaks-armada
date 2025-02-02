package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/exaring/otelpgx"
	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/pgx"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"go.uber.org/automaxprocs/maxprocs"

	"github.com/ahrav/gitleaks-armada/internal/app/enumeration"
	"github.com/ahrav/gitleaks-armada/internal/app/orchestration"
	"github.com/ahrav/gitleaks-armada/internal/app/rules"
	"github.com/ahrav/gitleaks-armada/internal/config/loaders/fileloader"
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
				"error_time":    r.Time.Format(time.RFC3339),
				"trace_id":      otel.GetTraceID(ctx),
			}

			// Add any error-specific attributes.
			for k, v := range r.Attributes {
				errorAttrs[k] = v
			}

			fmt.Fprintf(os.Stderr, "Error event: %s, details: %v\n",
				r.Message, errorAttrs)
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

	log = logger.NewWithMetadata(os.Stdout, logger.LevelInfo, svcName, traceIDFn, logEvents, metadata)

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

	poolCfg.ConnConfig.Tracer = otelpgx.NewTracer()

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

	coord, err := kubernetes.NewCoordinator(cfg, log)
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

	kafkaCfg := &kafka.Config{
		Brokers:               strings.Split(os.Getenv("KAFKA_BROKERS"), ","),
		EnumerationTaskTopic:  os.Getenv("KAFKA_ENUMERATION_TASK_TOPIC"),
		ScanningTaskTopic:     os.Getenv("KAFKA_SCANNING_TASK_TOPIC"),
		ResultsTopic:          os.Getenv("KAFKA_RESULTS_TOPIC"),
		ProgressTopic:         os.Getenv("KAFKA_PROGRESS_TOPIC"),
		JobMetricsTopic:       os.Getenv("KAFKA_JOB_METRICS_TOPIC"),
		HighPriorityTaskTopic: os.Getenv("KAFKA_HIGH_PRIORITY_TASK_TOPIC"),
		RulesRequestTopic:     os.Getenv("KAFKA_RULES_REQUEST_TOPIC"),
		RulesResponseTopic:    os.Getenv("KAFKA_RULES_RESPONSE_TOPIC"),
		GroupID:               os.Getenv("KAFKA_GROUP_ID"),
		ClientID:              fmt.Sprintf("controller-%s", hostname),
		ServiceType:           serviceType,
	}
	broker, err := kafka.ConnectWithRetry(kafkaCfg, log, metricCollector, tracer)
	if err != nil {
		log.Error(ctx, "failed to create kafka broker", "error", err)
		os.Exit(1)
	}
	log.Info(ctx, "Controller connected to Kafka")

	eventReplayer, err := kafka.NewEventReplayer(
		fmt.Sprintf("controller-%s", hostname),
		&kafka.ReplayConfig{
			Brokers: strings.Split(os.Getenv("KAFKA_BROKERS"), ","),
			// TODO: Add all the other topics which we need to replay events from.
			Topics: []string{
				os.Getenv("KAFKA_JOB_METRICS_TOPIC"),
			},
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
	eventPublisher := kafka.NewDomainEventPublisher(broker, domainEventTranslator)
	enumFactory := enumeration.NewEnumerationFactory(http.DefaultClient, tracer)
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

	configLoader := fileloader.NewFileLoader("/etc/scanner/config/config.yaml")
	rulesService := rules.NewService(rulesStore.NewStore(pool, tracer, metricCollector))
	orchestrator := orchestration.NewOrchestrator(
		hostname,
		coord,
		broker,
		eventPublisher,
		domainEventReplayer,
		enumCoord,
		rulesService,
		scanTaskRepo,
		scanJobRepo,
		enumStateStorage,
		configLoader,
		log,
		metricCollector,
		tracer,
	)
	defer orchestrator.Stop(ctx)

	log.Info(ctx, "Orchestrator initialized")
	ready.Store(true)

	if err := orchestrator.Run(ctx); err != nil {
		log.Error(ctx, "failed to run orchestrator", "error", err)
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
