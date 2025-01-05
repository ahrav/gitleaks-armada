package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/pgx"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"go.uber.org/automaxprocs/maxprocs"

	"github.com/ahrav/gitleaks-armada/internal/app/enumeration"
	"github.com/ahrav/gitleaks-armada/internal/cluster/kubernetes"
	"github.com/ahrav/gitleaks-armada/internal/controller"
	"github.com/ahrav/gitleaks-armada/internal/controller/metrics"
	enumDomain "github.com/ahrav/gitleaks-armada/internal/domain/enumeration"
	enumStore "github.com/ahrav/gitleaks-armada/internal/enumeration/storage/postgres"
	"github.com/ahrav/gitleaks-armada/internal/infra/eventbus/kafka"
	"github.com/ahrav/gitleaks-armada/internal/rules"
	rulesStore "github.com/ahrav/gitleaks-armada/internal/rules/storage/postgres"
	"github.com/ahrav/gitleaks-armada/pkg/common"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
	"github.com/ahrav/gitleaks-armada/pkg/common/otel"
	"github.com/ahrav/gitleaks-armada/pkg/config"
)

func main() {
	_, _ = maxprocs.Set()

	hostname, err := os.Hostname()
	if err != nil {
		log.Fatalf("failed to get hostname: %v", err)
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

	svcName := fmt.Sprintf("CONTROLLER-%s", hostname)
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

	pool, err := pgxpool.New(ctx, dsn)
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
		LeaderLockID: "scanner-leader-lock",
		Identity:     podName,
		Name:         "scanner-controller",
		WorkerName:   "scanner-worker",
	}

	coord, err := kubernetes.NewCoordinator(cfg, log)
	if err != nil {
		log.Error(ctx, "failed to create coordinator", "error", err)
		os.Exit(1)
	}
	defer coord.Stop()

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

	metricCollector := metrics.New()
	go func() {
		if err := common.RunMetricsServer(":8081"); err != nil {
			log.Error(ctx, "metrics server error", "error", err)
		}
	}()

	tracer := traceProvider.Tracer(os.Getenv("TEMPO_SERVICE_NAME"))

	kafkaCfg := &kafka.Config{
		Brokers:       strings.Split(os.Getenv("KAFKA_BROKERS"), ","),
		TaskTopic:     os.Getenv("KAFKA_TASK_TOPIC"),
		ResultsTopic:  os.Getenv("KAFKA_RESULTS_TOPIC"),
		RulesTopic:    os.Getenv("KAFKA_RULES_TOPIC"),
		GroupID:       os.Getenv("KAFKA_GROUP_ID"),
		ProgressTopic: os.Getenv("KAFKA_PROGRESS_TOPIC"),
		ClientID:      fmt.Sprintf("controller-%s", hostname),
	}
	broker, err := kafka.ConnectWithRetry(kafkaCfg, log, metricCollector, tracer)
	if err != nil {
		log.Error(ctx, "failed to create kafka broker", "error", err)
		os.Exit(1)
	}
	log.Info(ctx, "Controller connected to Kafka")

	configLoader := config.NewFileLoader("/etc/scanner/config/config.yaml")
	checkpointStorage := enumStore.NewCheckpointStore(pool, tracer)
	enumStateStorage := enumStore.NewEnumerationSessionStateStore(pool, checkpointStorage, tracer)
	eventPublisher := kafka.NewKafkaDomainEventPublisher(broker)
	enumFactory := enumeration.NewEnumerationFactory(http.DefaultClient, nil, tracer)

	enumService := enumeration.NewOrchestrator(
		enumStateStorage,
		checkpointStorage,
		enumFactory,
		enumDomain.NewLifecycleService(),
		eventPublisher,
		configLoader,
		log,
		metricCollector,
		tracer,
	)

	rulesService := rules.NewRuleService(rulesStore.NewStore(pool, tracer, metricCollector))
	ctrl := controller.NewController(
		hostname,
		coord,
		broker,
		eventPublisher,
		enumService,
		rulesService,
		configLoader,
		log,
		metricCollector,
		tracer,
	)
	defer ctrl.Stop(ctx)

	log.Info(ctx, "Controller initialized")

	ready.Store(true)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	log.Info(ctx, "Starting controller...")
	leaderChan, err := ctrl.Run(ctx)
	if err != nil {
		log.Error(ctx, "failed to run controller", "error", err)
		os.Exit(1)
	}

	// Wait for shutdown signal or leadership.
	select {
	case <-leaderChan:
		log.Info(ctx, "Leadership acquired, controller running...")
		// Wait for shutdown signal
		<-sigChan
		log.Info(ctx, "Shutdown signal received, stopping controller...")
	case <-sigChan:
		log.Info(ctx, "Shutdown signal received before leadership, stopping...")
	case <-ctx.Done():
		log.Info(ctx, "Context cancelled, stopping controller...")
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
