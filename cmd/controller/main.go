package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	_ "github.com/lib/pq"
	"go.uber.org/automaxprocs/maxprocs"

	"github.com/ahrav/gitleaks-armada/pkg/cluster/kubernetes"
	"github.com/ahrav/gitleaks-armada/pkg/common"
	"github.com/ahrav/gitleaks-armada/pkg/config"
	"github.com/ahrav/gitleaks-armada/pkg/controller"
	"github.com/ahrav/gitleaks-armada/pkg/messaging/kafka"
	"github.com/ahrav/gitleaks-armada/pkg/metrics"
	pg "github.com/ahrav/gitleaks-armada/pkg/storage/postgres"
)

func main() {
	_, _ = maxprocs.Set()

	hostname, err := os.Hostname()
	if err != nil {
		log.Fatalf("failed to get hostname: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ready := &atomic.Bool{}
	healthServer := common.NewHealthServer(ready)
	defer func() {
		if err := healthServer.Server().Shutdown(ctx); err != nil {
			log.Printf("[%s] Error shutting down health server: %v", hostname, err)
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

	dbConn, err := sql.Open("postgres", dsn)
	if err != nil {
		log.Fatalf("[%s] failed to open db: %v", hostname, err)
	}
	defer dbConn.Close()

	if err := runMigrations(dbConn); err != nil {
		log.Fatalf("[%s] failed to run migrations: %v", hostname, err)
	}

	log.Printf("[%s] Migrations applied successfully. Starting application...", hostname)

	podName := os.Getenv("POD_NAME")
	if podName == "" {
		log.Fatalf("[%s] POD_NAME environment variable must be set", hostname)
	}

	namespace := os.Getenv("POD_NAMESPACE")
	if namespace == "" {
		log.Fatalf("[%s] POD_NAMESPACE environment variable must be set", hostname)
	}

	cfg := &kubernetes.K8sConfig{
		Namespace:    namespace,
		LeaderLockID: "scanner-leader-lock",
		Identity:     podName,
		Name:         "scanner-controller",
		WorkerName:   "scanner-worker",
	}

	coord, err := kubernetes.NewCoordinator(cfg)
	if err != nil {
		log.Fatalf("[%s] failed to create coordinator: %v", hostname, err)
	}
	defer coord.Stop()

	kafkaCfg := &kafka.Config{
		Brokers:       strings.Split(os.Getenv("KAFKA_BROKERS"), ","),
		TaskTopic:     os.Getenv("KAFKA_TASK_TOPIC"),
		ResultsTopic:  os.Getenv("KAFKA_RESULTS_TOPIC"),
		RulesTopic:    os.Getenv("KAFKA_RULES_TOPIC"),
		GroupID:       os.Getenv("KAFKA_GROUP_ID"),
		ProgressTopic: os.Getenv("KAFKA_PROGRESS_TOPIC"),
		ClientID:      fmt.Sprintf("scanner-%s", hostname),
	}

	broker, err := common.ConnectKafkaWithRetry(kafkaCfg)
	if err != nil {
		log.Fatalf("[%s] Failed to create Kafka broker: %v", hostname, err)
	}
	log.Printf("[%s] Successfully connected to Kafka", hostname)

	m := metrics.New("scanner_controller")
	go func() {
		if err := metrics.StartServer(":8081"); err != nil {
			log.Printf("[%s] metrics server error: %v", hostname, err)
		}
	}()

	checkpointStorage := pg.NewCheckpointStorage(dbConn)
	enumStateStorage := pg.NewEnumerationStateStorage(dbConn, checkpointStorage)

	configLoader := config.NewFileLoader("/etc/scanner/config/config.yaml")

	ctrl := controller.NewController(
		hostname,
		coord,
		broker,
		enumStateStorage,
		checkpointStorage,
		configLoader,
		m,
	)
	log.Printf("[%s] Controller initialized", hostname)

	ready.Store(true)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	log.Printf("[%s] Starting controller...", hostname)
	leaderChan, err := ctrl.Run(ctx)
	if err != nil {
		log.Fatalf("[%s] failed to run controller: %v", hostname, err)
	}

	// Wait for shutdown signal or leadership.
	select {
	case <-leaderChan:
		log.Printf("[%s] Leadership acquired, controller running...", hostname)
		// Wait for shutdown signal
		<-sigChan
		log.Printf("[%s] Shutdown signal received, stopping controller...", hostname)
	case <-sigChan:
		log.Printf("[%s] Shutdown signal received before leadership, stopping...", hostname)
	case <-ctx.Done():
		log.Printf("[%s] Context cancelled, stopping controller...", hostname)
	}
}

// TODO: consider moving this to an init container.
// runMigrations uses golang-migrate to apply all up migrations from "db/migrations".
func runMigrations(dbConn *sql.DB) error {
	driver, err := postgres.WithInstance(dbConn, new(postgres.Config))
	if err != nil {
		return fmt.Errorf("could not create postgres driver: %w", err)
	}

	const migrationsPath = "file:///app/db/migrations"
	migrations, err := migrate.NewWithDatabaseInstance(migrationsPath, "postgres", driver)
	if err != nil {
		return fmt.Errorf("could not create migrate instance: %w", err)
	}

	if err := migrations.Up(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("migration up failed: %w", err)
	}
	return nil
}
