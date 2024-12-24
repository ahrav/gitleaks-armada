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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ready := &atomic.Bool{}
	healthServer := common.NewHealthServer(ready)
	defer func() {
		if err := healthServer.Server().Shutdown(ctx); err != nil {
			log.Printf("Error shutting down health server: %v", err)
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
		log.Fatalf("failed to open db: %v", err)
	}
	defer dbConn.Close()

	if err := runMigrations(dbConn); err != nil {
		log.Fatalf("failed to run migrations: %v", err)
	}

	log.Println("Migrations applied successfully. Starting application...")

	podName := os.Getenv("POD_NAME")
	if podName == "" {
		log.Fatal("POD_NAME environment variable must be set")
	}

	namespace := os.Getenv("POD_NAMESPACE")
	if namespace == "" {
		log.Fatal("POD_NAMESPACE environment variable must be set")
	}

	cfg := &kubernetes.K8sConfig{
		Namespace:    namespace,
		LeaderLockID: "scanner-leader-lock",
		Identity:     podName,
		Name:         "scanner-orchestrator",
		WorkerName:   "scanner-worker",
	}

	coord, err := kubernetes.NewCoordinator(cfg)
	if err != nil {
		log.Fatalf("failed to create coordinator: %v", err)
	}
	defer coord.Stop()

	hostname, err := os.Hostname()
	if err != nil {
		log.Fatalf("failed to get hostname: %v", err)
	}

	kafkaCfg := &kafka.Config{
		Brokers:       strings.Split(os.Getenv("KAFKA_BROKERS"), ","),
		TaskTopic:     os.Getenv("KAFKA_TASK_TOPIC"),
		ResultsTopic:  os.Getenv("KAFKA_RESULTS_TOPIC"),
		GroupID:       os.Getenv("KAFKA_GROUP_ID"),
		ProgressTopic: os.Getenv("KAFKA_PROGRESS_TOPIC"),
		ClientID:      fmt.Sprintf("scanner-%s", hostname),
	}

	broker, err := common.ConnectKafkaWithRetry(kafkaCfg)
	if err != nil {
		log.Fatalf("Failed to create Kafka broker: %v", err)
	}
	log.Println("Successfully connected to Kafka")

	m := metrics.New("scanner_controller")
	go func() {
		if err := metrics.StartServer(":8081"); err != nil {
			log.Printf("metrics server error: %v", err)
		}
	}()

	checkpointStorage := pg.NewCheckpointStorage(dbConn)
	enumStateStorage := pg.NewEnumerationStateStorage(dbConn, checkpointStorage)

	configLoader := config.NewFileLoader("/etc/scanner/config/config.yaml")

	ctrl := controller.NewController(coord, broker, enumStateStorage, checkpointStorage, configLoader, m)
	log.Println("Controller initialized")

	ready.Store(true)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	log.Println("Starting orchestrator...")
	leaderChan, err := ctrl.Run(ctx)
	if err != nil {
		log.Fatalf("failed to run orchestrator: %v", err)
	}

	// Wait for shutdown signal or leadership.
	select {
	case <-leaderChan:
		log.Println("Leadership acquired, orchestrator running...")
		// Wait for shutdown signal
		<-sigChan
		log.Println("Shutdown signal received, stopping orchestrator...")
	case <-sigChan:
		log.Println("Shutdown signal received before leadership, stopping...")
	case <-ctx.Done():
		log.Println("Context cancelled, stopping orchestrator...")
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
