package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"

	"go.uber.org/automaxprocs/maxprocs"

	"github.com/ahrav/gitleaks-armada/pkg/cluster/kubernetes"
	"github.com/ahrav/gitleaks-armada/pkg/common"
	"github.com/ahrav/gitleaks-armada/pkg/controller"
	"github.com/ahrav/gitleaks-armada/pkg/messaging/kafka"
	"github.com/ahrav/gitleaks-armada/pkg/metrics"
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

	kafkaCfg := &kafka.KafkaConfig{
		Brokers:      strings.Split(os.Getenv("KAFKA_BROKERS"), ","),
		TaskTopic:    os.Getenv("KAFKA_TASK_TOPIC"),
		ResultsTopic: os.Getenv("KAFKA_RESULTS_TOPIC"),
		GroupID:      "orchestrator-group",
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

	enumStateStorage := controller.NewInMemoryEnumerationStateStorage()
	checkpointStorage := controller.NewInMemoryCheckpointStorage()

	ctrl := controller.NewController(coord, broker, enumStateStorage, checkpointStorage, m)
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
