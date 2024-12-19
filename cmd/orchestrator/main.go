package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/ahrav/gitleaks-armada/pkg/orchestration"
	"github.com/ahrav/gitleaks-armada/pkg/orchestration/kubernetes"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

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

	monitor, err := kubernetes.NewWorkerMonitor(cfg)
	if err != nil {
		log.Fatalf("failed to create worker monitor: %v", err)
	}
	defer monitor.Stop()

	brokers := strings.Split(os.Getenv("KAFKA_BROKERS"), ",")
	kafkaCfg := &orchestration.KafkaConfig{
		Brokers:      brokers,
		TaskTopic:    os.Getenv("KAFKA_TASK_TOPIC"),
		ResultsTopic: os.Getenv("KAFKA_RESULTS_TOPIC"),
		GroupID:      "orchestrator-group",
	}

	broker, err := orchestration.NewKafkaBroker(kafkaCfg)
	if err != nil {
		log.Fatalf("Failed to create Kafka broker: %v", err)
	}

	orch := orchestration.NewOrchestrator(coord, monitor, broker)

	log.Println("Starting orchestrator...")
	ready, err := orch.Run(ctx)
	if err != nil {
		log.Fatalf("failed to run orchestrator: %v", err)
	}

	// Wait for leadership or shutdown.
	select {
	case <-ready:
		log.Println("Leadership acquired, orchestrator running...")
		<-sigChan
		log.Println("Shutdown signal received, stopping orchestrator...")
	case <-ctx.Done():
		log.Println("Context cancelled, stopping orchestrator...")
	}
}
