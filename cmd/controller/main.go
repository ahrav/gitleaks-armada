package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"

	"go.uber.org/automaxprocs/maxprocs"

	"github.com/ahrav/gitleaks-armada/pkg/metrics"
	"github.com/ahrav/gitleaks-armada/pkg/orchestration"
	"github.com/ahrav/gitleaks-armada/pkg/orchestration/kubernetes"
)

var (
	ready atomic.Bool
)

func main() {
	_, _ = maxprocs.Set()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start health server.
	healthServer := setupHealthServer()
	defer func() {
		if err := healthServer.Shutdown(ctx); err != nil {
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

	m := metrics.New("scanner_controller")
	go func() {
		if err := metrics.StartServer(":8081"); err != nil {
			log.Printf("metrics server error: %v", err)
		}
	}()

	orch := orchestration.NewController(coord, broker, m)

	ready.Store(true)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	log.Println("Starting orchestrator...")
	leaderChan, err := orch.Run(ctx)
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

func setupHealthServer() *http.Server {
	mux := http.NewServeMux()

	mux.HandleFunc("/v1/readiness", func(w http.ResponseWriter, r *http.Request) {
		if !ready.Load() {
			http.Error(w, "Not ready", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc("/v1/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	server := &http.Server{Addr: ":8080", Handler: mux}

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("Health server error: %v", err)
		}
	}()

	return server
}
