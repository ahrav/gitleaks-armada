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

	brokers := strings.Split(os.Getenv("KAFKA_BROKERS"), ",")
	cfg := &orchestration.KafkaConfig{
		Brokers:      brokers,
		TaskTopic:    os.Getenv("KAFKA_TASK_TOPIC"),
		ResultsTopic: os.Getenv("KAFKA_RESULTS_TOPIC"),
		GroupID:      os.Getenv("KAFKA_GROUP_ID"),
	}

	broker, err := orchestration.NewKafkaBroker(cfg)
	if err != nil {
		log.Fatalf("Failed to create Kafka broker: %v", err)
	}
	log.Println("Kafka broker created successfully")

	// Start metrics server
	// m := metrics.New("scanner_worker")
	go func() {
		if err := metrics.StartServer(":8081"); err != nil {
			log.Printf("metrics server error: %v", err)
		}
	}()

	ready.Store(true)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Shutting down scanner...")
		cancel()
	}()

	log.Println("Subscribing to tasks...")
	if err := broker.SubscribeTasks(ctx, handleScanTask); err != nil {
		log.Fatalf("Failed to subscribe to tasks: %v", err)
	}

	<-ctx.Done()
	log.Println("Shutdown complete")
}

func handleScanTask(task orchestration.Task) error {
	log.Printf("Scanning task: %s", task.ResourceURI)
	return nil
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
