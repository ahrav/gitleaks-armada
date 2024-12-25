package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"

	"go.uber.org/automaxprocs/maxprocs"

	"github.com/ahrav/gitleaks-armada/pkg/common"
	"github.com/ahrav/gitleaks-armada/pkg/messaging/kafka"
	"github.com/ahrav/gitleaks-armada/pkg/metrics"
	"github.com/ahrav/gitleaks-armada/pkg/scanner"
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

	hostname, err := os.Hostname()
	if err != nil {
		log.Fatalf("Failed to get hostname: %v", err)
	}

	kafkaCfg := &kafka.Config{
		Brokers:      strings.Split(os.Getenv("KAFKA_BROKERS"), ","),
		TaskTopic:    os.Getenv("KAFKA_TASK_TOPIC"),
		ResultsTopic: os.Getenv("KAFKA_RESULTS_TOPIC"),
		GroupID:      os.Getenv("KAFKA_GROUP_ID"),
		ClientID:     fmt.Sprintf("scanner-%s", hostname),
	}

	broker, err := common.ConnectKafkaWithRetry(kafkaCfg)
	if err != nil {
		log.Fatalf("Failed to create Kafka broker: %v", err)
	}
	log.Printf("Scanner %s connected to Kafka", hostname)

	m := metrics.New("scanner_worker")
	scanner := scanner.NewScanner(ctx, broker, m)

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
		log.Printf("Scanner %s shutting down...", hostname)
		cancel()
	}()

	log.Printf("Starting scanner %s...", hostname)
	if err := scanner.Run(ctx); err != nil {
		log.Printf("Scanner error: %v", err)
	}

	<-ctx.Done()
	log.Printf("Scanner %s shutdown complete", hostname)
}
