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

	hostname, err := os.Hostname()
	if err != nil {
		log.Fatalf("Failed to get hostname: %v", err)
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

	kafkaCfg := &kafka.Config{
		Brokers:      strings.Split(os.Getenv("KAFKA_BROKERS"), ","),
		TaskTopic:    os.Getenv("KAFKA_TASK_TOPIC"),
		ResultsTopic: os.Getenv("KAFKA_RESULTS_TOPIC"),
		RulesTopic:   os.Getenv("KAFKA_RULES_TOPIC"),
		GroupID:      os.Getenv("KAFKA_GROUP_ID"),
		ClientID:     fmt.Sprintf("scanner-%s", hostname),
	}

	broker, err := common.ConnectKafkaWithRetry(kafkaCfg)
	if err != nil {
		log.Fatalf("[%s] Failed to create Kafka broker: %v", hostname, err)
	}
	log.Printf("[%s] Scanner connected to Kafka", hostname)

	m := metrics.New("scanner_worker")
	scanner := scanner.NewScanner(ctx, hostname, broker, m)

	go func() {
		if err := metrics.StartServer(":8081"); err != nil {
			log.Printf("[%s] metrics server error: %v", hostname, err)
		}
	}()

	ready.Store(true)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Printf("[%s] Scanner shutting down...", hostname)
		cancel()
	}()

	log.Printf("[%s] Starting scanner...", hostname)
	if err := scanner.Run(ctx); err != nil {
		log.Printf("[%s] Scanner error: %v", hostname, err)
	}

	<-ctx.Done()
	log.Printf("[%s] Scanner shutdown complete", hostname)
}
