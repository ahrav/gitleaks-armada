package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/ahrav/gitleaks-armada/pkg/orchestration"
)

func main() {
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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	exitChan := make(chan os.Signal, 1)
	signal.Notify(exitChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-exitChan
		fmt.Println("Shutting down scanner...")
		cancel()
	}()

	log.Println("Subscribing to tasks...")
	if err := broker.SubscribeTasks(ctx, handleScanTask); err != nil {
		log.Fatalf("Failed to subscribe to tasks: %v", err)
	}

	<-ctx.Done()
}

func handleScanTask(chunk orchestration.Chunk) error {
	// TODO: Implement scanning logic
	// After scanning, publish results back to the results topic
	return nil
}
