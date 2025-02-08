package kafka

import (
	"fmt"
	"time"

	"github.com/IBM/sarama"
	"github.com/cenkalti/backoff"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

// ClientConfig contains all configuration needed for Kafka client setup
type ClientConfig struct {
	Brokers     []string
	GroupID     string
	ClientID    string
	ServiceType string
}

// NewClient creates and configures a Kafka client with the provided settings.
// It sets up consistent configuration for both producers and consumers.
func NewClient(cfg *ClientConfig) (sarama.Client, error) {
	config := sarama.NewConfig()
	config.ClientID = cfg.ClientID

	// Consumer settings
	config.Consumer.Return.Errors = true
	config.Consumer.Group.Rebalance.Strategy = sarama.NewBalanceStrategyRoundRobin()
	config.Consumer.Offsets.Initial = sarama.OffsetOldest
	config.Consumer.Group.Session.Timeout = 20 * time.Second
	config.Consumer.Group.Heartbeat.Interval = 6 * time.Second
	config.Consumer.Group.Member.UserData = []byte(cfg.ClientID)
	config.Consumer.Offsets.AutoCommit.Enable = false

	// Producer settings
	config.Producer.RequiredAcks = sarama.WaitForAll
	config.Producer.Return.Successes = true
	config.Producer.Partitioner = sarama.NewHashPartitioner

	// Version should be consistent across all components
	config.Version = sarama.V3_6_0_0

	return sarama.NewClient(cfg.Brokers, config)
}

// ConnectEventBus creates an EventBus instance using the provided Kafka client.
// It handles retries for establishing producer and consumer group connections.
func ConnectEventBus(
	cfg *EventBusConfig,
	client sarama.Client,
	logger *logger.Logger,
	metrics EventBusMetrics,
	tracer trace.Tracer,
) (events.EventBus, error) {
	var eventBus events.EventBus

	expBackoff := backoff.NewExponentialBackOff()
	expBackoff.MaxElapsedTime = 5 * time.Minute
	expBackoff.InitialInterval = 5 * time.Second

	operation := func() error {
		producer, err := sarama.NewSyncProducerFromClient(client)
		if err != nil {
			return fmt.Errorf("creating producer: %w", err)
		}

		consumerGroup, err := sarama.NewConsumerGroupFromClient(cfg.GroupID, client)
		if err != nil {
			producer.Close() // Clean up on failure
			return fmt.Errorf("creating consumer group: %w", err)
		}

		eventBus, err = NewEventBus(
			producer,
			consumerGroup,
			cfg,
			logger,
			metrics,
			tracer,
		)
		if err != nil {
			producer.Close()
			consumerGroup.Close()
			return fmt.Errorf("creating event bus: %w", err)
		}
		return nil
	}

	err := backoff.Retry(operation, expBackoff)
	if err != nil {
		return nil, fmt.Errorf("failed to connect event bus after retries: %w", err)
	}

	return eventBus, nil
}
