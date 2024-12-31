// Package kafka provides a Kafka-based implementation of the messaging broker interface.
package kafka

import (
	"fmt"
	"time"

	"github.com/IBM/sarama"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
	"github.com/ahrav/gitleaks-armada/pkg/messaging"
)

// BrokerMetrics defines the subset of metrics operations needed by the broker.
type BrokerMetrics interface {
	IncMessagePublished(topic string)
	IncMessageConsumed(topic string)
	IncPublishError(topic string)
	IncConsumeError(topic string)
}

// Config contains settings for connecting to and interacting with Kafka brokers.
// It defines the topics, consumer group, and client identifiers needed for message routing.
type Config struct {
	// Brokers is a list of Kafka broker addresses to connect to.
	Brokers []string

	// TaskTopic is the topic name for publishing scan tasks.
	TaskTopic string
	// ResultsTopic is the topic name for publishing scan results.
	ResultsTopic string
	// ProgressTopic is the topic name for publishing scan progress updates.
	ProgressTopic string
	// RulesTopic is the topic name for publishing scanning rules.
	RulesTopic string

	// GroupID identifies the consumer group for this broker instance.
	GroupID string
	// ClientID uniquely identifies this client to the Kafka cluster.
	ClientID string
}

var _ messaging.Broker = (*Broker)(nil)

// Broker implements the messaging.Broker interface using Apache Kafka.
// It handles publishing and subscribing to messages across different topics
// for scan tasks, results, progress updates, and rules.
type Broker struct {
	clientID string

	producer      sarama.SyncProducer
	consumerGroup sarama.ConsumerGroup

	taskTopic     string
	resultsTopic  string
	progressTopic string
	rulesTopic    string

	logger  *logger.Logger
	metrics BrokerMetrics
	tracer  trace.Tracer
}

// NewBroker creates a new Kafka broker with the provided configuration.
// It sets up both a producer and consumer group with appropriate settings
// for reliable message delivery and consumption.
func NewBroker(cfg *Config, logger *logger.Logger, metrics BrokerMetrics, tracer trace.Tracer) (*Broker, error) {
	// Configure the producer for reliable delivery with acknowledgments.
	producerConfig := sarama.NewConfig()
	producerConfig.Producer.RequiredAcks = sarama.WaitForAll
	producerConfig.Producer.Return.Successes = true
	producerConfig.ClientID = cfg.ClientID

	// Use round-robin partitioner to evenly distribute messages.
	producerConfig.Producer.Partitioner = sarama.NewRoundRobinPartitioner

	producer, err := sarama.NewSyncProducer(cfg.Brokers, producerConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create kafka producer: %w", err)
	}

	consumerConfig := sarama.NewConfig()
	consumerConfig.ClientID = cfg.ClientID
	consumerConfig.Consumer.Group.Rebalance.Strategy = sarama.NewBalanceStrategyRoundRobin()

	// Start from the oldest offset as this ensures we don't miss any messages
	// published before the broker was started.
	consumerConfig.Consumer.Offsets.Initial = sarama.OffsetOldest

	// Configure session management timeouts.
	consumerConfig.Consumer.Group.Session.Timeout = 20 * time.Second
	consumerConfig.Consumer.Group.Heartbeat.Interval = 6 * time.Second

	// Enable automatic offset commits.
	consumerConfig.Consumer.Offsets.AutoCommit.Enable = true
	consumerConfig.Consumer.Offsets.AutoCommit.Interval = 1 * time.Second

	consumerConfig.Version = sarama.V2_8_0_0

	consumerGroup, err := sarama.NewConsumerGroup(cfg.Brokers, cfg.GroupID, consumerConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create consumer group: %w", err)
	}

	return &Broker{
		producer:      producer,
		consumerGroup: consumerGroup,
		taskTopic:     cfg.TaskTopic,
		resultsTopic:  cfg.ResultsTopic,
		progressTopic: cfg.ProgressTopic,
		rulesTopic:    cfg.RulesTopic,
		clientID:      cfg.ClientID,
		logger:        logger,
		tracer:        tracer,
		metrics:       metrics,
	}, nil
}