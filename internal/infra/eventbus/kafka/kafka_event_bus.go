// Package kafka provides a Kafka-based implementation of the event bus for asynchronous messaging.
package kafka

import (
	"context"
	"fmt"
	"time"

	"github.com/IBM/sarama"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/domain/enumeration"
	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/domain/rules"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/internal/infra/eventbus/kafka/tracing"
	"github.com/ahrav/gitleaks-armada/internal/infra/eventbus/serialization"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

// BrokerMetrics defines metrics operations needed to monitor Kafka message handling.
// It enables tracking of successful and failed message publishing/consumption.
type BrokerMetrics interface {
	IncMessagePublished(ctx context.Context, topic string)
	IncMessageConsumed(ctx context.Context, topic string)
	IncPublishError(ctx context.Context, topic string)
	IncConsumeError(ctx context.Context, topic string)
}

// Config contains settings for connecting to and interacting with Kafka brokers.
// It defines the topics, consumer group, and client identifiers needed for message routing.
type Config struct {
	// Brokers is a list of Kafka broker addresses to connect to.
	Brokers []string

	// EnumerationTaskTopic is the topic name for publishing enumeration tasks.
	EnumerationTaskTopic string
	// ScanningTaskTopic is the topic name for publishing scanning tasks.
	ScanningTaskTopic string
	// ResultsTopic is the topic name for publishing scan results.
	ResultsTopic string
	// ProgressTopic is the topic name for publishing scan progress updates.
	ProgressTopic string
	// HighPriorityTaskTopic is the topic for high-priority scanning tasks (e.g., resume).
	HighPriorityTaskTopic string

	// Split rules topic into two for clear direction of flow.
	RulesRequestTopic  string // controller -> scanner
	RulesResponseTopic string // scanner -> controller (updates & published)

	// GroupID identifies the consumer group for this broker instance.
	GroupID string
	// ClientID uniquely identifies this client to the Kafka cluster.
	ClientID string
}

var _ events.EventBus = (*KafkaEventBus)(nil)

// KafkaEventBus implements the EventBus interface using Kafka as the underlying message broker.
// It handles publishing and subscribing to domain events across distributed services.
type KafkaEventBus struct {
	producer      sarama.SyncProducer
	consumerGroup sarama.ConsumerGroup

	enumTaskTopic         string
	scanTaskTopic         string
	resultsTopic          string
	progressTopic         string
	highPriorityTaskTopic string
	rulesRequestTopic     string
	rulesResponseTopic    string

	// Maps domain event types to Kafka topic names.
	topics map[events.EventType]string

	logger  *logger.Logger
	tracer  trace.Tracer
	metrics BrokerMetrics
}

// NewKafkaEventBusFromConfig creates a new Kafka-based event bus from the provided configuration.
// It establishes connections to Kafka brokers and configures both producer and consumer components
// for reliable message delivery and consumption. The event bus provides a durable messaging
// backbone for distributing domain events across services.
// TODO: Review the configuration of the producer and consumer.
// This will likely need to be adjusted for production use cases where we want to
// have multiple brokers setup for redundancy and high availability.
func NewKafkaEventBusFromConfig(
	cfg *Config,
	logger *logger.Logger,
	metrics BrokerMetrics,
	tracer trace.Tracer,
) (*KafkaEventBus, error) {
	producerConfig := sarama.NewConfig()
	producerConfig.Producer.RequiredAcks = sarama.WaitForAll
	producerConfig.Producer.Return.Successes = true
	producerConfig.Producer.Partitioner = sarama.NewHashPartitioner
	producerConfig.ClientID = cfg.ClientID

	producer, err := sarama.NewSyncProducer(cfg.Brokers, producerConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create kafka producer: %w", err)
	}

	// Configure consumer group for reliable message processing with
	// automatic offset commits and rebalancing.
	consumerConfig := sarama.NewConfig()
	consumerConfig.ClientID = cfg.ClientID
	consumerConfig.Consumer.Group.Rebalance.Strategy = sarama.NewBalanceStrategyRoundRobin()
	consumerConfig.Consumer.Offsets.Initial = sarama.OffsetOldest
	consumerConfig.Consumer.Group.Session.Timeout = 20 * time.Second
	consumerConfig.Consumer.Group.Heartbeat.Interval = 6 * time.Second
	// TODO: Decide if we want to keep auto-commit enabled.
	// We should probably only commit offsets if the message is successfully processed.
	consumerConfig.Consumer.Offsets.AutoCommit.Enable = true
	consumerConfig.Consumer.Offsets.AutoCommit.Interval = 1 * time.Second
	consumerConfig.Version = sarama.V2_8_0_0

	consumerGroup, err := sarama.NewConsumerGroup(cfg.Brokers, cfg.GroupID, consumerConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create consumer group: %w", err)
	}

	// Map domain events to their corresponding Kafka topics to enable
	// type-safe event routing.
	topicsMap := map[events.EventType]string{
		enumeration.EventTypeTaskCreated: cfg.EnumerationTaskTopic,
		rules.EventTypeRulesRequested:    cfg.RulesRequestTopic,     // controller -> scanner
		rules.EventTypeRulesUpdated:      cfg.RulesResponseTopic,    // scanner -> controller
		rules.EventTypeRulesPublished:    cfg.RulesResponseTopic,    // scanner -> controller
		scanning.EventTypeTaskStarted:    cfg.ScanningTaskTopic,     // scanner -> controller
		scanning.EventTypeTaskProgressed: cfg.ScanningTaskTopic,     // scanner -> controller
		scanning.EventTypeTaskCompleted:  cfg.ScanningTaskTopic,     // scanner -> controller
		scanning.EventTypeTaskFailed:     cfg.ScanningTaskTopic,     // scanner -> controller
		scanning.EventTypeTaskResume:     cfg.HighPriorityTaskTopic, // controller -> scanner (resumption tasks)
		scanning.EventTypeTaskHeartbeat:  cfg.ScanningTaskTopic,     // scanner -> controller (liveness only)
	}

	bus := &KafkaEventBus{
		producer:      producer,
		consumerGroup: consumerGroup,

		enumTaskTopic:         cfg.EnumerationTaskTopic,
		scanTaskTopic:         cfg.ScanningTaskTopic,
		resultsTopic:          cfg.ResultsTopic,
		progressTopic:         cfg.ProgressTopic,
		highPriorityTaskTopic: cfg.HighPriorityTaskTopic,
		rulesRequestTopic:     cfg.RulesRequestTopic,
		rulesResponseTopic:    cfg.RulesResponseTopic,

		topics: topicsMap,

		logger:  logger,
		tracer:  tracer,
		metrics: metrics,
	}

	return bus, nil
}

// Publish sends a domain event to the appropriate Kafka topic.
// It handles serialization, routing based on event type, and includes
// observability instrumentation for tracing and metrics.
// TODO: Make error handling more robust. For example, we should retry
// publishing if the message is not acknowledged by the broker,
// since it's possible the broker is temporarily unavailable and we don't
// want to lose events.
// Note: We should only attempt to retry if the error is a transient one. (e.g. LEADER_NOT_AVAILABLE)
// If the error is a permanent one, we should not retry. (e.g. INVALID_CONFIG)
func (k *KafkaEventBus) Publish(ctx context.Context, event events.EventEnvelope, opts ...events.PublishOption) error {
	topic, ok := k.topics[event.Type]
	if !ok {
		return fmt.Errorf("unknown event type '%s', no topic mapped", event.Type)
	}

	ctx, span := tracing.StartProducerSpan(ctx, topic, k.tracer)
	defer span.End()

	var pParams events.PublishParams
	for _, opt := range opts {
		opt(&pParams)
	}

	// TODO: Consider also handling headers here.
	if pParams.Key != "" {
		event.Key = pParams.Key
		span.SetAttributes(attribute.String("event.key", event.Key))
	}

	msgBytes, err := serialization.SerializeEventEnvelope(event.Type, event.Payload)
	if err != nil {
		span.RecordError(err)

		if k.metrics != nil {
			k.metrics.IncPublishError(ctx, topic)
		}
		return fmt.Errorf("failed to serialize payload for event %s: %w", event.Type, err)
	}

	kafkaMsg := &sarama.ProducerMessage{
		Topic: topic,
		Key:   sarama.StringEncoder(event.Key), // Used for partition routing
		Value: sarama.ByteEncoder(msgBytes),
	}

	tracing.InjectTraceContext(ctx, kafkaMsg)

	partition, offset, sendErr := k.producer.SendMessage(kafkaMsg)
	if sendErr != nil {
		span.RecordError(sendErr)

		if k.metrics != nil {
			k.metrics.IncPublishError(ctx, topic)
		}
		return fmt.Errorf("failed to send message to kafka topic %s: %w", topic, sendErr)
	}

	if k.metrics != nil {
		k.metrics.IncMessagePublished(ctx, topic)
	}
	k.logger.Info(ctx, "Published message to Kafka",
		"topic", topic,
		"partition", partition,
		"offset", offset,
		"event_type", event.Type,
		"key", event.Key,
	)

	return nil
}

// Subscribe registers a handler function to process domain events from specified event types.
// It manages consumer group membership and message processing in a separate goroutine.
func (k *KafkaEventBus) Subscribe(
	ctx context.Context,
	eventTypes []events.EventType,
	handler func(context.Context, events.EventEnvelope) error,
) error {
	ctx, span := k.tracer.Start(ctx, "kafka_event_bus.subscribe",
		trace.WithAttributes(
			attribute.String("component", "kafka_event_bus"),
		))
	defer span.End()

	// Collect unique topics for the requested event types.
	topicSet := make(map[string]struct{})
	for _, et := range eventTypes {
		if topic, ok := k.topics[et]; ok {
			topicSet[topic] = struct{}{}
		} else {
			span.RecordError(fmt.Errorf("subscribe: unknown event type %s", et))
			span.SetStatus(codes.Error, "unknown event type")
			return fmt.Errorf("subscribe: unknown event type %s", et)
		}
	}

	var topics []string
	for t := range topicSet {
		topics = append(topics, t)
	}
	span.AddEvent("topics_collected", trace.WithAttributes(attribute.StringSlice("topics", topics)))

	go k.consumeLoop(ctx, topics, handler)
	k.logger.Info(ctx, "Subscribed to events", "event_types", eventTypes)

	return nil
}

// consumeLoop maintains a continuous consumer group session for processing messages.
func (k *KafkaEventBus) consumeLoop(
	ctx context.Context,
	topics []string,
	handler func(context.Context, events.EventEnvelope) error,
) {
	cgHandler := &domainEventHandler{
		eventBus:    k,
		userHandler: handler,
		logger:      k.logger,
		tracer:      k.tracer,
		metrics:     k.metrics,
	}

	for {
		if err := k.consumerGroup.Consume(ctx, topics, cgHandler); err != nil {
			k.logger.Error(ctx, "Error from consumer group", "error", err)
		}
		if ctx.Err() != nil {
			return
		}
	}
}

// domainEventHandler implements sarama.ConsumerGroupHandler to process Kafka messages
// and convert them into domain events for the application.
type domainEventHandler struct {
	eventBus    *KafkaEventBus
	userHandler func(context.Context, events.EventEnvelope) error

	logger  *logger.Logger
	tracer  trace.Tracer
	metrics BrokerMetrics
}

func (h *domainEventHandler) Setup(sess sarama.ConsumerGroupSession) error {
	h.logger.Info(context.Background(),
		"Consumer group session setup",
		"generation_id", sess.GenerationID(),
		"member_id", sess.MemberID(),
	)
	return nil
}

func (h *domainEventHandler) Cleanup(sess sarama.ConsumerGroupSession) error {
	h.logger.Info(context.Background(),
		"Consumer group session cleanup",
		"generation_id", sess.GenerationID(),
		"member_id", sess.MemberID(),
	)
	return nil
}

// ConsumeClaim processes messages from an assigned partition, deserializing them into
// domain events and invoking the user-provided handler.
func (h *domainEventHandler) ConsumeClaim(
	sess sarama.ConsumerGroupSession,
	claim sarama.ConsumerGroupClaim,
) error {
	h.logPartitionStart(sess.Context(), claim.Partition(), sess.MemberID())

	for msg := range claim.Messages() {
		msgCtx := tracing.ExtractTraceContext(sess.Context(), msg)
		msgCtx, span := tracing.StartConsumerSpan(msgCtx, msg, h.tracer)

		evtType, domainBytes, err := serialization.UnmarshalUniversalEnvelope(msg.Value)
		if err != nil {
			sess.MarkMessage(msg, "")
			span.RecordError(err)
			continue
		}

		payloadObj, err := serialization.DeserializePayload(evtType, domainBytes)
		if err != nil {
			sess.MarkMessage(msg, "")
			span.RecordError(err)
			continue
		}

		dEvent := events.EventEnvelope{
			Type:      evtType,
			Key:       string(msg.Key),
			Timestamp: time.Now(),
			Payload:   payloadObj,
		}

		h.logger.Info(msgCtx, "Received Kafka message",
			"topic", msg.Topic,
			"partition", claim.Partition(),
			"offset", msg.Offset,
			"event_type", evtType,
			"key", dEvent.Key,
		)

		if err := h.userHandler(msgCtx, dEvent); err != nil {
			if h.metrics != nil {
				h.metrics.IncConsumeError(msgCtx, msg.Topic)
			}
			h.logger.Error(msgCtx, "Failed to handle message", "error", err)
			span.RecordError(err)
		} else {
			if h.metrics != nil {
				h.metrics.IncMessageConsumed(msgCtx, msg.Topic)
			}
			h.logger.Info(msgCtx, "Successfully processed message", "topic", msg.Topic)
		}

		sess.MarkMessage(msg, "")
		span.End()
	}
	return nil
}

func (h *domainEventHandler) logPartitionStart(ctx context.Context, partition int32, memberID string) {
	h.logger.Info(ctx, "Starting to consume from partition",
		"partition", partition,
		"member_id", memberID,
	)
}

// Close gracefully shuts down the event bus by closing both producer and consumer connections.
func (k *KafkaEventBus) Close() error {
	if err := k.producer.Close(); err != nil {
		return err
	}
	return k.consumerGroup.Close()
}
