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
	// JobMetricsTopic is the topic name for publishing job metrics.
	JobMetricsTopic string

	// Split rules topic into two for clear direction of flow.
	RulesRequestTopic  string // controller -> scanner
	RulesResponseTopic string // scanner -> controller (updates & published)

	// GroupID identifies the consumer group for this broker instance.
	GroupID string
	// ClientID uniquely identifies this client to the Kafka cluster.
	ClientID string

	// ServiceType identifies the type of service (e.g., "scanner", "controller")
	ServiceType string
}

// TopicConfig defines the configuration for event routing to Kafka topics.
// This is used to define the primary and secondary topics for an event type.
type TopicConfig struct {
	// Primary is the main topic for this event type.
	Primary string
	// Secondary contains additional topics this event should be published to.
	Secondary []string
}

var _ events.EventBus = (*KafkaEventBus)(nil)

// KafkaEventBus implements the EventBus interface using Kafka as the underlying message broker.
// It handles publishing and subscribing to domain events across distributed services.
type KafkaEventBus struct {
	producer      sarama.SyncProducer
	consumerGroup sarama.ConsumerGroup

	// Maps domain event types to their Kafka topics
	topicMap map[events.EventType]string

	logger  *logger.Logger
	tracer  trace.Tracer
	metrics BrokerMetrics
}

// NewKafkaEventBusFromConfig creates a new Kafka-based event bus from the provided configuration.
// It establishes connections to Kafka brokers and configures both producer and consumer components
// for reliable message delivery and consumption.
func NewKafkaEventBusFromConfig(
	cfg *Config,
	logger *logger.Logger,
	metrics BrokerMetrics,
	tracer trace.Tracer,
) (*KafkaEventBus, error) {
	if metrics == nil {
		return nil, fmt.Errorf("metrics are required for kafka event bus")
	}

	logger = logger.With(
		"component", "kafka_event_bus",
		"client_id", cfg.ClientID,
		"group_id", cfg.GroupID,
		"service_type", cfg.ServiceType,
	)

	producerConfig := sarama.NewConfig()
	producerConfig.Producer.RequiredAcks = sarama.WaitForAll
	producerConfig.Producer.Return.Successes = true
	producerConfig.Producer.Partitioner = sarama.NewRoundRobinPartitioner
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
	consumerConfig.Consumer.Offsets.AutoCommit.Enable = false
	consumerConfig.Version = sarama.V2_8_0_0

	consumerGroup, err := sarama.NewConsumerGroup(cfg.Brokers, cfg.GroupID, consumerConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create consumer group: %w", err)
	}

	// Map domain events to their corresponding Kafka topics.
	// TODO: Maybe use a more performant data structure for this?
	topicMap := map[events.EventType]string{
		enumeration.EventTypeTaskCreated: cfg.EnumerationTaskTopic,  // controller -> scanner
		rules.EventTypeRulesRequested:    cfg.RulesRequestTopic,     // controller -> scanner
		rules.EventTypeRulesUpdated:      cfg.RulesResponseTopic,    // scanner -> controller
		rules.EventTypeRulesPublished:    cfg.RulesResponseTopic,    // scanner -> controller
		scanning.EventTypeTaskStarted:    cfg.ScanningTaskTopic,     // scanner -> controller
		scanning.EventTypeTaskProgressed: cfg.ScanningTaskTopic,     // scanner -> controller
		scanning.EventTypeTaskCompleted:  cfg.ScanningTaskTopic,     // scanner -> controller
		scanning.EventTypeTaskFailed:     cfg.ScanningTaskTopic,     // scanner -> controller
		scanning.EventTypeTaskHeartbeat:  cfg.ScanningTaskTopic,     // scanner -> controller
		scanning.EventTypeTaskResume:     cfg.HighPriorityTaskTopic, // controller -> scanner
		scanning.EventTypeTaskJobMetric:  cfg.JobMetricsTopic,       // scanner -> controller
	}

	bus := &KafkaEventBus{
		producer:      producer,
		consumerGroup: consumerGroup,
		topicMap:      topicMap,
		logger:        logger,
		metrics:       metrics,
		tracer:        tracer,
	}

	return bus, nil
}

// Publish sends a domain event to all configured Kafka topics for its type.
// It handles serialization, routing based on event type, and includes
// observability instrumentation for tracing and metrics.
// TODO: Make error handling more robust. For example, we should retry
// publishing if the message is not acknowledged by the broker,
// since it's possible the broker is temporarily unavailable and we don't
// want to lose events.
// Note: We should only attempt to retry if the error is a transient one. (e.g. LEADER_NOT_AVAILABLE)
// If the error is a permanent one, we should not retry. (e.g. INVALID_CONFIG)
func (k *KafkaEventBus) Publish(ctx context.Context, event events.EventEnvelope, opts ...events.PublishOption) error {
	topic, ok := k.topicMap[event.Type]
	if !ok {
		return fmt.Errorf("unknown event type '%s', no topic mapped", event.Type)
	}

	ctx, span := tracing.StartProducerSpan(ctx, topic, k.tracer)
	defer span.End()

	var pParams events.PublishParams
	for _, opt := range opts {
		opt(&pParams)
	}

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

	// Publish to primary topic.
	// TODO: Consider making this a little more ergonomic.
	if err := k.publishToTopic(ctx, topic, event.Key, msgBytes); err != nil {
		return err
	}

	return nil
}

// publishToTopic handles the actual publishing of a message to a single Kafka topic
func (k *KafkaEventBus) publishToTopic(ctx context.Context, topic, key string, msgBytes []byte) error {
	kafkaMsg := &sarama.ProducerMessage{
		Topic: topic,
		Key:   sarama.StringEncoder(key),
		Value: sarama.ByteEncoder(msgBytes),
	}

	tracing.InjectTraceContext(ctx, kafkaMsg)

	partition, offset, err := k.producer.SendMessage(kafkaMsg)
	if err != nil {
		if k.metrics != nil {
			k.metrics.IncPublishError(ctx, topic)
		}
		return fmt.Errorf("failed to send message to kafka topic %s: %w", topic, err)
	}

	if k.metrics != nil {
		k.metrics.IncMessagePublished(ctx, topic)
	}

	k.logger.Info(ctx, "Published message to Kafka",
		"topic", topic,
		"partition", partition,
		"offset", offset,
		"key", key,
	)

	return nil
}

// Subscribe registers a handler function to process domain events from specified event types.
// It manages consumer group membership and message processing in a separate goroutine.
func (k *KafkaEventBus) Subscribe(
	ctx context.Context,
	eventTypes []events.EventType,
	handler events.HandlerFunc,
) error {
	ctx, span := k.tracer.Start(ctx, "kafka_event_bus.subscribe",
		trace.WithAttributes(
			attribute.String("component", "kafka_event_bus"),
		))
	defer span.End()

	// Collect unique topics for the requested event types.
	var topics []string
	topicSet := make(map[string]struct{})
	for _, et := range eventTypes {
		if topic, ok := k.topicMap[et]; ok {
			topicSet[topic] = struct{}{}
			topics = append(topics, topic)
		} else {
			span.RecordError(fmt.Errorf("subscribe: unknown event type %s", et))
			span.SetStatus(codes.Error, "unknown event type")
			return fmt.Errorf("subscribe: unknown event type %s", et)
		}
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
	handler events.HandlerFunc,
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
	userHandler events.HandlerFunc

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
			Metadata: events.EventMetadata{
				Partition: claim.Partition(),
				Offset:    msg.Offset,
			},
		}

		h.logger.Info(msgCtx, "Received Kafka message",
			"topic", msg.Topic,
			"partition", claim.Partition(),
			"offset", msg.Offset,
			"event_type", evtType,
			"key", dEvent.Key,
		)

		ack := func(err error) {
			if err != nil {
				h.metrics.IncConsumeError(msgCtx, msg.Topic)
				h.logger.Error(msgCtx, "Failed to acknowledge message", "error", err)
				span.RecordError(err)
				span.SetStatus(codes.Error, "failed to acknowledge message")
				return
			}
			h.metrics.IncMessageConsumed(msgCtx, msg.Topic)
			sess.MarkMessage(msg, "")
		}

		if err := h.userHandler(msgCtx, dEvent, ack); err != nil {
			h.logger.Error(msgCtx, "Failed to handle message", "error", err)
			span.RecordError(err)
		} else {
			h.logger.Info(msgCtx, "Successfully processed message", "topic", msg.Topic)
		}
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
