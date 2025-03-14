// Package kafka provides a Kafka-based implementation of the event bus for asynchronous messaging.
package kafka

import (
	"context"
	"errors"
	"fmt"
	"runtime/debug"
	"time"

	"github.com/IBM/sarama"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/domain/rules"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/internal/infra/eventbus/kafka/tracing"
	"github.com/ahrav/gitleaks-armada/internal/infra/eventbus/serialization"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

// EventBusMetrics defines metrics operations needed to monitor Kafka message handling.
// It enables tracking of successful and failed message publishing/consumption.
type EventBusMetrics interface {
	IncMessagePublished(ctx context.Context, topic string)
	IncMessageConsumed(ctx context.Context, topic string)
	IncPublishError(ctx context.Context, topic string)
	IncConsumeError(ctx context.Context, topic string)
}

// EventBusConfig contains settings for connecting to and interacting with Kafka brokers.
// It defines the topics, consumer group, and client identifiers needed for message routing.
type EventBusConfig struct {
	// Brokers is a list of Kafka broker addresses to connect to.
	Brokers []string

	// JobLifecycleTopic is the topic for all job-related events (creation, metrics, enumeration, etc.).
	JobLifecycleTopic string

	// ScannerLifecycleTopic is the topic for all scanner-related events (registration, heartbeats, etc.).
	ScannerLifecycleTopic string

	// TaskCreatedTopic is the topic name for publishing task created events.
	TaskCreatedTopic string
	// ScanningTaskTopic is the topic name for publishing scanning tasks.
	ScanningTaskTopic string
	// HighPriorityTaskTopic is the topic for high-priority scanning tasks (e.g., resume).
	HighPriorityTaskTopic string
	// ResultsTopic is the topic name for publishing scan results.
	ResultsTopic string
	// ProgressTopic is the topic name for publishing scan progress updates.
	ProgressTopic string

	// Split rules topic into two for clear direction of flow.
	RulesRequestTopic  string // controller -> scanner
	RulesResponseTopic string // scanner -> controller

	// GroupID identifies the consumer group for this broker instance.
	GroupID string
	// ClientID uniquely identifies this client to the Kafka cluster.
	ClientID string

	// ServiceType identifies the type of service (e.g., "scanner", "controller")
	ServiceType string

	// JobBroadcastTopic is the topic for broadcast events to all scanners
	JobBroadcastTopic string
}

var _ events.EventBus = (*EventBus)(nil)

// EventBus implements the EventBus interface using Kafka as the underlying message broker.
// It handles publishing and subscribing to domain events across distributed services.
type EventBus struct {
	producer      sarama.SyncProducer
	consumerGroup sarama.ConsumerGroup

	// Maps domain event types to their Kafka topics
	topicMap map[events.EventType]string

	logger  *logger.Logger
	tracer  trace.Tracer
	metrics EventBusMetrics
}

// NewEventBus creates a new Kafka-based event bus from the provided configuration.
// It establishes connections to Kafka brokers and configures both producer and consumer components
// for reliable message delivery and consumption.
func NewEventBus(
	producer sarama.SyncProducer,
	consumerGroup sarama.ConsumerGroup,
	cfg *EventBusConfig,
	logger *logger.Logger,
	metrics EventBusMetrics,
	tracer trace.Tracer,
) (*EventBus, error) {
	if cfg == nil {
		return nil, errors.New("event bus config is required")
	}

	if producer == nil {
		return nil, errors.New("producer is required")
	}

	if consumerGroup == nil {
		return nil, errors.New("consumer group is required")
	}

	logger = logger.With(
		"component", "kafka_event_bus",
		"client_id", cfg.ClientID,
		"group_id", cfg.GroupID,
		"service_type", cfg.ServiceType,
	)

	topicMap := map[events.EventType]string{
		rules.EventTypeRulesRequested: cfg.RulesRequestTopic,  // controller -> scanner
		rules.EventTypeRulesUpdated:   cfg.RulesResponseTopic, // scanner -> controller
		rules.EventTypeRulesPublished: cfg.RulesResponseTopic, // scanner -> controller

		scanning.EventTypeJobRequested:            cfg.JobLifecycleTopic, // api -> controller
		scanning.EventTypeJobScheduled:            cfg.JobLifecycleTopic, // controller -> controller
		scanning.EventTypeJobPausing:              cfg.JobLifecycleTopic, // controller -> controller
		scanning.EventTypeJobEnumerationCompleted: cfg.JobLifecycleTopic, // controller -> controller

		scanning.EventTypeJobPaused:     cfg.JobBroadcastTopic, // controller -> scanner (broadcast)
		scanning.EventTypeJobCancelled:  cfg.JobBroadcastTopic, // controller -> scanner (broadcast)
		scanning.EventTypeJobResuming:   cfg.JobLifecycleTopic, // controller -> controller
		scanning.EventTypeJobCancelling: cfg.JobLifecycleTopic, // controller -> controller

		scanning.EventTypeTaskCreated:    cfg.TaskCreatedTopic,      // controller -> scanner
		scanning.EventTypeTaskPaused:     cfg.ScanningTaskTopic,     // controller -> scanner
		scanning.EventTypeTaskResume:     cfg.HighPriorityTaskTopic, // controller -> scanner
		scanning.EventTypeTaskStarted:    cfg.ScanningTaskTopic,     // scanner -> controller
		scanning.EventTypeTaskProgressed: cfg.ScanningTaskTopic,     // scanner -> controller
		scanning.EventTypeTaskCompleted:  cfg.ScanningTaskTopic,     // scanner -> controller
		scanning.EventTypeTaskFailed:     cfg.ScanningTaskTopic,     // scanner -> controller
		scanning.EventTypeTaskHeartbeat:  cfg.ScanningTaskTopic,     // scanner -> controller
		scanning.EventTypeTaskJobMetric:  cfg.JobLifecycleTopic,     // scanner -> controller && controller -> controller
		scanning.EventTypeTaskCancelled:  cfg.ScanningTaskTopic,     // scanner -> controller

		scanning.EventTypeScannerRegistered:    cfg.ScannerLifecycleTopic, // scanner -> controller
		scanning.EventTypeScannerHeartbeat:     cfg.ScannerLifecycleTopic, // scanner -> controller
		scanning.EventTypeScannerStatusChanged: cfg.ScannerLifecycleTopic, // scanner -> controller
		scanning.EventTypeScannerDeregistered:  cfg.ScannerLifecycleTopic, // scanner -> controller
	}

	bus := &EventBus{
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
func (b *EventBus) Publish(ctx context.Context, event events.EventEnvelope, opts ...events.PublishOption) error {
	topic, ok := b.topicMap[event.Type]
	if !ok {
		return fmt.Errorf("unknown event type '%s', no topic mapped", event.Type)
	}

	ctx, span := tracing.StartProducerSpan(ctx, topic, b.tracer)
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
		if b.metrics != nil {
			b.metrics.IncPublishError(ctx, topic)
		}
		return fmt.Errorf("failed to serialize payload for event %s: %w", event.Type, err)
	}

	// Publish to primary topic.
	// TODO: Consider making this a little more ergonomic.
	if err := b.publishToTopic(ctx, topic, event.Key, msgBytes); err != nil {
		return err
	}

	return nil
}

// publishToTopic handles the actual publishing of a message to a single Kafka topic
func (b *EventBus) publishToTopic(ctx context.Context, topic, key string, msgBytes []byte) error {
	kafkaMsg := &sarama.ProducerMessage{
		Topic: topic,
		Key:   sarama.StringEncoder(key),
		Value: sarama.ByteEncoder(msgBytes),
	}

	tracing.InjectTraceContext(ctx, kafkaMsg)

	partition, offset, err := b.producer.SendMessage(kafkaMsg)
	if err != nil {
		if b.metrics != nil {
			b.metrics.IncPublishError(ctx, topic)
		}
		return fmt.Errorf("failed to send message to kafka topic %s: %w", topic, err)
	}

	if b.metrics != nil {
		b.metrics.IncMessagePublished(ctx, topic)
	}

	b.logger.Debug(ctx, "Published message to Kafka",
		"topic", topic,
		"partition", partition,
		"offset", offset,
		"key", key,
	)

	return nil
}

// Subscribe registers a handler function to process domain events from specified event types.
// It manages consumer group membership and message processing in a separate goroutine.
func (b *EventBus) Subscribe(
	ctx context.Context,
	eventTypes []events.EventType,
	handler events.HandlerFunc,
) error {
	ctx, span := b.tracer.Start(ctx, "kafka_event_bus.subscribe",
		trace.WithAttributes(
			attribute.String("component", "kafka_event_bus"),
		))
	defer span.End()

	go func() {
		<-ctx.Done()
		b.logger.Info(ctx, "Context cancelled, stopping subscription to consumer group")
	}()

	// Collect unique topics for the requested event types.
	var topics []string
	topicSet := make(map[string]struct{})
	for _, et := range eventTypes {
		if topic, ok := b.topicMap[et]; ok {
			topicSet[topic] = struct{}{}
			topics = append(topics, topic)
		} else {
			span.RecordError(fmt.Errorf("subscribe: unknown event type %s", et))
			span.SetStatus(codes.Error, "unknown event type")
			return fmt.Errorf("subscribe: unknown event type %s", et)
		}
	}

	span.AddEvent("topics_collected", trace.WithAttributes(attribute.StringSlice("topics", topics)))

	go b.consumeLoop(ctx, topics, handler)
	b.logger.Info(ctx, "Subscribed to events", "event_types", eventTypes)

	return nil
}

// consumeLoop maintains a continuous consumer group session for processing messages.
func (b *EventBus) consumeLoop(
	ctx context.Context,
	topics []string,
	handler events.HandlerFunc,
) {
	cgHandler := &domainEventHandler{
		eventBus:    b,
		userHandler: handler,
		logger:      b.logger,
		tracer:      b.tracer,
		metrics:     b.metrics,
	}

	for {
		if err := b.consumerGroup.Consume(ctx, topics, cgHandler); err != nil {
			b.logger.Error(ctx, "Error from consumer group", "error", err)
		}
		if ctx.Err() != nil {
			return
		}
	}
}

// domainEventHandler implements sarama.ConsumerGroupHandler to process Kafka messages
// and convert them into domain events for the application.
type domainEventHandler struct {
	eventBus    *EventBus
	userHandler events.HandlerFunc

	logger  *logger.Logger
	tracer  trace.Tracer
	metrics EventBusMetrics
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

// OffsetStrategy defines the interface for managing Kafka message offset commitments.
// Different implementations allow for flexible control over when and how messages
// are marked as processed within a consumer group.
type OffsetStrategy interface {
	MarkOffset(sess sarama.ConsumerGroupSession, msg *sarama.ConsumerMessage)
}

// DefaultOffsetStrategy provides immediate message acknowledgment behavior.
// This strategy is suitable for scenarios where messages can be processed
// independently and immediate commits are acceptable.
type DefaultOffsetStrategy struct{}

func (DefaultOffsetStrategy) MarkOffset(sess sarama.ConsumerGroupSession, msg *sarama.ConsumerMessage) {
	sess.MarkMessage(msg, "")
}

// BatchOffsetStrategy provides manual offset control for batch processing scenarios.
// This strategy is useful when you need to ensure all messages in a batch are
// processed successfully before committing their offsets.
type BatchOffsetStrategy struct{}

func (BatchOffsetStrategy) MarkOffset(sess sarama.ConsumerGroupSession, msg *sarama.ConsumerMessage) {
	// Increment offset by 1 to mark the next message to be consumed
	sess.MarkOffset(msg.Topic, msg.Partition, msg.Offset+1, "")
}

// ConsumeClaim processes messages from an assigned partition, deserializing them into
// domain events and invoking the user-provided handler.
func (h *domainEventHandler) ConsumeClaim(
	sess sarama.ConsumerGroupSession,
	claim sarama.ConsumerGroupClaim,
) (err error) {
	// Add panic recovery
	defer func() {
		if r := recover(); r != nil {
			// Convert panic to error and log.
			// If a scanner is killed unexpectedly the underlying sarama consumer will panic.
			// This is a workaround to catch those panics and log them.
			err = fmt.Errorf("panic in ConsumeClaim: %v", r)
			h.logger.Error(sess.Context(), "Recovered from panic in ConsumeClaim",
				"error", err,
				"stack", string(debug.Stack()),
				"partition", claim.Partition(),
				"member_id", sess.MemberID(),
			)

			if h.metrics != nil {
				h.metrics.IncConsumeError(sess.Context(), claim.Topic())
			}
		}
	}()

	h.logPartitionStart(sess.Context(), claim.Partition(), sess.MemberID())
	consumeLogger := h.logger.With("operation", "consume_claim", "partition", claim.Partition())

	commitTicker := time.NewTicker(1 * time.Second)
	defer commitTicker.Stop()

	commitChan := make(chan struct{}, 1)
	go func() {
		for range commitTicker.C {
			select {
			case commitChan <- struct{}{}:
			default:
			}
		}
	}()

	for {
		select {
		case <-commitChan:
			sess.Commit() // Final commit before exiting
		case msg := <-claim.Messages():
			func() {
				defer func() {
					if r := recover(); r != nil {
						h.logger.Error(sess.Context(), "Recovered from panic in message processing",
							"error", fmt.Sprintf("panic: %v", r),
							"stack", string(debug.Stack()),
							"topic", msg.Topic,
							"partition", claim.Partition(),
							"offset", msg.Offset,
						)

						sess.MarkMessage(msg, "")

						if h.metrics != nil {
							h.metrics.IncConsumeError(sess.Context(), msg.Topic)
						}
					}
				}()

				msgCtx := tracing.ExtractTraceContext(sess.Context(), msg)
				msgCtx, span := tracing.StartConsumerSpan(msgCtx, msg, h.tracer)
				defer span.End()

				evtType, domainBytes, err := serialization.UnmarshalUniversalEnvelope(msg.Value)
				if err != nil {
					h.logger.Error(msgCtx, "Failed to unmarshal universal envelope", "error", err)
					sess.MarkMessage(msg, "")
					span.RecordError(err)
					return
				}

				payloadObj, err := serialization.DeserializePayload(evtType, domainBytes)
				if err != nil {
					h.logger.Error(msgCtx, "Failed to deserialize payload", "error", err)
					sess.MarkMessage(msg, "")
					span.RecordError(err)
					return
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

				consumeLogger.Debug(msgCtx, "Received Kafka message",
					"topic", msg.Topic,
					"partition", claim.Partition(),
					"offset", msg.Offset,
					"event_type", evtType,
					"key", dEvent.Key,
				)

				// TODO: consider a map if the number of events or strategies grows.
				var offsetStrategy OffsetStrategy
				switch evtType {
				case scanning.EventTypeTaskJobMetric, scanning.EventTypeJobEnumerationCompleted:
					offsetStrategy = BatchOffsetStrategy{}
				default:
					offsetStrategy = DefaultOffsetStrategy{}
				}

				ack := func(err error) {
					// Create a new span for acknowledgment.
					// This is necessary because the acknowledgment is done in a separate
					// goroutine from the message processing.
					ackCtx, ackSpan := h.tracer.Start(msgCtx, "kafka_consumer.acknowledge",
						trace.WithLinks(trace.LinkFromContext(msgCtx)),
					)
					defer ackSpan.End()

					if err != nil {
						consumeLogger.Error(ackCtx, "Failed to acknowledge message", "error", err)
						h.metrics.IncConsumeError(ackCtx, msg.Topic)
						ackSpan.RecordError(err)
						ackSpan.SetStatus(codes.Error, "failed to acknowledge message")
						return
					}
					h.metrics.IncMessageConsumed(ackCtx, msg.Topic)

					offsetStrategy.MarkOffset(sess, msg)
				}

				if err := h.userHandler(msgCtx, dEvent, ack); err != nil {
					consumeLogger.Error(msgCtx, "Failed to handle message", "error", err)
					span.RecordError(err)
					return
				}

				consumeLogger.Debug(msgCtx, "Successfully processed message", "topic", msg.Topic)
			}()
		}
	}
}

func (h *domainEventHandler) logPartitionStart(ctx context.Context, partition int32, memberID string) {
	h.logger.Info(ctx, "Starting to consume from partition",
		"partition", partition,
		"member_id", memberID,
	)
}

// Close gracefully shuts down the event bus by closing both producer and consumer connections.
func (b *EventBus) Close() error {
	logger := b.logger.With("operation", "close")
	ctx, span := b.tracer.Start(context.Background(), "kafka_event_bus.close")
	defer span.End()

	if err := b.producer.Close(); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to close producer")
		logger.Error(ctx, "Failed to close producer", "error", err)
		return err
	}
	if err := b.consumerGroup.Close(); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to close consumer group")
		logger.Error(ctx, "Failed to close consumer group", "error", err)
		return err
	}

	span.AddEvent("closed_event_bus")
	span.SetStatus(codes.Ok, "closed event bus")
	logger.Info(ctx, "Closed event bus")

	return nil
}
