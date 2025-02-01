package kafka

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/IBM/sarama"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/infra/eventbus/serialization"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

// Position represents a specific location in a Kafka partition,
// identified by a partition number and an offset.
// It is used to specify where to start replaying events in a Kafka topic.
type Position struct {
	Partition int32
	Offset    int64
}

// Identifier returns a string representation of the Position in the format "partition:offset".
func (p Position) Identifier() string { return fmt.Sprintf("%d:%d", p.Partition, p.Offset) }

// Validate checks if the Position is valid.
// A valid Position has a non-negative partition and offset.
// Returns an error if the Position is invalid.
func (p Position) Validate() error {
	if p.Partition < 0 {
		return fmt.Errorf("invalid partition: %d", p.Partition)
	}
	if p.Offset < 0 {
		return fmt.Errorf("invalid offset: %d", p.Offset)
	}
	return nil
}

// ReplayConfig contains the configuration required to replay events from Kafka.
// It includes the list of Kafka brokers and the topics to replay events from.
type ReplayConfig struct {
	Brokers []string
	Topics  []string
}

// EventReplayerMetrics defines metrics operations needed to monitor event replay operations.
type EventReplayerMetrics interface {
	// Replay metrics.
	IncReplayStarted(ctx context.Context)
	IncReplayCompleted(ctx context.Context)
	IncReplayErrors(ctx context.Context)

	// Message metrics.
	IncMessageReplayed(ctx context.Context, topic string)
	IncMessageReplayError(ctx context.Context, topic string)

	// Batch metrics.
	ObserveReplayBatchSize(ctx context.Context, size int)
	ObserveReplayDuration(ctx context.Context, duration time.Duration)
}

var _ events.EventReplayer = (*eventReplayer)(nil)

// eventReplayer is responsible for replaying events from Kafka topics
// starting from a specified position.
type eventReplayer struct {
	config *ReplayConfig

	client     sarama.Client
	shutdownWg sync.WaitGroup

	logger  *logger.Logger
	tracer  trace.Tracer
	metrics EventReplayerMetrics
}

// NewEventReplayer creates a new EventReplayer instance with the provided configuration,
// logger, metrics, and tracer. It initializes a Kafka client and returns an error if
// the client cannot be created.
func NewEventReplayer(
	controllerID string,
	cfg *ReplayConfig,
	logger *logger.Logger,
	metrics EventReplayerMetrics,
	tracer trace.Tracer,
) (*eventReplayer, error) {
	config := sarama.NewConfig()
	config.Consumer.Return.Errors = true
	config.Version = sarama.V2_8_0_0

	logger = logger.With("component", "event_replayer", "controller_id", controllerID)

	client, err := sarama.NewClient(cfg.Brokers, config)
	if err != nil {
		return nil, fmt.Errorf("creating kafka client: %w", err)
	}

	return &eventReplayer{
		client:  client,
		config:  cfg,
		logger:  logger,
		metrics: metrics,
		tracer:  tracer,
	}, nil
}

// ReplayEvents replays events from Kafka starting from the specified position.
// It returns a channel of events.EventEnvelope that will receive the replayed events.
// The method handles errors and logs them appropriately.
func (r *eventReplayer) ReplayEvents(
	ctx context.Context,
	from events.StreamPosition,
) (<-chan events.EventEnvelope, error) {
	r.metrics.IncReplayStarted(ctx)
	evtLogger := r.logger.With("position", from.Identifier())
	// Create an outer span for parameter validation and consumer creation.
	ctx, span := r.tracer.Start(ctx, "kafka_replayer.replay_events", trace.WithAttributes(
		attribute.String("component", "event_replayer"),
		attribute.String("position", from.Identifier()),
	))
	defer span.End()

	if err := from.Validate(); err != nil {
		r.metrics.IncReplayErrors(ctx)
		span.RecordError(err)
		span.SetStatus(codes.Error, "invalid position")
		return nil, fmt.Errorf("invalid position: %w", err)
	}

	identifier := from.Identifier()
	var (
		partition int32
		offset    int64
	)
	if _, err := fmt.Sscanf(identifier, "%d:%d", &partition, &offset); err != nil {
		r.metrics.IncReplayErrors(ctx)
		span.RecordError(err)
		span.SetStatus(codes.Error, "invalid position identifier format")
		return nil, fmt.Errorf("invalid position identifier format: %w", err)
	}
	span.SetAttributes(
		attribute.Int64("partition", int64(partition)),
		attribute.Int64("offset", offset),
	)

	consumer, err := sarama.NewConsumerFromClient(r.client)
	if err != nil {
		r.metrics.IncReplayErrors(ctx)
		span.RecordError(err)
		span.SetStatus(codes.Error, "creating consumer")
		return nil, fmt.Errorf("creating consumer: %w", err)
	}
	span.AddEvent("event_replayer_consumer_created")
	evtLogger.Info(ctx, "Consumer created")

	// Create a channel for sending events.
	// This channel will be closed when the context is
	// cancelled or all events are replayed.
	eventCh := make(chan events.EventEnvelope, 1)

	// Start consuming in a separate goroutine to stream events to the caller.
	r.shutdownWg.Add(1)
	go func() {
		startTime := time.Now()
		defer func() {
			r.metrics.ObserveReplayDuration(ctx, time.Since(startTime))
			r.metrics.IncReplayCompleted(ctx)
			r.shutdownWg.Done()
			close(eventCh)
			if err := consumer.Close(); err != nil {
				evtLogger.Error(ctx, "Error closing consumer", "error", err)
			}
		}()

		// Process each topic separately. For each topic, we start a new child span
		// so that no single span runs for the entire duration of the replay.
		for _, topic := range r.config.Topics {
			topicCtx, topicSpan := r.tracer.Start(ctx, "kafka_replayer.replay_topic", trace.WithAttributes(
				attribute.String("topic", topic),
				attribute.Int64("partition", int64(partition)),
				attribute.Int64("offset", offset),
			))
			topicLogger := logger.NewLoggerContext(evtLogger.With("topic", topic, "partition", partition, "offset", offset))

			partitionConsumer, err := consumer.ConsumePartition(topic, partition, offset)
			if err != nil {
				r.metrics.IncReplayErrors(topicCtx)
				topicLogger.Error(topicCtx, "Failed to create partition consumer", "error", err)
				topicSpan.RecordError(err)
				topicSpan.SetStatus(codes.Error, "failed to create partition consumer")
				topicSpan.End()
				// Proceed to the next topic instead of halting the entire replay.
				continue
			}
			topicSpan.AddEvent("partition_consumer_created")

			r.processPartitionMessages(topicCtx, partitionConsumer, topicLogger, eventCh, topic)
			topicSpan.End()
		}
	}()

	return eventCh, nil
}

// processPartitionMessages processes messages from a Kafka partition consumer.
// It handles message deserialization, error handling, and sends events to the provided channel.
// The method maintains tracing and logging context throughout message processing.
func (r *eventReplayer) processPartitionMessages(
	ctx context.Context,
	partitionConsumer sarama.PartitionConsumer,
	logger *logger.LoggerContext,
	eventCh chan<- events.EventEnvelope,
	topic string,
) {
	span := trace.SpanFromContext(ctx)
	defer partitionConsumer.Close()

	var msgCount int64 = 0
	batchSize := 0
	for {
		select {
		case msg := <-partitionConsumer.Messages():
			evtType, domainBytes, err := serialization.UnmarshalUniversalEnvelope(msg.Value)
			if err != nil {
				r.metrics.IncMessageReplayError(ctx, topic)
				logger.Error(ctx, "Failed to unmarshal event", "error", err, "msg_offset", msg.Offset)
				span.RecordError(err)
				continue
			}

			payload, err := serialization.DeserializePayload(evtType, domainBytes)
			if err != nil {
				r.metrics.IncMessageReplayError(ctx, topic)
				logger.Error(ctx, "Failed to deserialize payload", "error", err, "msg_offset", msg.Offset)
				span.RecordError(err)
				continue
			}

			evt := events.EventEnvelope{
				Type:      evtType,
				Key:       string(msg.Key),
				Timestamp: msg.Timestamp,
				Payload:   payload,
				Metadata: events.EventMetadata{
					Partition: msg.Partition,
					Offset:    msg.Offset,
				},
			}

			select {
			case eventCh <- evt:
				r.metrics.IncMessageReplayed(ctx, topic)
				logger.Debug(ctx, "Replayed event", "msg_offset", msg.Offset)
			case <-ctx.Done():
				span.AddEvent("context cancelled")
				return
			}

			msgCount++
			batchSize++
			// Every 100 messages, record a batch event instead of starting a new span per message.
			// TODO: Maybe make this configurable after we have a better understanding of how often this happens.
			if msgCount%100 == 0 {
				r.metrics.ObserveReplayBatchSize(ctx, batchSize)
				batchSize = 0
				span.AddEvent("processed_100_messages", trace.WithAttributes(
					attribute.Int64("msg_count", msgCount),
				))
			}

		case <-ctx.Done():
			if batchSize > 0 {
				r.metrics.ObserveReplayBatchSize(ctx, batchSize)
			}
			span.AddEvent("context cancelled")
			return

		case err := <-partitionConsumer.Errors():
			r.metrics.IncMessageReplayError(ctx, topic)
			logger.Error(ctx, "Error consuming message", "error", err)
			span.RecordError(err)
		}
	}
}

// Close closes the Kafka client associated with the EventReplayer.
// It should be called to clean up resources when the EventReplayer is no longer needed.
// Note: Close should only be called once. Calling it multiple times will result in an panic.
func (r *eventReplayer) Close() error {
	r.shutdownWg.Wait()
	return r.client.Close()
}
