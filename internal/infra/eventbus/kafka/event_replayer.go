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

	// Consumer lag metrics.
	ObserveConsumerLag(ctx context.Context, topic string, partition int32, lag int64)
	IncLagCheckError(ctx context.Context, topic string)
}

var _ events.EventReplayer = (*eventReplayer)(nil)

// ReplayConfig contains the configuration required to replay events from Kafka.
// It includes the list of Kafka brokers and the topics to replay events from.
type ReplayConfig struct {
	ClientID    string
	Brokers     []string
	TopicMapper TopicMapper

	// Lag monitoring configuration.
	LagCheckInterval time.Duration // Default to 5s if not set
}

// eventReplayer is responsible for replaying events from Kafka topics
// starting from a specified position.
type eventReplayer struct {
	topicMapper TopicMapper

	client     sarama.Client
	consumer   sarama.Consumer
	shutdownWg sync.WaitGroup

	lagCheckInterval time.Duration

	logger  *logger.Logger
	tracer  trace.Tracer
	metrics EventReplayerMetrics
}

// NewEventReplayer creates a new EventReplayer instance with the provided configuration,
// logger, metrics, and tracer.
func NewEventReplayer(
	cfg *ReplayConfig,
	logger *logger.Logger,
	metrics EventReplayerMetrics,
	tracer trace.Tracer,
) (*eventReplayer, error) {
	config := sarama.NewConfig()
	config.Consumer.Return.Errors = true
	config.Version = sarama.V2_8_0_0
	config.ClientID = cfg.ClientID

	logger = logger.With("component", "event_replayer")

	client, err := sarama.NewClient(cfg.Brokers, config)
	if err != nil {
		return nil, fmt.Errorf("creating kafka client for event replayer: %w", err)
	}

	consumer, err := sarama.NewConsumerFromClient(client)
	if err != nil {
		return nil, fmt.Errorf("creating kafka consumer for event replayer: %w", err)
	}

	const defaultLagCheckInterval = 5 * time.Second
	lagCheckInterval := cfg.LagCheckInterval
	if lagCheckInterval == 0 {
		lagCheckInterval = defaultLagCheckInterval
	}

	return &eventReplayer{
		topicMapper:      cfg.TopicMapper,
		client:           client,
		consumer:         consumer,
		lagCheckInterval: lagCheckInterval,
		logger:           logger,
		metrics:          metrics,
		tracer:           tracer,
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
	evtLogger := logger.NewLoggerContext(r.logger.With("position", from.Identifier()))
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
		streamType string
		partition  int32
		offset     int64
	)
	if _, err := fmt.Sscanf(identifier, "%s:%d:%d", &streamType, &partition, &offset); err != nil {
		r.metrics.IncReplayErrors(ctx)
		span.RecordError(err)
		span.SetStatus(codes.Error, "invalid position identifier format")
		return nil, fmt.Errorf("invalid position identifier format: %w", err)
	}
	topic, err := r.topicMapper.GetTopicForStreamType(events.StreamType(streamType))
	if err != nil {
		r.metrics.IncReplayErrors(ctx)
		span.RecordError(err)
		span.SetStatus(codes.Error, "invalid entity type")
		return nil, fmt.Errorf("invalid entity type: %w", err)
	}
	span.SetAttributes(
		attribute.String("entity_type", streamType),
		attribute.Int64("partition", int64(partition)),
		attribute.Int64("offset", offset),
		attribute.String("topic", topic),
	)
	evtLogger.Add("entity_type", streamType, "partition", partition, "offset", offset, "topic", topic)

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
		}()

		topicCtx, topicSpan := r.tracer.Start(ctx, "kafka_replayer.replay_topic", trace.WithAttributes(
			attribute.String("topic", topic),
			attribute.Int64("partition", int64(partition)),
			attribute.Int64("offset", offset),
		))
		defer topicSpan.End()

		partitionConsumer, err := r.consumer.ConsumePartition(topic, partition, offset)
		if err != nil {
			r.metrics.IncReplayErrors(topicCtx)
			evtLogger.Error(topicCtx, "Failed to create partition consumer", "error", err)
			topicSpan.RecordError(err)
			topicSpan.SetStatus(codes.Error, "failed to create partition consumer")
			return
		}
		topicSpan.AddEvent("partition_consumer_created")

		r.processPartitionMessages(topicCtx, partitionConsumer, topic, partition, eventCh, evtLogger)
	}()

	return eventCh, nil
}

// processPartitionMessages processes messages from a Kafka partition consumer.
// It handles message deserialization, error handling, and sends events to the provided channel.
// The method maintains tracing and logging context throughout message processing.
func (r *eventReplayer) processPartitionMessages(
	ctx context.Context,
	partitionConsumer sarama.PartitionConsumer,
	topic string,
	partitionID int32,
	eventCh chan<- events.EventEnvelope,
	logger *logger.LoggerContext,
) {
	span := trace.SpanFromContext(ctx)
	defer partitionConsumer.Close()

	lagTicker := time.NewTicker(r.lagCheckInterval)
	defer lagTicker.Stop()

	var msgCount int64 = 0
	batchSize := 0
	for {
		select {
		case <-lagTicker.C:
			latestOffset, err := r.client.GetOffset(topic, partitionID, sarama.OffsetNewest)
			if err != nil {
				r.metrics.IncLagCheckError(ctx, topic)
				logger.Error(ctx, "Failed to get latest offset", "error", err)
				span.RecordError(err)
				continue
			}

			lag := latestOffset - partitionConsumer.HighWaterMarkOffset()
			logger.Info(ctx, "Lag", "lag", lag)
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
			// TODO: Consider adding retry logic?
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
	return r.consumer.Close()
}
