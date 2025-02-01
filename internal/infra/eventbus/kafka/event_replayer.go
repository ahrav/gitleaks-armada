package kafka

import (
	"context"
	"fmt"

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

// EventReplayer is responsible for replaying events from Kafka topics
// starting from a specified position.
type EventReplayer struct {
	client  sarama.Client
	config  *ReplayConfig
	logger  *logger.Logger
	tracer  trace.Tracer
	metrics BrokerMetrics
}

// NewEventReplayer creates a new EventReplayer instance with the provided configuration,
// logger, metrics, and tracer. It initializes a Kafka client and returns an error if
// the client cannot be created.
func NewEventReplayer(
	controllerID string,
	cfg *ReplayConfig,
	logger *logger.Logger,
	metrics BrokerMetrics,
	tracer trace.Tracer,
) (*EventReplayer, error) {
	config := sarama.NewConfig()
	config.Consumer.Return.Errors = true
	config.Version = sarama.V2_8_0_0

	logger = logger.With("component", "event_replayer", "controller_id", controllerID)

	client, err := sarama.NewClient(cfg.Brokers, config)
	if err != nil {
		return nil, fmt.Errorf("creating kafka client: %w", err)
	}

	return &EventReplayer{
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
func (r *EventReplayer) ReplayEvents(
	ctx context.Context,
	from events.StreamPosition,
) (<-chan events.EventEnvelope, error) {
	evtLogger := r.logger.With("position", from.Identifier())
	// Create an outer span for parameter validation and consumer creation.
	ctx, span := r.tracer.Start(ctx, "kafka_replayer.replay_events", trace.WithAttributes(
		attribute.String("component", "event_replayer"),
		attribute.String("position", from.Identifier()),
	))
	defer span.End()

	if err := from.Validate(); err != nil {
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
	go func() {
		// Ensure we close the event channel and the consumer.
		defer close(eventCh)
		defer func() {
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
			// (Note: Instead of deferring topicSpan.End() here, we’ll end it explicitly when the topic is done.)
			topicLogger := logger.NewLoggerContext(evtLogger.With("topic", topic, "partition", partition, "offset", offset))

			partitionConsumer, err := consumer.ConsumePartition(topic, partition, offset)
			if err != nil {
				topicLogger.Error(topicCtx, "Failed to create partition consumer", "error", err)
				topicSpan.RecordError(err)
				topicSpan.SetStatus(codes.Error, "failed to create partition consumer")
				topicSpan.End()
				// Proceed to the next topic instead of halting the entire replay.
				continue
			}
			topicSpan.AddEvent("partition_consumer_created")

			// Wrap the partition consumer loop in its own function scope so that
			// we can use a defer to close the partition consumer without affecting
			// subsequent iterations.
			// TODO: maybe extract into a helper function?
			func() {
				defer partitionConsumer.Close()

				var msgCount int64 = 0
				for {
					select {
					case msg := <-partitionConsumer.Messages():
						evtType, domainBytes, err := serialization.UnmarshalUniversalEnvelope(msg.Value)
						if err != nil {
							topicLogger.Error(topicCtx, "Failed to unmarshal event", "error", err, "msg_offset", msg.Offset)
							topicSpan.RecordError(err)
							continue
						}

						payload, err := serialization.DeserializePayload(evtType, domainBytes)
						if err != nil {
							topicLogger.Error(topicCtx, "Failed to deserialize payload", "error", err, "msg_offset", msg.Offset)
							topicSpan.RecordError(err)
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
							topicLogger.Debug(topicCtx, "Replayed event", "msg_offset", msg.Offset)
						case <-topicCtx.Done():
							topicSpan.AddEvent("context cancelled")
							return
						}

						msgCount++
						// Every 100 messages, record a batch event instead of starting a new span per message.
						if msgCount%100 == 0 {
							topicSpan.AddEvent("processed_100_messages", trace.WithAttributes(
								attribute.Int64("msg_count", msgCount),
							))
						}

					case <-topicCtx.Done():
						topicSpan.AddEvent("context cancelled")
						return

					case err := <-partitionConsumer.Errors():
						topicLogger.Error(topicCtx, "Error consuming message", "error", err)
						topicSpan.RecordError(err)
					}
				}
			}() // end of partitionConsumer loop

			// End the topic-specific span once its work is done.
			topicSpan.End()
		}
	}()

	return eventCh, nil
}

// Close closes the Kafka client associated with the EventReplayer.
// It should be called to clean up resources when the EventReplayer is no longer needed.
func (r *EventReplayer) Close() error {
	return r.client.Close()
}
