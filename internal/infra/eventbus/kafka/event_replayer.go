package kafka

import (
	"context"
	"fmt"

	"github.com/IBM/sarama"
	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/infra/eventbus/serialization"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

type KafkaPosition struct {
	Partition int32
	Offset    int64
}

func (p KafkaPosition) Identifier() string {
	return fmt.Sprintf("%d:%d", p.Partition, p.Offset)
}

func (p KafkaPosition) Validate() error {
	if p.Partition < 0 {
		return fmt.Errorf("invalid partition: %d", p.Partition)
	}
	if p.Offset < 0 {
		return fmt.Errorf("invalid offset: %d", p.Offset)
	}
	return nil
}

type ReplayConfig struct {
	Brokers []string
	Topics  []string
}

type KafkaEventReplayer struct {
	client  sarama.Client
	config  *ReplayConfig
	logger  *logger.Logger
	tracer  trace.Tracer
	metrics BrokerMetrics
}

func NewKafkaEventReplayer(cfg *ReplayConfig, logger *logger.Logger, metrics BrokerMetrics, tracer trace.Tracer) (*KafkaEventReplayer, error) {
	config := sarama.NewConfig()
	config.Consumer.Return.Errors = true
	config.Version = sarama.V2_8_0_0

	client, err := sarama.NewClient(cfg.Brokers, config)
	if err != nil {
		return nil, fmt.Errorf("creating kafka client: %w", err)
	}

	return &KafkaEventReplayer{
		client:  client,
		config:  cfg,
		logger:  logger,
		metrics: metrics,
		tracer:  tracer,
	}, nil
}

func (r *KafkaEventReplayer) ReplayEvents(ctx context.Context, from events.StreamPosition) (<-chan events.EventEnvelope, error) {
	ctx, span := r.tracer.Start(ctx, "kafka_replayer.replay_events")
	defer span.End()

	pos, ok := from.(KafkaPosition)
	if !ok {
		return nil, fmt.Errorf("expected KafkaPosition, got %T", from)
	}

	if err := pos.Validate(); err != nil {
		return nil, fmt.Errorf("invalid position: %w", err)
	}

	span.SetAttributes(
		attribute.Int64("partition", int64(pos.Partition)),
		attribute.Int64("offset", pos.Offset),
	)

	consumer, err := sarama.NewConsumerFromClient(r.client)
	if err != nil {
		return nil, fmt.Errorf("creating consumer: %w", err)
	}

	// Create a channel for sending events
	eventCh := make(chan events.EventEnvelope)

	// Start consuming in a separate goroutine
	go func() {
		defer close(eventCh)
		defer consumer.Close()

		// Create a partition consumer for each topic
		for _, topic := range r.config.Topics {
			partitionConsumer, err := consumer.ConsumePartition(topic, pos.Partition, pos.Offset)
			if err != nil {
				r.logger.Error(ctx, "Failed to create partition consumer",
					"topic", topic,
					"partition", pos.Partition,
					"error", err,
				)
				return
			}
			defer partitionConsumer.Close()

			// Process messages until context is cancelled or partition EOF
			for {
				select {
				case msg := <-partitionConsumer.Messages():
					evtType, domainBytes, err := serialization.UnmarshalUniversalEnvelope(msg.Value)
					if err != nil {
						r.logger.Error(ctx, "Failed to unmarshal event",
							"error", err,
							"offset", msg.Offset,
						)
						continue
					}

					payload, err := serialization.DeserializePayload(evtType, domainBytes)
					if err != nil {
						r.logger.Error(ctx, "Failed to deserialize payload",
							"error", err,
							"offset", msg.Offset,
						)
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

					// Try to send event or exit if context is cancelled
					select {
					case eventCh <- evt:
						r.logger.Debug(ctx, "Replayed event",
							"topic", topic,
							"partition", msg.Partition,
							"offset", msg.Offset,
						)
					case <-ctx.Done():
						return
					}

				case <-ctx.Done():
					return

				case err := <-partitionConsumer.Errors():
					r.logger.Error(ctx, "Error consuming message",
						"topic", topic,
						"partition", pos.Partition,
						"error", err,
					)
				}
			}
		}
	}()

	return eventCh, nil
}

func (r *KafkaEventReplayer) Close() error {
	return r.client.Close()
}
