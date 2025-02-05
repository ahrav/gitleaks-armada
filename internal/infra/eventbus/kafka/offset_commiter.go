package kafka

import (
	"context"
	"fmt"
	"sync"

	"github.com/IBM/sarama"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

// KafkaOffsetCommitter commits offsets given a Kafka stream position.
// It is unaware of domain-level abstractions.
type KafkaOffsetCommitter struct {
	offsetMgr sarama.OffsetManager

	topic string

	mu    sync.Mutex
	pomap map[int32]sarama.PartitionOffsetManager

	logger *logger.Logger
	tracer trace.Tracer
	// TODO: add metrics
}

// NewKafkaOffsetCommitter creates a new KafkaOffsetCommitter.
func NewKafkaOffsetCommitter(
	offsetMgr sarama.OffsetManager,
	topic string,
	logger *logger.Logger,
	tracer trace.Tracer,
) *KafkaOffsetCommitter {
	logger = logger.With("component", "kafka_offset_committer")
	return &KafkaOffsetCommitter{
		offsetMgr: offsetMgr,
		topic:     topic,
		pomap:     make(map[int32]sarama.PartitionOffsetManager),
		logger:    logger,
		tracer:    tracer,
	}
}

// CommitStreamPosition commits the given stream position (expects a Kafka Position).
func (k *KafkaOffsetCommitter) CommitStreamPosition(ctx context.Context, streamPos events.StreamPosition) error {
	ctx, span := k.tracer.Start(ctx, "kafka_offset_committer.commit_stream_position", trace.WithAttributes(
		attribute.String("component", "kafka_offset_committer"),
		attribute.String("stream_position", streamPos.Identifier()),
	))
	defer span.End()

	if err := streamPos.Validate(); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "invalid position")
		return fmt.Errorf("invalid position: %w", err)
	}

	identifier := streamPos.Identifier()
	var (
		partition int32
		offset    int64
	)
	if _, err := fmt.Sscanf(identifier, "%d:%d", &partition, &offset); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "invalid position identifier format")
		return fmt.Errorf("invalid position identifier format: %w", err)
	}
	span.SetAttributes(
		attribute.Int64("partition", int64(partition)),
		attribute.Int64("offset", offset),
	)

	k.mu.Lock()
	pom, exists := k.pomap[partition]
	if !exists {
		var err error
		pom, err = k.offsetMgr.ManagePartition(k.topic, partition)
		if err != nil {
			k.mu.Unlock()
			return fmt.Errorf("failed to manage partition %d: %w", partition, err)
		}
		k.pomap[partition] = pom
	}
	k.mu.Unlock()

	// Mark the next offset (X+1).
	pom.MarkOffset(offset+1, "committed by KafkaOffsetCommitter")
	return nil
}

// Close closes the offset manager and all partition offset managers.
func (k *KafkaOffsetCommitter) Close() error {
	ctx, span := k.tracer.Start(context.Background(), "kafka_offset_committer.close", trace.WithAttributes(
		attribute.String("component", "kafka_offset_committer"),
	))
	defer span.End()
	k.logger.Info(ctx, "Closing KafkaOffsetCommitter")

	k.mu.Lock()
	defer k.mu.Unlock()

	var firstErr error
	for _, pom := range k.pomap {
		if err := pom.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if err := k.offsetMgr.Close(); err != nil && firstErr == nil {
		firstErr = err
	}

	// TODO: Handle errors correctly here. We can't just handle the first error.

	k.logger.Info(ctx, "KafkaOffsetCommitter closed")

	return firstErr
}
