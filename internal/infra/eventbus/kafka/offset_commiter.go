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

var _ events.OffsetCommitter = (*KafkaOffsetCommitter)(nil)

// KafkaOffsetCommitter manages and persists consumer group offsets for Kafka topics.
// It provides thread-safe offset management across multiple partitions and ensures
// exactly-once message processing semantics by tracking consumption progress.
type KafkaOffsetCommitter struct {
	offsetMgr sarama.OffsetManager

	topic string

	mu    sync.Mutex
	pomap map[int32]sarama.PartitionOffsetManager

	logger *logger.Logger
	tracer trace.Tracer
	// TODO: add metrics
}

// NewKafkaOffsetCommitter creates a new KafkaOffsetCommitter with the specified offset manager,
// topic, logger, and tracer. It initializes internal state for partition management.
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

// CommitPosition persists the given stream position to Kafka's offset management system.
// It expects a position identifier in the format "partition:offset" and ensures
// thread-safe access to partition-specific offset managers.
func (k *KafkaOffsetCommitter) CommitPosition(ctx context.Context, streamPos events.StreamPosition) error {
	logr := logger.NewLoggerContext(k.logger.With("stream_position", streamPos.Identifier()))
	ctx, span := k.tracer.Start(ctx, "kafka_offset_committer.commit_position", trace.WithAttributes(
		attribute.String("component", "kafka_offset_committer"),
		attribute.String("stream_position", streamPos.Identifier()),
	))
	defer span.End()
	logr.Debug(ctx, "Starting offset commit")

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
	logr.Add("partition", partition, "offset", offset)
	span.SetAttributes(
		attribute.Int64("partition", int64(partition)),
		attribute.Int64("offset", offset),
	)

	k.mu.Lock()
	defer k.mu.Unlock()
	pom, exists := k.pomap[partition]
	if !exists {
		logr.Debug(ctx, "Managing partition")
		var err error
		pom, err = k.offsetMgr.ManagePartition(k.topic, partition)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "failed to manage partition")
			return fmt.Errorf("failed to manage partition %d: %w", partition, err)
		}
		k.pomap[partition] = pom
		span.AddEvent("partition_managed")
	}

	// Mark the next offset (X+1).
	pom.MarkOffset(offset+1, "committed by KafkaOffsetCommitter")
	logr.Debug(ctx, "Successfully marked offset")
	span.AddEvent("offset_marked")
	span.SetStatus(codes.Ok, "position committed")

	return nil
}

// Close releases all resources held by the offset committer, including partition managers
// and the main offset manager. It should be called when the committer is no longer needed
// to prevent resource leaks.
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
