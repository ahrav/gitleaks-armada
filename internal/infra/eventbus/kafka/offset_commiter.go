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
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

// OffsetCommitterMetrics defines metrics operations needed to monitor offset commit operations.
type OffsetCommitterMetrics interface {
	// Commit metrics.
	IncCommitStarted(ctx context.Context)
	IncCommitCompleted(ctx context.Context)
	IncCommitErrors(ctx context.Context)

	// Partition management metrics.
	IncPartitionManaged(ctx context.Context, topic string)
	IncPartitionManagementError(ctx context.Context, topic string)

	// Performance metrics.
	ObserveCommitDuration(ctx context.Context, duration time.Duration)
}

var _ events.OffsetCommitter = (*offsetCommiter)(nil)

// OffsetCommitterConfig contains the configuration required to commit offsets to Kafka.
type OffsetCommitterConfig struct {
	GroupID     string
	ClientID    string
	Brokers     []string
	TopicMapper TopicMapper
}

// offsetCommiter manages and persists consumer group offsets for Kafka topics.
// It provides thread-safe offset management across multiple partitions and ensures
// exactly-once message processing semantics by tracking consumption progress.
type offsetCommiter struct {
	topicMapper TopicMapper

	offsetMgr sarama.OffsetManager

	mu    sync.Mutex
	pomap map[string]map[int32]sarama.PartitionOffsetManager

	logger  *logger.Logger
	tracer  trace.Tracer
	metrics OffsetCommitterMetrics
}

// NewOffsetCommitter creates a new OffsetCommitter with the specified configuration.
func NewOffsetCommitter(
	cfg *OffsetCommitterConfig,
	logger *logger.Logger,
	metrics OffsetCommitterMetrics,
	tracer trace.Tracer,
) (*offsetCommiter, error) {
	config := sarama.NewConfig()
	config.Consumer.Return.Errors = true
	config.Version = sarama.V2_8_0_0
	config.ClientID = cfg.ClientID

	logger = logger.With("component", "kafka_offset_committer")

	client, err := sarama.NewClient(cfg.Brokers, config)
	if err != nil {
		return nil, fmt.Errorf("creating kafka client for offset committer: %w", err)
	}

	mgr, err := sarama.NewOffsetManagerFromClient(cfg.GroupID, client)
	if err != nil {
		return nil, fmt.Errorf("creating kafka offset manager for offset committer: %w", err)
	}

	return &offsetCommiter{
		offsetMgr:   mgr,
		topicMapper: cfg.TopicMapper,
		pomap:       make(map[string]map[int32]sarama.PartitionOffsetManager),
		logger:      logger,
		tracer:      tracer,
		metrics:     metrics,
	}, nil
}

// CommitPosition persists the given stream position to Kafka's offset management system.
// It expects a position identifier in the format "streamType:partition:offset" and ensures
// thread-safe access to partition-specific offset managers.
func (k *offsetCommiter) CommitPosition(ctx context.Context, streamPos events.StreamPosition) error {
	start := time.Now()
	k.metrics.IncCommitStarted(ctx)
	defer func() {
		k.metrics.ObserveCommitDuration(ctx, time.Since(start))
	}()

	logr := logger.NewLoggerContext(k.logger.With("stream_position", streamPos.Identifier()))
	ctx, span := k.tracer.Start(ctx, "kafka_offset_committer.commit_position", trace.WithAttributes(
		attribute.String("component", "kafka_offset_committer"),
		attribute.String("stream_position", streamPos.Identifier()),
	))
	defer span.End()
	logr.Debug(ctx, "Starting offset commit")

	// Since we've already validated the position, we can safely type assert.
	pos, ok := streamPos.(Position)
	if !ok {
		k.metrics.IncCommitErrors(ctx)
		span.RecordError(fmt.Errorf("invalid position type"))
		span.SetStatus(codes.Error, "invalid position type")
		return fmt.Errorf("expected kafka.Position, got %T", streamPos)
	}

	topic, err := k.topicMapper.GetTopicForStreamType(pos.EntityType)
	if err != nil {
		k.metrics.IncCommitErrors(ctx)
		span.RecordError(err)
		span.SetStatus(codes.Error, "invalid entity type")
		return fmt.Errorf("invalid entity type: %w", err)
	}

	logr.Add("partition", pos.Partition, "offset", pos.Offset, "topic", topic)
	span.SetAttributes(
		attribute.Int64("partition", int64(pos.Partition)),
		attribute.Int64("offset", pos.Offset),
		attribute.String("topic", topic),
	)

	k.mu.Lock()
	defer k.mu.Unlock()

	topicMap, exists := k.pomap[topic]
	if !exists {
		topicMap = make(map[int32]sarama.PartitionOffsetManager)
		k.pomap[topic] = topicMap
	}

	pom, exists := topicMap[pos.Partition]
	if !exists {
		logr.Debug(ctx, "Managing partition")
		var err error
		pom, err = k.offsetMgr.ManagePartition(topic, pos.Partition)
		if err != nil {
			k.metrics.IncPartitionManagementError(ctx, topic)
			span.RecordError(err)
			span.SetStatus(codes.Error, "failed to manage partition")
			return fmt.Errorf("failed to manage partition %d: %w", pos.Partition, err)
		}
		k.metrics.IncPartitionManaged(ctx, topic)
		topicMap[pos.Partition] = pom
		span.AddEvent("partition_managed")
	}

	// Mark the next offset (X+1)
	pom.MarkOffset(pos.Offset+1, "committed by KafkaOffsetCommitter")
	logr.Debug(ctx, "Successfully marked offset")
	span.AddEvent("offset_marked")

	// Commit the marked offsets.
	// This is blocking.
	// TODO: consider using a non-blocking approach with a separate goroutine.
	k.offsetMgr.Commit()

	span.AddEvent("offsets_committed")
	logr.Debug(ctx, "Successfully committed offsets")

	k.metrics.IncCommitCompleted(ctx)
	span.SetStatus(codes.Ok, "position committed")

	return nil
}

// Close releases all resources held by the offset committer, including partition managers
// and the main offset manager. It should be called when the committer is no longer needed
// to prevent resource leaks.
func (k *offsetCommiter) Close() error {
	ctx, span := k.tracer.Start(context.Background(), "kafka_offset_committer.close", trace.WithAttributes(
		attribute.String("component", "kafka_offset_committer"),
	))
	defer span.End()
	k.logger.Info(ctx, "Closing KafkaOffsetCommitter")

	k.mu.Lock()
	defer k.mu.Unlock()

	var firstErr error
	for _, topicMap := range k.pomap {
		for _, pom := range topicMap {
			if err := pom.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	if err := k.offsetMgr.Close(); err != nil && firstErr == nil {
		firstErr = err
	}

	// TODO: Handle errors correctly here. We can't just handle the first error.

	k.logger.Info(ctx, "KafkaOffsetCommitter closed")

	return firstErr
}
