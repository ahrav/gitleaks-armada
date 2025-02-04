package scanning

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	domain "github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

type taskStatusEntry struct {
	status    domain.TaskStatus
	updatedAt time.Time
}

// shouldBeCleanedUp returns true if the task is in a terminal state and has been
// in that state for longer than the retention period, indicating it can be
// cleaned up.
func (t *taskStatusEntry) shouldBeCleanedUp(now time.Time, retentionPeriod time.Duration) bool {
	return t.status == domain.TaskStatusCompleted || t.status == domain.TaskStatusFailed &&
		now.Sub(t.updatedAt) > retentionPeriod
}

type pendingMetric struct {
	event     scanning.TaskJobMetricEvent
	timestamp time.Time
	attempts  int
}

var _ domain.JobMetricsTracker = (*jobMetricsTracker)(nil)

// jobMetricsTracker implements JobMetricsTracker with in-memory state and periodic persistence.
// TODO: We need a way to record the overall status of the job. We will want to use
// the metrics to determine this.
type jobMetricsTracker struct {
	metrics    map[uuid.UUID]*domain.JobMetrics // Job ID -> Metrics
	taskStatus map[uuid.UUID]taskStatusEntry    // Task ID -> Status
	repository domain.MetricsRepository         // Adapter to underlying job and task repositories

	checkpoints map[uuid.UUID]map[int32]int64 // Job ID -> Partition ID -> Offset
	replayer    events.DomainEventReplayer    // Replayer for consuming events to recover state

	// pendingMetrics is a map of task ID to a list of pending metrics that we have received but
	// haven't yet received a corresponding task status for.
	pendingMetrics map[uuid.UUID][]pendingMetric
	notifyCh       chan struct{}  // channel used to signal new work
	stopCh         chan struct{}  // channel used to signal shutdown
	wg             sync.WaitGroup // used to wait for background goroutine(s)

	// TODO: Enhance logging.
	logger *logger.Logger
	tracer trace.Tracer

	// Configuration.

	// cleanupInterval is how often we look for completed/failed tasks to clean up.
	cleanupInterval time.Duration
	// retentionPeriod is how long we retain task statuses after completion/failure.
	retentionPeriod time.Duration
	// retryInterval is how long we wait before checking our pending metrics
	// to see if there are any that failed to get processed initially.
	retryInterval time.Duration
	// maxRetries is the maximum number of retries we will attempt to get a task status.
	maxRetries int
	// TODO: Consider if we should have a max number of pending metrics we will
	// store.
}

// NewJobMetricsTracker creates a new JobMetricsTracker with the provided dependencies
// and configuration. It starts background cleanup of completed task statuses.
func NewJobMetricsTracker(
	repository domain.MetricsRepository,
	replayer events.DomainEventReplayer,
	logger *logger.Logger,
	tracer trace.Tracer,
) *jobMetricsTracker {
	const (
		defaultCleanupInterval = 15 * time.Minute
		defaultRetentionPeriod = 1 * time.Hour
		defaultRetryInterval   = 1 * time.Minute
		defaultMaxRetries      = 5
	)
	logger = logger.With("component", "job_metrics_tracker")

	t := &jobMetricsTracker{
		metrics:         make(map[uuid.UUID]*domain.JobMetrics),
		taskStatus:      make(map[uuid.UUID]taskStatusEntry),
		repository:      repository,
		checkpoints:     make(map[uuid.UUID]map[int32]int64),
		replayer:        replayer,
		pendingMetrics:  make(map[uuid.UUID][]pendingMetric),
		notifyCh:        make(chan struct{}, 1), // dont block on sending to notifyCh
		stopCh:          make(chan struct{}),
		logger:          logger,
		tracer:          tracer,
		cleanupInterval: defaultCleanupInterval,
		retentionPeriod: defaultRetentionPeriod,
		retryInterval:   defaultRetryInterval,
		maxRetries:      defaultMaxRetries,
	}

	// Start background cleanup.
	ctx := context.Background()
	go t.startStatusCleanupWorker(ctx)
	t.wg.Add(1)
	go t.runBackgroundLoop(ctx)

	return t
}

// startStatusCleanupWorker runs periodic cleanup of completed/failed task statuses.
func (t *jobMetricsTracker) startStatusCleanupWorker(ctx context.Context) {
	logger := t.logger.With(
		"operation", "start_status_cleanup_worker",
		"interval", t.cleanupInterval,
		"retention_period", t.retentionPeriod,
	)

	ctx, span := t.tracer.Start(ctx, "job_metrics_tracker.start_status_cleanup",
		trace.WithAttributes(
			attribute.String("interval", t.cleanupInterval.String()),
		))

	span.AddEvent("starting_status_cleanup_worker")
	logger.Info(ctx, "starting status cleanup worker")

	ticker := time.NewTicker(t.cleanupInterval)
	defer ticker.Stop()

	span.End()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.cleanupTaskStatus(ctx)
		}
	}
}

// cleanupTaskStatus removes completed/failed task status entries.
func (t *jobMetricsTracker) cleanupTaskStatus(ctx context.Context) {
	now := time.Now()
	logger := t.logger.With(
		"operation", "cleanup_task_status",
		"now", now,
		"task_status_count", len(t.taskStatus),
	)
	logger.Info(ctx, "cleaning up task statuses")
	for taskID, entry := range t.taskStatus {
		if entry.shouldBeCleanedUp(now, t.retentionPeriod) {
			delete(t.taskStatus, taskID)
			logger.Info(ctx, "task status cleaned up", "task_id", taskID)
		}
	}
	logger.Info(ctx, "finished cleaning up task statuses")
}

func (t *jobMetricsTracker) runBackgroundLoop(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer t.wg.Done()

	logger := t.logger.With("operation", "run_background_loop")

	ctx, span := t.tracer.Start(ctx, "job_metrics_tracker.run_background_loop")
	span.AddEvent("starting_background_loop")
	logger.Info(ctx, "starting background loop")

	span.End()

	ticker := time.NewTicker(t.retryInterval)
	defer ticker.Stop()

	for {
		// If there's nothing pending, block until we get a notify or a stop.
		if len(t.pendingMetrics) == 0 {
			select {
			case <-t.notifyCh:
				t.processPendingMetrics(ctx)
			case <-t.stopCh:
				return
			}
		}

		select {
		case <-ticker.C:
			t.processPendingMetrics(ctx)
		case <-t.notifyCh:
			t.processPendingMetrics(ctx)
		case <-t.stopCh:
			return
		}
	}
}

// HandleJobMetrics processes task-related events and updates job metrics accordingly.
// It maintains an in-memory state of task statuses and aggregates metrics per job.
//
// The method handles the following events:
// - TaskStartedEvent: When a task begins execution
// - TaskCompletedEvent: When a task successfully completes
// - TaskFailedEvent: When a task fails to complete
// - TaskStaleEvent: When a task is detected as stale/hung
//
// For each event, it:
// 1. Updates the task's status in memory
// 2. Updates the associated job's metrics based on the status transition
// 3. Maintains timing information for cleanup purposes
//
// This event handler is crucial for maintaining accurate job progress and health metrics,
// which are used for monitoring and reporting job execution status.
// TODO: Figure out if handling job metrics independently of task status updates could be
// problematic. There could be an instance where the task status update fails and the DB
// never has the task. This is okay for now since we retry using our pending metrics
// mechanism.
func (t *jobMetricsTracker) HandleJobMetrics(ctx context.Context, evt events.EventEnvelope) error {
	logger := logger.NewLoggerContext(t.logger.With(
		"operation", "handle_job_metrics",
		"event_type", evt.Type,
	))

	ctx, span := t.tracer.Start(ctx, "job_metrics_tracker.handle_job_metrics")
	defer span.End()

	metricEvt, ok := evt.Payload.(scanning.TaskJobMetricEvent)
	if !ok {
		span.SetStatus(codes.Error, "expected TaskJobMetricEvent")
		span.RecordError(fmt.Errorf("expected TaskJobMetricEvent, got %T", evt.Payload))
		return fmt.Errorf("expected TaskJobMetricEvent, got %T", evt.Payload)
	}

	span.SetAttributes(
		attribute.String("job_id", metricEvt.JobID.String()),
		attribute.String("task_id", metricEvt.TaskID.String()),
		attribute.String("status", string(metricEvt.Status)),
	)
	logger.Add(
		"job_id", metricEvt.JobID.String(),
		"task_id", metricEvt.TaskID.String(),
		"status", metricEvt.Status,
	)

	// Check if we need state recovery.
	_, exists := t.metrics[metricEvt.JobID]
	if !exists {
		metrics, err := t.repository.GetJobMetrics(ctx, metricEvt.JobID)
		if err != nil && !errors.Is(err, domain.ErrNoJobMetricsFound) {
			span.RecordError(err)
			span.SetStatus(codes.Error, "getting job metrics")
			logger.Error(ctx, "failed to get job metrics", "error", err)
			return err
		}
		if metrics == nil {
			logger.Debug(ctx, "no job metrics found, creating new job metrics")
			metrics = domain.NewJobMetrics()
		}

		t.metrics[metricEvt.JobID] = metrics

		checkpoints, err := t.repository.GetCheckpoints(ctx, metricEvt.JobID)
		if err != nil {
			if !errors.Is(err, domain.ErrNoCheckpointsFound) {
				span.RecordError(err)
				span.SetStatus(codes.Error, "getting checkpoints")
				logger.Error(ctx, "failed to get checkpoints", "error", err)
				return err
			}
			logger.Debug(ctx, "no checkpoints found, creating new checkpoints")
			span.AddEvent("no_checkpoints_found")
		}

		// Only replay if this partition has previous events.
		if len(checkpoints) > 0 {
			logger.Add("checkpoints_count", len(checkpoints))
			metadata := evt.Metadata
			if lastOffset, ok := checkpoints[metadata.Partition]; ok {
				logger.Add(
					"partition", metadata.Partition,
					"last_offset", lastOffset,
				)
				span.AddEvent("replaying_events", trace.WithAttributes(
					attribute.Int("partition", int(metadata.Partition)),
					attribute.Int64("offset", lastOffset),
				))
				logger.Info(ctx, "replaying events")
				if err := t.replayEvents(ctx, metricEvt.JobID, metadata.Partition, lastOffset); err != nil {
					span.RecordError(err)
					span.SetStatus(codes.Error, "replaying events")
					logger.Error(ctx, "failed to replay events", "error", err)
					return err
				}
				logger.Info(ctx, "events replayed successfully")
				span.AddEvent("events_replayed_successfully")
			}

			t.checkpoints[metricEvt.JobID] = checkpoints
			logger.Info(ctx, "replayed events, checkpoints updated")
		}
	}

	// Attempt to process the metric immediately.
	if err := t.processMetric(ctx, metricEvt); err != nil {
		if errors.Is(err, domain.ErrTaskNotFound) {
			span.AddEvent("task_not_found", trace.WithAttributes(
				attribute.String("task_id", metricEvt.TaskID.String()),
			))
			// We don't have the task status yet: add to pending for retry.
			t.pendingMetrics[metricEvt.JobID] = append(t.pendingMetrics[metricEvt.TaskID], pendingMetric{
				event:     metricEvt,
				timestamp: time.Now(),
			})
			span.AddEvent("pending_metric_added")
			logger.Debug(ctx, "pending metric added", "task_id", metricEvt.TaskID.String())
			// Notify the background loop that we have new pending work.
			select {
			case t.notifyCh <- struct{}{}:
			default:
			}
			return nil
		}
		span.AddEvent("failed_to_process_metric", trace.WithAttributes(
			attribute.String("error", err.Error()),
		))
		span.RecordError(err)
		logger.Error(ctx, "failed to process metric", "error", err)
		return err
	}
	if t.checkpoints[metricEvt.JobID] == nil {
		t.checkpoints[metricEvt.JobID] = make(map[int32]int64)
	}
	t.checkpoints[metricEvt.JobID][evt.Metadata.Partition] = evt.Metadata.Offset
	logger.Info(ctx, "checkpoints updated")
	span.AddEvent("metric_processed")
	span.SetStatus(codes.Ok, "metric processed")

	return nil
}

func (t *jobMetricsTracker) replayEvents(ctx context.Context, jobID uuid.UUID, partition int32, fromOffset int64) error {
	logger := t.logger.With(
		"operation", "replay_events",
		"job_id", jobID.String(),
		"partition", partition,
		"from_offset", fromOffset,
	)
	ctx, span := t.tracer.Start(ctx, "job_metrics_tracker.replay_events",
		trace.WithAttributes(
			attribute.String("job_id", jobID.String()),
			attribute.Int("partition", int(partition)),
			attribute.Int64("from_offset", fromOffset),
		),
	)
	defer span.End()

	events, err := t.replayer.ReplayFromPosition(ctx, scanning.NewJobMetricsPosition(jobID, partition, fromOffset))
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "replaying events")
		return fmt.Errorf(
			"failed to get events for jobID: %s, partition: %d, fromOffset: %d, error: %w",
			jobID.String(), partition, fromOffset, err,
		)
	}
	span.AddEvent("starting_event_replay_stream")

	for evt := range events {
		if metricEvt, ok := evt.Payload.(scanning.TaskJobMetricEvent); ok {
			if metricEvt.JobID == jobID {
				if err := t.processMetric(ctx, metricEvt); err != nil {
					// During replay, if task not found, just skip it
					// These are historical events, so if task doesn't exist
					// now, it likely never will
					if errors.Is(err, domain.ErrTaskNotFound) {
						span.RecordError(err)
						logger.Warn(ctx, "task not found, skipping event", "error", err)
						continue
					}
					span.RecordError(err)
					span.SetStatus(codes.Error, "processing replayed event")
					return fmt.Errorf("processing replayed event: %w", err)
				}
			} else {
				logger.Warn(ctx, "skipping event for different job", "job_id", metricEvt.JobID.String())
			}
		}
	}
	span.AddEvent("event_replay_stream_completed")
	span.SetStatus(codes.Ok, "event replay stream completed")

	return nil
}

// TODO: come back to this and see if reusing the underlying slice is a good idea.
// Probably not worth it right now.
func (t *jobMetricsTracker) processPendingMetrics(ctx context.Context) {
	logger := t.logger.With(
		"operation", "process_pending_metrics",
		"pending_metrics_count", len(t.pendingMetrics),
	)
	ctx, span := t.tracer.Start(ctx, "job_metrics_tracker.process_pending_metrics")
	defer span.End()

	span.AddEvent("processing_pending_metrics", trace.WithAttributes(
		attribute.Int("count", len(t.pendingMetrics)),
	))

	remaining := make(map[uuid.UUID][]pendingMetric)
	for taskID, metrics := range t.pendingMetrics {
		for _, pending := range metrics {
			if pending.attempts > t.maxRetries {
				// TODO: drop + do something.
				span.AddEvent("metric_dropped", trace.WithAttributes(
					attribute.String("task_id", pending.event.TaskID.String()),
				))
				logger.Warn(ctx, "metric dropped", "task_id", taskID.String())
				continue
			}

			err := t.processMetric(ctx, pending.event)
			if err != nil {
				if errors.Is(err, domain.ErrTaskNotFound) {
					// Still not found—bump attempts and re-queue.
					pending.attempts++
					remaining[taskID] = append(remaining[taskID], pending)
					span.AddEvent("metric_re-queued", trace.WithAttributes(
						attribute.String("task_id", taskID.String()),
					))
				} else {
					span.AddEvent("failed_to_process_metric", trace.WithAttributes(
						attribute.String("task_id", taskID.String()),
						attribute.String("error", err.Error()),
					))
					span.RecordError(err)
					logger.Error(ctx,
						"failed to process pending metric",
						"task_id", taskID.String(),
						"error", err,
					)
				}
			}
		}
	}
	span.AddEvent("pending_metrics_processed", trace.WithAttributes(
		attribute.Int("remaining", len(remaining)),
	))
	span.SetStatus(codes.Ok, "pending metrics processed")
	logger.Info(ctx, "pending metrics processed", "remaining", len(remaining))

	t.pendingMetrics = remaining
}

// processMetric encapsulates the core logic to update job metrics and task statuses.
// It returns domain.ErrTaskNotFound if the task does not yet exist (so callers
// can decide whether to retry or add to pending).
func (t *jobMetricsTracker) processMetric(ctx context.Context, evt scanning.TaskJobMetricEvent) error {
	ctx, span := t.tracer.Start(ctx, "job_metrics_tracker.process_metric")
	defer span.End()

	span.SetAttributes(
		attribute.String("job_id", evt.JobID.String()),
		attribute.String("task_id", evt.TaskID.String()),
		attribute.String("new_status", string(evt.Status)),
	)

	metrics := t.metrics[evt.JobID]

	if _, err := t.repository.GetTask(ctx, evt.TaskID); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "task not found")
		return fmt.Errorf("failed to get task with taskID: %s, error: %w", evt.TaskID.String(), err)
	}

	// Get the previous status from our in-memory cache.
	var oldStatus domain.TaskStatus
	if entry, exists := t.taskStatus[evt.TaskID]; exists {
		oldStatus = entry.status
	} else {
		oldStatus = domain.TaskStatusPending
	}

	span.SetAttributes(
		attribute.String("old_status", string(oldStatus)),
	)

	if oldStatus == domain.TaskStatusPending {
		metrics.OnTaskAdded(evt.Status)
		span.AddEvent("task_added")
	} else {
		metrics.OnTaskStatusChanged(oldStatus, evt.Status)
		span.AddEvent("task_status_changed")
	}

	t.taskStatus[evt.TaskID] = taskStatusEntry{
		status:    evt.Status,
		updatedAt: time.Now(),
	}
	span.AddEvent("task_status_cached")
	span.SetStatus(codes.Ok, "task metrics processed")

	return nil
}

// LaunchMetricsFlusher starts a background goroutine that periodically flushes metrics to storage.
func (t *jobMetricsTracker) LaunchMetricsFlusher(interval time.Duration) {
	logger := t.logger.With(
		"operation", "launch_metrics_flusher",
		"interval", interval,
	)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ctx, span := t.tracer.Start(ctx, "job_metrics_tracker.start_metrics_flush")

	span.AddEvent("starting_metrics_flusher")
	logger.Info(ctx, "starting metrics flusher")

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	span.End()

	for {
		select {
		case <-ctx.Done():
			// Ensure final flush on shutdown.
			t.FlushMetrics(ctx)
			return
		case <-ticker.C:
			t.FlushMetrics(ctx)
		}
	}
}

// FlushMetrics persists all in-memory job metrics to the underlying storage.
// This method is critical for durability, ensuring that job progress and statistics
// are not lost in case of system failures or restarts.
//
// It attempts to flush metrics for all tracked jobs, continuing even if some updates fail.
// If any errors occur during the flush, it logs them and returns the first error encountered
// while attempting to complete the remaining updates.
//
// This method is typically called periodically by a background goroutine to ensure
// regular persistence of metrics state.
func (t *jobMetricsTracker) FlushMetrics(ctx context.Context) {
	logger := t.logger.With("operation", "flush_metrics", "metrics_count", len(t.metrics))
	ctx, span := t.tracer.Start(ctx, "job_metrics_tracker.flush_metrics",
		trace.WithAttributes(
			attribute.Int("metrics_count", len(t.metrics)),
		),
	)
	defer span.End()

	span.AddEvent("starting_metrics_flush")

	for jobID, metrics := range t.metrics {
		chckpt := t.checkpoints[jobID]
		if len(chckpt) == 0 {
			span.AddEvent("no_partitions_to_flush", trace.WithAttributes(
				attribute.String("job_id", jobID.String()),
			))
			continue
		}
		span.AddEvent("flushing_partitions", trace.WithAttributes(
			attribute.String("job_id", jobID.String()),
			attribute.Int("num_partitions", len(chckpt)),
		))

		for partition, offset := range chckpt {
			if err := t.repository.UpdateMetricsAndCheckpoint(ctx, jobID, metrics, partition, offset); err != nil {
				span.RecordError(err)
				logger.Error(ctx, "failed to flush job metrics",
					"job_id", jobID.String(),
					"partition", partition,
					"offset", offset,
					"error", err,
				)
				continue
			}
			span.AddEvent("metrics_partition_flushed", trace.WithAttributes(
				attribute.String("job_id", jobID.String()),
				attribute.Int("partition", int(partition)),
				attribute.Int64("offset", offset),
			))
		}
	}
	span.AddEvent("metrics_flushed")
	span.SetStatus(codes.Ok, "metrics flushed")
	logger.Info(ctx, "metrics flushed")

	return
}

// Stop stops the background goroutines and waits for them to finish.
func (t *jobMetricsTracker) Stop(ctx context.Context) {
	_, span := t.tracer.Start(ctx, "job_metrics_tracker.stop")
	defer span.End()

	span.AddEvent("stopping_metrics_tracker")

	close(t.stopCh)

	// Lets flush any pending metrics.
	t.processPendingMetrics(context.Background())

	t.wg.Wait()

	span.AddEvent("metrics_tracker_stopped")
	span.SetStatus(codes.Ok, "metrics tracker stopped")
}
