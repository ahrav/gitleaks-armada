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

	// pendingMetrics is a list of pending metrics that we have received but
	// haven't yet received a corresponding task status for.
	pendingMetrics []pendingMetric
	notifyCh       chan struct{}  // channel used to signal new work
	stopCh         chan struct{}  // channel used to signal shutdown
	wg             sync.WaitGroup // used to wait for background goroutine(s)

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
	logger *logger.Logger,
	tracer trace.Tracer,
) *jobMetricsTracker {
	const (
		defaultCleanupInterval = 15 * time.Minute
		defaultRetentionPeriod = 1 * time.Hour
		defaultRetryInterval   = 1 * time.Minute
		defaultMaxRetries      = 5
	)

	t := &jobMetricsTracker{
		metrics:         make(map[uuid.UUID]*domain.JobMetrics),
		taskStatus:      make(map[uuid.UUID]taskStatusEntry),
		repository:      repository,
		checkpoints:     make(map[uuid.UUID]map[int32]int64),
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
	go t.startStatusCleanup(context.Background())
	t.wg.Add(1)
	go t.runBackgroundLoop()

	return t
}

// startStatusCleanup runs periodic cleanup of completed/failed task statuses.
func (t *jobMetricsTracker) startStatusCleanup(ctx context.Context) {
	ctx, span := t.tracer.Start(ctx, "job_metrics_tracker.start_status_cleanup",
		trace.WithAttributes(
			attribute.String("interval", t.cleanupInterval.String()),
		))

	span.AddEvent("starting_status_cleanup")

	ticker := time.NewTicker(t.cleanupInterval)
	defer ticker.Stop()

	span.End()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.cleanupTaskStatus()
		}
	}
}

// cleanupTaskStatus removes completed/failed task status entries.
func (t *jobMetricsTracker) cleanupTaskStatus() {
	now := time.Now()
	for taskID, entry := range t.taskStatus {
		if entry.shouldBeCleanedUp(now, t.retentionPeriod) {
			delete(t.taskStatus, taskID)
		}
	}
}

func (t *jobMetricsTracker) runBackgroundLoop() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer t.wg.Done()

	ctx, span := t.tracer.Start(ctx, "job_metrics_tracker.run_background_loop")

	span.AddEvent("starting_background_loop")
	span.End()

	ticker := time.NewTicker(t.retryInterval)
	defer ticker.Stop()

	for {
		// If there's nothing pending, block until we get a notify or a stop.
		if len(t.pendingMetrics) == 0 {
			select {
			case <-t.notifyCh:
				// got new metrics, continue.
			case <-t.stopCh:
				return
			}
		}

		select {
		case <-ticker.C:
			t.processPendingMetrics(ctx)
		case <-t.notifyCh:
			// There's new items; maybe keep them for next tick or process immediately
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

	// Check if we need state recovery.
	metrics, exists := t.metrics[metricEvt.JobID]
	if !exists {
		var err error
		metrics, err = t.repository.GetJobMetrics(ctx, metricEvt.JobID)
		if err != nil && !errors.Is(err, domain.ErrNoJobMetricsFound) {
			return fmt.Errorf("getting job metrics: %w", err)
		}
		if metrics == nil {
			metrics = domain.NewJobMetrics()
		}

		checkpoints, err := t.repository.GetCheckpoints(ctx, metricEvt.JobID)
		if err != nil {
			return fmt.Errorf("getting checkpoints: %w", err)
		}

		// Only replay if this partition has previous events.
		metadata := evt.Metadata
		if lastOffset, ok := checkpoints[metadata.Partition]; ok {
			if err := t.replayEvents(ctx, metricEvt.JobID, metadata.Partition, lastOffset); err != nil {
				return fmt.Errorf("replaying events: %w", err)
			}
		}

		t.metrics[metricEvt.JobID] = metrics
		t.checkpoints[metricEvt.JobID] = checkpoints
	}

	// Attempt to process the metric immediately.
	if err := t.processMetric(ctx, metricEvt); err != nil {
		if errors.Is(err, domain.ErrTaskNotFound) {
			span.AddEvent("task_not_found", trace.WithAttributes(
				attribute.String("task_id", metricEvt.TaskID.String()),
			))
			// We don't have the task status yet: add to pending for retry.
			t.pendingMetrics = append(t.pendingMetrics, pendingMetric{
				event:     metricEvt,
				timestamp: time.Now(),
			})
			span.AddEvent("pending_metric_added")
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
		return fmt.Errorf("processing metric: %w", err)
	}

	span.AddEvent("metric_processed")
	span.SetStatus(codes.Ok, "metric processed")

	return nil
}

func (t *jobMetricsTracker) replayEvents(ctx context.Context, jobID uuid.UUID, partition int32, fromOffset int64) error {
	events, err := t.kafkaClient.ConsumeFromOffset(ctx, partition, fromOffset)
	if err != nil {
		return fmt.Errorf("consuming events: %w", err)
	}

	for _, evt := range events {
		if metricEvt, ok := evt.Payload.(scanning.TaskJobMetricEvent); ok {
			if metricEvt.JobID == jobID {
				if err := t.processMetric(ctx, metricEvt); err != nil {
					// During replay, if task not found, just skip it
					// These are historical events, so if task doesn't exist
					// now, it likely never will
					if errors.Is(err, domain.ErrTaskNotFound) {
						continue
					}
					return fmt.Errorf("processing replayed event: %w", err)
				}
			}
		}
	}

	return nil
}

// TODO: come back to this and see if reusing the underlying slice is a good idea.
// Probably not worth it right now.
func (t *jobMetricsTracker) processPendingMetrics(ctx context.Context) {
	ctx, span := t.tracer.Start(ctx, "job_metrics_tracker.process_pending_metrics")
	defer span.End()

	span.AddEvent("processing_pending_metrics", trace.WithAttributes(
		attribute.Int("count", len(t.pendingMetrics)),
	))

	var remaining []pendingMetric
	for _, pending := range t.pendingMetrics {
		if pending.attempts > t.maxRetries {
			// TODO: drop + do something.
			span.AddEvent("metric_dropped", trace.WithAttributes(
				attribute.String("task_id", pending.event.TaskID.String()),
			))
			t.logger.Warn(ctx, "metric dropped", "task_id", pending.event.TaskID.String())
			continue
		}

		err := t.processMetric(ctx, pending.event)
		if err != nil {
			if errors.Is(err, domain.ErrTaskNotFound) {
				// Still not found—bump attempts and re-queue.
				pending.attempts++
				remaining = append(remaining, pending)
				span.AddEvent("metric_re-queued", trace.WithAttributes(
					attribute.String("task_id", pending.event.TaskID.String()),
				))
			} else {
				span.AddEvent("failed_to_process_metric", trace.WithAttributes(
					attribute.String("task_id", pending.event.TaskID.String()),
					attribute.String("error", err.Error()),
				))
				span.RecordError(err)
				t.logger.Error(ctx,
					"failed to process pending metric",
					"task_id", pending.event.TaskID.String(),
					"error", err,
				)
			}
		}
	}
	span.AddEvent("pending_metrics_processed", trace.WithAttributes(
		attribute.Int("remaining", len(remaining)),
	))
	span.SetStatus(codes.Ok, "pending metrics processed")

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
		return err
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ctx, span := t.tracer.Start(ctx, "job_metrics_tracker.start_metrics_flush")

	span.AddEvent("starting_metrics_flusher")

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	span.End()

	for {
		select {
		case <-ctx.Done():
			// Ensure final flush on shutdown.
			_ = t.FlushMetrics(ctx)
			return
		case <-ticker.C:
			if err := t.FlushMetrics(ctx); err != nil {
				// Error handling done within FlushMetrics.
				continue
			}
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
func (t *jobMetricsTracker) FlushMetrics(ctx context.Context) error {
	ctx, span := t.tracer.Start(ctx, "job_metrics_tracker.flush_metrics")
	defer span.End()

	span.AddEvent("flushing_metrics")

	for jobID, metrics := range t.metrics {
		if err := t.repository.UpdateJobMetrics(ctx, jobID, metrics); err != nil {
			span.RecordError(err)
			t.logger.Error(ctx, "failed to flush job metrics",
				"job_id", jobID.String(),
				"error", err,
			)
			continue
		}
	}
	span.AddEvent("metrics_flushed")
	span.SetStatus(codes.Ok, "metrics flushed")

	return nil
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
