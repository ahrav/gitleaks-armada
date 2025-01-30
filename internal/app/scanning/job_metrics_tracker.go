package scanning

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
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
type jobMetricsTracker struct {
	metrics    map[uuid.UUID]*domain.JobMetrics // Job ID -> Metrics
	taskStatus map[uuid.UUID]taskStatusEntry    // Task ID -> Status
	repository domain.MetricsRepository         // Adapter to underlying job and task repositories

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
func (t *jobMetricsTracker) HandleJobMetrics(ctx context.Context, evt events.EventEnvelope) error {
	ctx, span := t.tracer.Start(ctx, "job_metrics_tracker.handle_job_metrics")
	defer span.End()

	metricEvt, ok := evt.Payload.(scanning.TaskJobMetricEvent)
	if !ok {
		return fmt.Errorf("expected TaskJobMetricEvent, got %T", evt.Payload)
	}

	span.SetAttributes(
		attribute.String("job_id", metricEvt.JobID.String()),
		attribute.String("task_id", metricEvt.TaskID.String()),
		attribute.String("status", string(metricEvt.Status)),
	)

	// Attempt to process the metric immediately.
	if err := t.processMetric(ctx, metricEvt); err != nil {
		if errors.Is(err, domain.ErrTaskNotFound) {
			// We don’t have the task status yet: add to pending for retry.
			t.pendingMetrics = append(t.pendingMetrics, pendingMetric{
				event:     metricEvt,
				timestamp: time.Now(),
			})
			// Notify the background loop that we have new pending work.
			select {
			case t.notifyCh <- struct{}{}:
			default:
			}
			return nil
		}
		return fmt.Errorf("processing metric: %w", err)
	}

	return nil
}

func (t *jobMetricsTracker) runBackgroundLoop() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer t.wg.Done()

	ticker := time.NewTicker(t.retryInterval)
	defer ticker.Stop()

	for {
		// If there’s nothing pending, block until we get a notify or a stop.
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

func (t *jobMetricsTracker) processPendingMetrics(ctx context.Context) {
	var remaining []pendingMetric
	for _, pending := range t.pendingMetrics {
		if pending.attempts > t.maxRetries {
			// TODO: drop + do something.
			continue
		}

		err := t.processMetric(ctx, pending.event)
		if err != nil {
			if errors.Is(err, domain.ErrTaskNotFound) {
				// Still not found—bump attempts and re-queue.
				pending.attempts++
				remaining = append(remaining, pending)
			} else {
				t.logger.Error(ctx,
					"failed to process pending metric",
					"task_id", pending.event.TaskID.String(),
					"error", err,
				)
			}
		}
	}
	t.pendingMetrics = remaining
}

// processMetric encapsulates the core logic to update job metrics and task statuses.
// It returns domain.ErrTaskNotFound if the task status does not yet exist (so callers
// can decide whether to retry or add to pending).
func (t *jobMetricsTracker) processMetric(ctx context.Context, evt scanning.TaskJobMetricEvent) error {
	ctx, span := t.tracer.Start(ctx, "job_metrics_tracker.process_metric")
	defer span.End()

	span.SetAttributes(
		attribute.String("job_id", evt.JobID.String()),
		attribute.String("task_id", evt.TaskID.String()),
		attribute.String("status", string(evt.Status)),
	)

	metrics, exists := t.metrics[evt.JobID]
	if !exists {
		var err error
		metrics, err = t.repository.GetJobMetrics(ctx, evt.JobID)
		if err != nil {
			// If the job doesn't exist in repository, treat it as "no metrics found"
			// but if it's some other error, bubble up.
			if !errors.Is(err, domain.ErrNoJobMetricsFound) {
				return fmt.Errorf("getting job metrics: %w", err)
			}
			metrics = domain.NewJobMetrics()
		}
		t.metrics[evt.JobID] = metrics
	}

	oldStatus, err := t.getTaskStatus(ctx, evt.TaskID)
	if err != nil {
		return err
	}

	if oldStatus == domain.TaskStatusPending {
		metrics.OnTaskAdded(evt.Status)
	} else {
		metrics.OnTaskStatusChanged(oldStatus, evt.Status)
	}

	t.taskStatus[evt.TaskID] = taskStatusEntry{
		status:    evt.Status,
		updatedAt: time.Now(),
	}

	return nil
}

// getTaskStatus retrieves task status from memory or falls back to repository.
func (t *jobMetricsTracker) getTaskStatus(ctx context.Context, taskID uuid.UUID) (domain.TaskStatus, error) {
	if status, exists := t.taskStatus[taskID]; exists {
		return status.status, nil
	}

	status, err := t.repository.GetTaskStatus(ctx, taskID)
	if err != nil {
		return "", err
	}

	t.taskStatus[taskID] = taskStatusEntry{
		status:    status,
		updatedAt: time.Now(),
	}
	return status, nil
}

// startStatusCleanup runs periodic cleanup of completed/failed task statuses.
func (t *jobMetricsTracker) startStatusCleanup(ctx context.Context) {
	ticker := time.NewTicker(t.cleanupInterval)
	defer ticker.Stop()

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

// LaunchMetricsFlusher starts a background goroutine that periodically flushes metrics to storage.
func (t *jobMetricsTracker) LaunchMetricsFlusher(interval time.Duration) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ctx, span := t.tracer.Start(ctx, "job_metrics_tracker.start_metrics_flush")
	defer span.End()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

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

	var firstErr error
	for jobID, metrics := range t.metrics {
		if err := t.repository.UpdateJobMetrics(ctx, jobID, metrics); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			t.logger.Error(ctx, "failed to flush job metrics",
				"job_id", jobID.String(),
				"error", err,
			)
			continue
		}
	}

	return firstErr
}

// Stop stops the background goroutines and waits for them to finish.
func (t *jobMetricsTracker) Stop(ctx context.Context) {
	close(t.stopCh)

	// Lets flush any pending metrics.
	t.processPendingMetrics(context.Background())

	t.wg.Wait()
}
