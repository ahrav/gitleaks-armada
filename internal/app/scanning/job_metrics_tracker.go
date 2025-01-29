package scanning

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	domain "github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

// MetricsRepository defines the minimal persistence requirements for job metrics tracking.
// This interface is designed to be implemented by adapting existing job and task repositories,
// allowing for efficient access to metrics-specific data without requiring full entity loads.
type MetricsRepository interface {
	// GetJobMetrics retrieves the metrics for a specific job.
	// Returns ErrJobNotFound if the job doesn't exist.
	GetJobMetrics(ctx context.Context, jobID uuid.UUID) (*domain.JobMetrics, error)

	// UpdateJobMetrics atomically updates the metrics for a job.
	// Returns ErrJobNotFound if the job doesn't exist or ErrInvalidMetrics if the metrics are invalid.
	UpdateJobMetrics(ctx context.Context, jobID uuid.UUID, metrics *domain.JobMetrics) error

	// GetTaskStatus efficiently retrieves just the status of a task.
	// Returns ErrTaskNotFound if the task doesn't exist.
	GetTaskStatus(ctx context.Context, taskID uuid.UUID) (domain.TaskStatus, error)
}

// metricsRepositoryAdapter adapts existing job and task repositories to implement
// the MetricsRepository interface. It provides efficient access to metrics-related
// data by potentially optimizing database queries for specific fields.
type metricsRepositoryAdapter struct {
	jobRepo  domain.JobRepository
	taskRepo domain.TaskRepository
}

// NewMetricsRepository creates a new MetricsRepository implementation that wraps
// existing job and task repositories. This adapter pattern allows reuse of existing
// persistence logic while providing a focused interface for metrics operations.
func NewMetricsRepository(jobRepo domain.JobRepository, taskRepo domain.TaskRepository) MetricsRepository {
	return &metricsRepositoryAdapter{jobRepo: jobRepo, taskRepo: taskRepo}
}

// ErrInvalidMetrics indicates the provided metrics are invalid
var ErrInvalidMetrics = errors.New("invalid metrics")

// GetJobMetrics implements MetricsRepository.GetJobMetrics by retrieving metrics
// from the underlying job repository.
func (r *metricsRepositoryAdapter) GetJobMetrics(ctx context.Context, jobID uuid.UUID) (*domain.JobMetrics, error) {
	if jobID == uuid.Nil {
		return nil, fmt.Errorf("%w: invalid job ID", ErrInvalidMetrics)
	}

	metrics, err := r.jobRepo.GetJobMetrics(ctx, jobID)
	if err != nil {
		if errors.Is(err, domain.ErrNoJobMetricsFound) {
			return nil, fmt.Errorf("getting job metrics: %w", domain.ErrNoJobMetricsFound)
		}
		return nil, fmt.Errorf("getting job metrics: %w", err)
	}

	return metrics, nil
}

// UpdateJobMetrics implements MetricsRepository.UpdateJobMetrics by delegating to
// the underlying job repository. The update is expected to be atomic to prevent
// race conditions in concurrent updates.
func (r *metricsRepositoryAdapter) UpdateJobMetrics(
	ctx context.Context,
	jobID uuid.UUID,
	metrics *domain.JobMetrics,
) error {
	if jobID == uuid.Nil {
		return fmt.Errorf("%w: invalid job ID", ErrInvalidMetrics)
	}
	if metrics == nil {
		return fmt.Errorf("%w: nil metrics", ErrInvalidMetrics)
	}
	// if !metrics.IsValid() {
	// 	return fmt.Errorf("%w: metrics validation failed", ErrInvalidMetrics)
	// }

	_, err := r.jobRepo.BulkUpdateJobMetrics(ctx, map[uuid.UUID]*domain.JobMetrics{
		jobID: metrics,
	})
	if err != nil {
		if errors.Is(err, domain.ErrNoJobMetricsUpdated) {
			return fmt.Errorf("updating job metrics: %w", domain.ErrNoJobMetricsUpdated)
		}
		return fmt.Errorf("updating job metrics: %w", err)
	}

	return nil
}

// GetTaskStatus implements MetricsRepository.GetTaskStatus by efficiently retrieving
// just the task status from the underlying task repository. This could be optimized
// in the future to only fetch the status field from the database.
func (r *metricsRepositoryAdapter) GetTaskStatus(ctx context.Context, taskID uuid.UUID) (domain.TaskStatus, error) {
	if taskID == uuid.Nil {
		return "", fmt.Errorf("%w: invalid task ID", domain.ErrTaskNotFound)
	}

	task, err := r.taskRepo.GetTask(ctx, taskID)
	if err != nil {
		if errors.Is(err, domain.ErrTaskNotFound) {
			return "", fmt.Errorf("getting task status: %w", domain.ErrTaskNotFound)
		}
		return "", fmt.Errorf("getting task status: %w", err)
	}

	return task.Status(), nil
}

// JobMetricsTracker handles aggregation and persistence of job-level metrics
// across distributed task processing. It maintains in-memory state of task
// statuses and job metrics, with periodic persistence to a backing store.
type JobMetricsTracker interface {
	// HandleJobMetrics processes task-related events to update job metrics.
	// It maintains both task status and aggregated job metrics in memory.
	HandleJobMetrics(ctx context.Context, evt events.EventEnvelope) error

	// FlushMetrics persists the current state of job metrics to the backing store.
	// This is typically called periodically to ensure durability of metrics.
	FlushMetrics(ctx context.Context) error
}

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

// jobMetricsTracker implements JobMetricsTracker with in-memory state and periodic persistence.
type jobMetricsTracker struct {
	metrics    map[uuid.UUID]*domain.JobMetrics // Job ID -> Metrics
	taskStatus map[uuid.UUID]taskStatusEntry    // Task ID -> Status
	repository MetricsRepository                // Adapter to underlying job and task repositories
	logger     *logger.Logger
	tracer     trace.Tracer

	// Configuration.

	// cleanupInterval is how often we look for completed/failed tasks to clean up.
	cleanupInterval time.Duration
	// retentionPeriod is how long we retain task statuses after completion/failure.
	retentionPeriod time.Duration
}

// NewJobMetricsTracker creates a new JobMetricsTracker with the provided dependencies
// and configuration. It starts background cleanup of completed task statuses.
func NewJobMetricsTracker(
	repository MetricsRepository,
	logger *logger.Logger,
	tracer trace.Tracer,
) *jobMetricsTracker {
	const (
		defaultCleanupInterval = 15 * time.Minute
		defaultRetentionPeriod = 1 * time.Hour
	)

	t := &jobMetricsTracker{
		metrics:         make(map[uuid.UUID]*domain.JobMetrics),
		taskStatus:      make(map[uuid.UUID]taskStatusEntry),
		repository:      repository,
		logger:          logger,
		tracer:          tracer,
		cleanupInterval: defaultCleanupInterval,
		retentionPeriod: defaultRetentionPeriod,
	}

	// Start background cleanup.
	go t.startStatusCleanup(context.Background())

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

	var jobID uuid.UUID
	var taskID uuid.UUID
	var newStatus domain.TaskStatus

	switch e := evt.Payload.(type) {
	case scanning.TaskStartedEvent:
		jobID = e.JobID
		taskID = e.TaskID
		newStatus = domain.TaskStatusInProgress
		span.SetAttributes(
			attribute.String("event_type", "task_started"),
			attribute.String("job_id", jobID.String()),
			attribute.String("task_id", taskID.String()),
		)

	case scanning.TaskCompletedEvent:
		jobID = e.JobID
		taskID = e.TaskID
		newStatus = domain.TaskStatusCompleted
		span.SetAttributes(
			attribute.String("event_type", "task_completed"),
			attribute.String("job_id", jobID.String()),
			attribute.String("task_id", taskID.String()),
		)

	case scanning.TaskFailedEvent:
		jobID = e.JobID
		taskID = e.TaskID
		newStatus = domain.TaskStatusFailed
		span.SetAttributes(
			attribute.String("event_type", "task_failed"),
			attribute.String("job_id", jobID.String()),
			attribute.String("task_id", taskID.String()),
		)

	case scanning.TaskStaleEvent:
		jobID = e.JobID
		taskID = e.TaskID
		newStatus = domain.TaskStatusStale
		span.SetAttributes(
			attribute.String("event_type", "task_stale"),
			attribute.String("job_id", jobID.String()),
			attribute.String("task_id", taskID.String()),
		)

	default:
		// Not a task status event we care about.
		t.logger.Debug(ctx, "ignoring event", "event_type", fmt.Sprintf("%T", e))
		return nil
	}

	var oldStatus domain.TaskStatus

	oldStatus, err := t.getTaskStatus(ctx, taskID)
	if err != nil {
		return fmt.Errorf("getting task status: %w", err)
	}

	metrics, exists := t.metrics[jobID]
	if !exists {
		var err error
		metrics, err = t.repository.GetJobMetrics(ctx, jobID)
		if err != nil {
			if !errors.Is(err, domain.ErrNoJobMetricsFound) {
				return fmt.Errorf("getting job metrics: %w", err)
			}
			metrics = domain.NewJobMetrics()
		}
	}

	if oldStatus == "" {
		t.logger.Info(ctx, "treating as new task",
			"task_id", taskID.String(),
			"new_status", newStatus,
		)
		metrics.OnTaskAdded(newStatus)
	} else {
		metrics.OnTaskStatusChanged(oldStatus, newStatus)
	}

	t.taskStatus[taskID] = taskStatusEntry{
		status:    newStatus,
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
		return "", fmt.Errorf("getting task status: %w", err)
	}

	t.taskStatus[taskID] = taskStatusEntry{
		status:    status,
		updatedAt: time.Now(),
	}
	return status, nil
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

// StartMetricsFlush starts periodic flushing of metrics to storage.
func StartMetricsFlush(ctx context.Context, tracker JobMetricsTracker, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Ensure final flush on shutdown.
			_ = tracker.FlushMetrics(context.Background())
			return
		case <-ticker.C:
			if err := tracker.FlushMetrics(ctx); err != nil {
				// Error handling done within FlushMetrics.
				continue
			}
		}
	}
}
