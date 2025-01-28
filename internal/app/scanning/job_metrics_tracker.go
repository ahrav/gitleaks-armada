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
func NewMetricsRepository(jobRepo domain.JobRepository, taskRepo domain.TaskRepository) (MetricsRepository, error) {
	if jobRepo == nil {
		return nil, errors.New("job repository is required")
	}
	if taskRepo == nil {
		return nil, errors.New("task repository is required")
	}

	return &metricsRepositoryAdapter{
		jobRepo:  jobRepo,
		taskRepo: taskRepo,
	}, nil
}

// ErrInvalidMetrics indicates the provided metrics are invalid
var ErrInvalidMetrics = errors.New("invalid metrics")

// GetJobMetrics implements MetricsRepository.GetJobMetrics by retrieving metrics
// from the underlying job repository. It could be optimized in the future to only
// fetch metrics-related fields from the database.
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

	// GetJobMetrics returns the current metrics for a specific job.
	// Returns ErrNoJobMetricsFound if the job doesn't exist in memory or storage.
	GetJobMetrics(ctx context.Context, jobID uuid.UUID) (*domain.JobMetrics, error)
}

type taskStatusEntry struct {
	status    domain.TaskStatus
	updatedAt time.Time
}

// jobMetricsTracker implements JobMetricsTracker with in-memory state and periodic persistence.
type jobMetricsTracker struct {
	metrics    map[uuid.UUID]*domain.JobMetrics // Job ID -> Metrics
	taskStatus map[uuid.UUID]taskStatusEntry    // Task ID -> Status
	repository MetricsRepository                // Using the provided adapter interface
	logger     *logger.Logger
	tracer     trace.Tracer

	// Protects access to metrics and taskStatus maps
	mu sync.RWMutex

	// Configuration
	cleanupInterval time.Duration
	retentionPeriod time.Duration
}

// Config holds configuration options for the JobMetricsTracker.
type Config struct {
	// How often to clean up completed/failed task status entries.
	CleanupInterval time.Duration

	// How long to retain task status after completion/failure.
	RetentionPeriod time.Duration
}

// DefaultConfig provides sensible defaults for JobMetricsTracker configuration.
func DefaultConfig() Config {
	return Config{
		CleanupInterval: 1 * time.Hour,
		RetentionPeriod: 24 * time.Hour,
	}
}

// NewJobMetricsTracker creates a new JobMetricsTracker with the provided dependencies
// and configuration. It starts background cleanup of completed task statuses.
func NewJobMetricsTracker(
	repository MetricsRepository,
	logger *logger.Logger,
	tracer trace.Tracer,
	cfg Config,
) (JobMetricsTracker, error) {
	// if repository == nil {
	// 	return nil, fmt.Errorf("%w: nil repository", domain.ErrInvalidInput)
	// }
	// if logger == nil {
	// 	return nil, fmt.Errorf("%w: nil logger", domain.ErrInvalidInput)
	// }
	// if tracer == nil {
	// 	return nil, fmt.Errorf("%w: nil tracer", domain.ErrInvalidInput)
	// }

	t := &jobMetricsTracker{
		metrics:         make(map[uuid.UUID]*domain.JobMetrics),
		taskStatus:      make(map[uuid.UUID]taskStatusEntry),
		repository:      repository,
		logger:          logger,
		tracer:          tracer,
		cleanupInterval: cfg.CleanupInterval,
		retentionPeriod: cfg.RetentionPeriod,
	}

	// Start background cleanup.
	go t.startStatusCleanup(context.Background())

	return t, nil
}

func (t *jobMetricsTracker) HandleJobMetrics(ctx context.Context, evt events.EventEnvelope) error {
	ctx, span := t.tracer.Start(ctx, "job_metrics_tracker.handle_job_metrics")
	defer span.End()

	var jobID uuid.UUID
	var taskID uuid.UUID
	var newStatus domain.TaskStatus

	// Extract event details based on type
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

	t.mu.Lock()
	defer t.mu.Unlock()

	metrics, exists := t.metrics[jobID]
	if !exists {
		var err error
		metrics, err = t.repository.GetJobMetrics(ctx, jobID)
		if err != nil {
			if errors.Is(err, domain.ErrNoJobMetricsFound) {
				metrics = domain.NewJobMetrics()
				t.metrics[jobID] = metrics
			} else {
				return fmt.Errorf("getting job metrics: %w", err)
			}
		}
		t.metrics[jobID] = metrics
	}

	// Get previous task status if it exists.
	oldStatus, err := t.getTaskStatusLocked(ctx, taskID)
	if err != nil {
		if !errors.Is(err, domain.ErrTaskNotFound) {
			t.logger.Error(ctx, "failed to get task status",
				"task_id", taskID.String(),
				"error", err,
			)
		}
		// Treat as a new task if we can't get the old status
		t.logger.Info(ctx, "treating as new task",
			"task_id", taskID.String(),
			"new_status", newStatus,
		)
		metrics.OnTaskAdded(newStatus)
	} else {
		metrics.OnTaskStatusChanged(oldStatus, newStatus)
	}

	// Update task status.
	t.taskStatus[taskID] = taskStatusEntry{
		status:    newStatus,
		updatedAt: time.Now(),
	}

	return nil
}

func (t *jobMetricsTracker) FlushMetrics(ctx context.Context) error {
	ctx, span := t.tracer.Start(ctx, "job_metrics_tracker.flush_metrics")
	defer span.End()

	t.mu.RLock()
	defer t.mu.RUnlock()

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

func (t *jobMetricsTracker) GetJobMetrics(ctx context.Context, jobID uuid.UUID) (*domain.JobMetrics, error) {
	// if jobID == uuid.Nil {
	// 	return nil, fmt.Errorf("%w: invalid job ID", domain.ErrInvalidInput)
	// }

	t.mu.RLock()
	defer t.mu.RUnlock()

	metrics, exists := t.metrics[jobID]
	if exists {
		return metrics.Clone(), nil
	}

	metrics, err := t.repository.GetJobMetrics(ctx, jobID)
	if err != nil {
		return nil, fmt.Errorf("getting job metrics: %w", err)
	}

	t.metrics[jobID] = metrics
	return metrics.Clone(), nil
}

// getTaskStatusLocked retrieves task status from memory or falls back to repository.
// Caller must hold the mutex lock.
func (t *jobMetricsTracker) getTaskStatusLocked(ctx context.Context, taskID uuid.UUID) (domain.TaskStatus, error) {
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
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	for taskID, entry := range t.taskStatus {
		if entry.status == domain.TaskStatusCompleted || entry.status == domain.TaskStatusFailed {
			// Only remove if it's been in terminal state longer than retention period
			if now.Sub(entry.updatedAt) > t.retentionPeriod {
				delete(t.taskStatus, taskID)
			}
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
