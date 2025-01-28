package scanning

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	domain "github.com/ahrav/gitleaks-armada/internal/domain/scanning"
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

	job, err := r.jobRepo.GetJob(ctx, jobID)
	if err != nil {
		if errors.Is(err, domain.ErrJobNotFound) {
			return nil, fmt.Errorf("getting job metrics: %w", domain.ErrJobNotFound)
		}
		return nil, fmt.Errorf("getting job metrics: %w", err)
	}

	metrics := job.Metrics()
	if metrics == nil {
		return nil, fmt.Errorf("%w: nil metrics for job %s", ErrInvalidMetrics, jobID)
	}

	return metrics, nil
}

// UpdateJobMetrics implements MetricsRepository.UpdateJobMetrics by delegating to
// the underlying job repository. The update is expected to be atomic to prevent
// race conditions in concurrent updates.
func (r *metricsRepositoryAdapter) UpdateJobMetrics(ctx context.Context, jobID uuid.UUID, metrics *domain.JobMetrics) error {
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
