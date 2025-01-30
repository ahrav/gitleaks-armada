package scanning

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	domain "github.com/ahrav/gitleaks-armada/internal/domain/scanning"
)

// ErrInvalidMetrics indicates the provided metrics are invalid.
var ErrInvalidMetrics = errors.New("invalid metrics")

var _ domain.MetricsRepository = (*metricsRepositoryAdapter)(nil)

// metricsRepositoryAdapter adapts existing job and task repositories to implement
// the MetricsRepository interface.
type metricsRepositoryAdapter struct {
	jobRepo  domain.JobRepository
	taskRepo domain.TaskRepository
}

// NewMetricsRepositoryAdapter creates a new MetricsRepository implementation that wraps
// existing job and task repositories.
func NewMetricsRepositoryAdapter(
	jobRepo domain.JobRepository,
	taskRepo domain.TaskRepository,
) *metricsRepositoryAdapter {
	return &metricsRepositoryAdapter{jobRepo: jobRepo, taskRepo: taskRepo}
}

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
			return "", fmt.Errorf("getting task: %w", domain.ErrTaskNotFound)
		}
		return "", fmt.Errorf("getting task: %w", err)
	}

	return task.Status(), nil
}
