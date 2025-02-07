package scanning

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	domain "github.com/ahrav/gitleaks-armada/internal/domain/scanning"
)

// ErrInvalidMetrics indicates the provided metrics are invalid.
var ErrInvalidMetrics = errors.New("invalid metrics")

var _ domain.MetricsRepository = (*metricsRepositoryAdapter)(nil)

// metricsRepositoryAdapter adapts existing job and task repositories to implement
// the MetricsRepository interface.
// TODO: BulkUpdateMetricsAndCheckpoint.
type metricsRepositoryAdapter struct {
	controllerID string

	jobRepo  domain.JobRepository
	taskRepo domain.TaskRepository

	tracer trace.Tracer
}

// NewMetricsRepositoryAdapter creates a new MetricsRepository implementation that wraps
// existing job and task repositories.
func NewMetricsRepositoryAdapter(
	controllerID string,
	jobRepo domain.JobRepository,
	taskRepo domain.TaskRepository,
	tracer trace.Tracer,
) *metricsRepositoryAdapter {
	return &metricsRepositoryAdapter{
		controllerID: controllerID,
		jobRepo:      jobRepo,
		taskRepo:     taskRepo,
		tracer:       tracer,
	}
}

// GetJobMetrics implements MetricsRepository.GetJobMetrics by retrieving metrics
// from the underlying job repository.
func (r *metricsRepositoryAdapter) GetJobMetrics(ctx context.Context, jobID uuid.UUID) (*domain.JobMetrics, error) {
	ctx, span := r.tracer.Start(ctx, "metrics_repository.get_job_metrics")
	defer span.End()

	span.SetAttributes(
		attribute.String("controller_id", r.controllerID),
		attribute.String("job_id", jobID.String()),
	)

	if jobID == uuid.Nil {
		err := fmt.Errorf("%w: nil job ID provided", ErrInvalidMetrics)
		span.RecordError(err)
		span.SetStatus(codes.Error, "invalid job ID")
		return nil, err
	}

	metrics, err := r.jobRepo.GetJobMetrics(ctx, jobID)
	if err != nil {
		if errors.Is(err, domain.ErrNoJobMetricsFound) {
			span.SetStatus(codes.Error, "no metrics found")
			return nil, fmt.Errorf("no metrics found for job %s: %w", jobID, domain.ErrNoJobMetricsFound)
		}
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to get job metrics")
		return nil, fmt.Errorf("failed to retrieve metrics for job %s: %w", jobID, err)
	}

	span.SetStatus(codes.Ok, "job metrics retrieved")
	return metrics, nil
}

// UpdateJobMetrics updates metrics for a specific job, ensuring atomic updates and
// proper validation.
func (r *metricsRepositoryAdapter) UpdateJobMetrics(
	ctx context.Context,
	jobID uuid.UUID,
	metrics *domain.JobMetrics,
) error {
	ctx, span := r.tracer.Start(ctx, "metrics_repository.update_job_metrics",
		trace.WithAttributes(
			attribute.String("job_id", jobID.String()),
			attribute.String("controller_id", r.controllerID),
		),
	)
	defer span.End()

	if err := r.validateJobMetricsUpdate(jobID, metrics); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "validation failed")
		return err
	}

	_, err := r.jobRepo.BulkUpdateJobMetrics(ctx, map[uuid.UUID]*domain.JobMetrics{
		jobID: metrics,
	})
	if err != nil {
		if errors.Is(err, domain.ErrNoJobMetricsUpdated) {
			span.SetStatus(codes.Error, "no metrics updated")
			return fmt.Errorf("no metrics updated for job %s: %w", jobID, domain.ErrNoJobMetricsUpdated)
		}
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to update job metrics")
		return fmt.Errorf("failed to update metrics for job %s: %w", jobID, err)
	}

	span.SetStatus(codes.Ok, "job metrics updated")
	return nil
}

// validateJobMetricsUpdate performs validation for job metrics updates.
func (r *metricsRepositoryAdapter) validateJobMetricsUpdate(jobID uuid.UUID, metrics *domain.JobMetrics) error {
	if jobID == uuid.Nil {
		return fmt.Errorf("%w: nil job ID provided", ErrInvalidMetrics)
	}
	if metrics == nil {
		return fmt.Errorf("%w: nil metrics provided", ErrInvalidMetrics)
	}
	// Add additional validation as needed
	// if !metrics.IsValid() {
	//     return fmt.Errorf("%w: metrics validation failed", ErrInvalidMetrics)
	// }
	return nil
}

// GetTask retrieves a specific task.
func (r *metricsRepositoryAdapter) GetTask(ctx context.Context, taskID uuid.UUID) (*domain.Task, error) {
	ctx, span := r.tracer.Start(ctx, "metrics_repository.get_task",
		trace.WithAttributes(
			attribute.String("task_id", taskID.String()),
			attribute.String("controller_id", r.controllerID),
		),
	)
	defer span.End()

	if taskID == uuid.Nil {
		err := fmt.Errorf("%w: nil task ID provided", domain.ErrTaskNotFound)
		span.RecordError(err)
		span.SetStatus(codes.Error, "invalid task ID")
		return nil, err
	}

	task, err := r.taskRepo.GetTask(ctx, taskID)
	if err != nil {
		if errors.Is(err, domain.ErrTaskNotFound) {
			span.SetStatus(codes.Error, "task not found")
			return nil, fmt.Errorf("task %s not found: %w", taskID, err)
		}
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to get task")
		return nil, fmt.Errorf("failed to retrieve task %s: %w", taskID, err)
	}

	span.SetStatus(codes.Ok, "task retrieved")
	return task, nil
}

// GetCheckpoints retrieves checkpoints for a specific job.
func (r *metricsRepositoryAdapter) GetCheckpoints(ctx context.Context, jobID uuid.UUID) (map[int32]int64, error) {
	ctx, span := r.tracer.Start(ctx, "metrics_repository.get_checkpoints",
		trace.WithAttributes(
			attribute.String("job_id", jobID.String()),
			attribute.String("controller_id", r.controllerID),
		),
	)
	defer span.End()

	if jobID == uuid.Nil {
		err := fmt.Errorf("%w: nil job ID provided", ErrInvalidMetrics)
		span.RecordError(err)
		span.SetStatus(codes.Error, "invalid job ID")
		return nil, err
	}

	checkpoints, err := r.jobRepo.GetCheckpoints(ctx, jobID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to get checkpoints")
		return nil, fmt.Errorf("failed to retrieve checkpoints for job %s: %w", jobID, err)
	}

	span.SetStatus(codes.Ok, "checkpoints retrieved")
	return checkpoints, nil
}

// UpdateMetricsAndCheckpoint updates both metrics and checkpoint information atomically.
func (r *metricsRepositoryAdapter) UpdateMetricsAndCheckpoint(
	ctx context.Context,
	jobID uuid.UUID,
	metrics *domain.JobMetrics,
	partitionID int32,
	offset int64,
) error {
	ctx, span := r.tracer.Start(ctx, "metrics_repository.update_metrics_and_checkpoint",
		trace.WithAttributes(
			attribute.String("job_id", jobID.String()),
			attribute.String("controller_id", r.controllerID),
			attribute.Int("partition_id", int(partitionID)),
			attribute.Int64("offset", offset),
		),
	)
	defer span.End()

	if err := r.validateJobMetricsUpdate(jobID, metrics); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "validation failed")
		return err
	}

	if err := r.jobRepo.UpdateMetricsAndCheckpoint(ctx, jobID, metrics, partitionID, offset); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to update metrics and checkpoint")
		return fmt.Errorf("failed to update metrics and checkpoint for job %s (partition: %d, offset: %d): %w",
			jobID, partitionID, offset, err)
	}

	span.SetStatus(codes.Ok, "metrics and checkpoint updated")
	return nil
}
