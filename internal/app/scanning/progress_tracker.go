package scanning

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

// ProgressTracker coordinates task and job progress monitoring across the system.
// It provides a unified interface for tracking scan execution, enabling real-time
// status updates and progress reporting for both individual tasks and overall jobs.
type ProgressTracker interface {
	// StartTracking begins monitoring a task's progress and notifies the job service.
	// This establishes initial tracking state and ensures proper job status transitions.
	StartTracking(ctx context.Context, evt scanning.TaskStartedEvent) error

	// UpdateProgress processes incoming progress events from running tasks.
	// This maintains up-to-date execution state and enables progress monitoring.
	UpdateProgress(ctx context.Context, evt scanning.TaskProgressedEvent) error

	// StopTracking finalizes monitoring for a completed task.
	// This ensures proper cleanup and job status updates when tasks finish.
	StopTracking(ctx context.Context, evt scanning.TaskCompletedEvent) error

	// GetJobProgress retrieves aggregated progress metrics for an entire job.
	// This provides a high-level view of overall job execution status.
	GetJobProgress(ctx context.Context, jobID uuid.UUID) (*scanning.Progress, error)

	// GetTaskProgress retrieves detailed progress metrics for a specific task.
	// This enables granular monitoring of individual scan operations.
	GetTaskProgress(ctx context.Context, taskID uuid.UUID) (*scanning.Progress, error)
}

// progressTracker implements ProgressTracker by coordinating between task and job services
// to maintain consistent progress state across the system.
type progressTracker struct {
	taskService ScanTaskService
	jobService  ScanJobService
	logger      *logger.Logger
	tracer      trace.Tracer
}

// NewProgressTracker creates a new progress tracker with the provided dependencies.
// It establishes the core components needed for system-wide progress monitoring.
func NewProgressTracker(
	taskService ScanTaskService,
	jobService ScanJobService,
	logger *logger.Logger,
	tracer trace.Tracer,
) ProgressTracker {
	return &progressTracker{
		taskService: taskService,
		jobService:  jobService,
		logger:      logger,
		tracer:      tracer,
	}
}

func (t *progressTracker) StartTracking(ctx context.Context, evt scanning.TaskStartedEvent) error {
	taskID, jobID := evt.TaskID, evt.JobID
	ctx, span := t.tracer.Start(ctx, "progress_tracker.scanning.start_tracking",
		trace.WithAttributes(
			attribute.String("task_id", taskID.String()),
			attribute.String("job_id", jobID.String()),
		))
	defer span.End()

	// Initialize task tracking state before notifying job service.
	task, err := t.taskService.StartTask(ctx, jobID, taskID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to start task tracking")
		return fmt.Errorf("failed to start task tracking: %w", err)
	}
	span.AddEvent("task_started")

	if err := t.jobService.OnTaskStarted(ctx, jobID, task); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to notify job service of task start")
		return fmt.Errorf("failed to notify job service of task start: %w", err)
	}
	span.AddEvent("job_service_notified")
	span.SetStatus(codes.Ok, "tracking started")

	return nil
}

func (t *progressTracker) StopTracking(ctx context.Context, evt scanning.TaskCompletedEvent) error {
	return nil
}

func (t *progressTracker) UpdateProgress(ctx context.Context, evt scanning.TaskProgressedEvent) error {
	return nil
}

func (t *progressTracker) GetJobProgress(ctx context.Context, jobID uuid.UUID) (*scanning.Progress, error) {
	return nil, nil
}

func (t *progressTracker) GetTaskProgress(ctx context.Context, taskID uuid.UUID) (*scanning.Progress, error) {
	return nil, nil
}
