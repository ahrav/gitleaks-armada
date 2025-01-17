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

// ProgressTracker provides a unified interface for progress tracking across the system
type ProgressTracker interface {
	// StartTracking begins monitoring a task's progress.
	StartTracking(ctx context.Context, evt scanning.TaskStartedEvent) error

	// UpdateProgress handles incoming progress events.
	UpdateProgress(ctx context.Context, evt scanning.TaskProgressedEvent) error

	// StopTracking ends monitoring for a task.
	StopTracking(ctx context.Context, evt scanning.TaskCompletedEvent) error

	// GetJobProgress retrieves current job progress.
	GetJobProgress(ctx context.Context, jobID uuid.UUID) (*scanning.Progress, error)

	// GetTaskProgress retrieves current task progress.
	GetTaskProgress(ctx context.Context, taskID uuid.UUID) (*scanning.Progress, error)
}

type progressTracker struct {
	taskService ScanTaskService
	jobService  ScanJobService
	logger      *logger.Logger
	tracer      trace.Tracer
}

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
