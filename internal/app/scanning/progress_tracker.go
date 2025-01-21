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

// TaskProgressTracker primarily coordinates task progress monitoring across the system.
// It provides a unified interface for tracking scan execution, enabling real-time
// status updates and progress reporting for individual tasks. Job status is
// implicitly derived from the status of its associated tasks.
type TaskProgressTracker interface {
	// StartTracking begins monitoring a task's progress and notifies the job service.
	// This establishes initial tracking state and ensures proper job status transitions.
	StartTracking(ctx context.Context, evt scanning.TaskStartedEvent) error

	// UpdateProgress processes incoming progress events from running tasks.
	// This maintains up-to-date execution state and enables progress monitoring.
	UpdateProgress(ctx context.Context, evt scanning.TaskProgressedEvent) error

	// StopTracking finalizes monitoring for a completed task.
	// This ensures proper cleanup and job status updates when tasks finish.
	StopTracking(ctx context.Context, evt scanning.TaskCompletedEvent) error

	// FailTask marks a task as failed and notifies the job service.
	FailTask(ctx context.Context, evt scanning.TaskFailedEvent) error

	// GetJobProgress retrieves aggregated progress metrics for an entire job.
	// This provides a high-level view of overall job execution status.
	//
	// Deprecated:  Job progress should ideally be retrieved from the JobService
	// directly, as this TaskProgressTracker is primarily concerned with task-level
	// progress. This method will be removed in a future release.
	GetJobProgress(ctx context.Context, jobID uuid.UUID) (*scanning.Progress, error)

	// GetTaskProgress retrieves detailed progress metrics for a specific task.
	// This enables granular monitoring of individual scan operations.
	GetTaskProgress(ctx context.Context, taskID uuid.UUID) (*scanning.Progress, error)
}

// taskProgressTracker implements ProgressTracker by coordinating between task and job services
// to maintain consistent progress state across the system.
type taskProgressTracker struct {
	taskService ScanTaskService
	jobService  ScanJobService
	logger      *logger.Logger
	tracer      trace.Tracer
}

// NewTaskProgressTracker creates a new progress tracker with the provided dependencies.
// It establishes the core components needed for system-wide progress monitoring.
func NewTaskProgressTracker(
	taskService ScanTaskService,
	jobService ScanJobService,
	logger *logger.Logger,
	tracer trace.Tracer,
) TaskProgressTracker {
	return &taskProgressTracker{
		taskService: taskService,
		jobService:  jobService,
		logger:      logger,
		tracer:      tracer,
	}
}

// StartTracking begins monitoring a new scan task and coordinates its initialization
// across the system. It first establishes task-level tracking state and then notifies
// the job service to ensure proper job status transitions. This two-phase initialization
// helps maintain consistency between task and job state.
func (t *taskProgressTracker) StartTracking(ctx context.Context, evt scanning.TaskStartedEvent) error {
	taskID, jobID := evt.TaskID, evt.JobID
	ctx, span := t.tracer.Start(ctx, "progress_tracker.scanning.start_tracking",
		trace.WithAttributes(
			attribute.String("task_id", taskID.String()),
			attribute.String("job_id", jobID.String()),
		))
	defer span.End()

	// Task state must be initialized before job notification to ensure proper ordering.
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

// UpdateProgress processes a task progress event by updating both task and job state.
// It maintains system-wide consistency by first updating the task's progress metrics,
// then notifying the job service to update aggregated job statistics. This ordering
// ensures that job-level metrics accurately reflect the latest task state.
func (t *taskProgressTracker) UpdateProgress(ctx context.Context, evt scanning.TaskProgressedEvent) error {
	taskID := evt.Progress.TaskID()
	ctx, span := t.tracer.Start(ctx, "progress_tracker.scanning.update_progress",
		trace.WithAttributes(
			attribute.String("task_id", taskID.String()),
		))
	defer span.End()

	// Update task state first to maintain causal ordering.
	task, err := t.taskService.UpdateProgress(ctx, evt.Progress)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to update task progress")
		return fmt.Errorf("failed to update task progress: %w", err)
	}

	if task != nil {
		// Notify the job service of the current task's progress. This step is crucial
		// as it enables the job service to accurately track the completion status of
		// all tasks associated with the job, which is essential for updating the
		// overall job status accordingly.
		if err := t.jobService.OnTaskUpdated(ctx, task.JobID(), task); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "failed to notify job service of task progress")
			return fmt.Errorf("failed to notify job service of task progress: %w", err)
		}
	}
	span.AddEvent("task_progress_updated")

	return nil
}

// StopTracking marks a task as successfully completed and updates the associated job's state.
// This is called when a task has finished its work normally and needs to be finalized in the system.
func (t *taskProgressTracker) StopTracking(ctx context.Context, evt scanning.TaskCompletedEvent) error {
	taskID := evt.TaskID
	ctx, span := t.tracer.Start(ctx, "progress_tracker.scanning.stop_tracking",
		trace.WithAttributes(
			attribute.String("task_id", taskID.String()),
		))
	defer span.End()

	task, err := t.taskService.CompleteTask(ctx, taskID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to complete task")
		return fmt.Errorf("failed to complete task: %w", err)
	}

	if err := t.jobService.OnTaskUpdated(ctx, task.JobID(), task); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to notify job service of task completion")
		return fmt.Errorf("failed to notify job service of task completion: %w", err)
	}
	span.AddEvent("task_completed")
	span.SetStatus(codes.Ok, "task tracking stopped")

	return nil
}

// FailTask marks a task as failed and updates the associated job accordingly.
// This is called when a task encounters an unrecoverable error and cannot complete normally.
func (t *taskProgressTracker) FailTask(ctx context.Context, evt scanning.TaskFailedEvent) error {
	taskID := evt.TaskID
	ctx, span := t.tracer.Start(ctx, "progress_tracker.scanning.fail_task",
		trace.WithAttributes(
			attribute.String("task_id", taskID.String()),
		))
	defer span.End()

	task, err := t.taskService.FailTask(ctx, taskID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to fail task")
		return fmt.Errorf("failed to fail task: %w", err)
	}

	if err := t.jobService.OnTaskUpdated(ctx, task.JobID(), task); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to notify job service of task failure")
		return fmt.Errorf("failed to notify job service of task failure: %w", err)
	}
	span.AddEvent("task_failed")
	span.SetStatus(codes.Ok, "task failed")

	return nil
}

func (t *taskProgressTracker) GetJobProgress(ctx context.Context, jobID uuid.UUID) (*scanning.Progress, error) {
	return nil, nil
}

func (t *taskProgressTracker) GetTaskProgress(ctx context.Context, taskID uuid.UUID) (*scanning.Progress, error) {
	return nil, nil
}
