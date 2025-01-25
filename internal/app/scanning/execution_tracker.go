package scanning

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

// ExecutionTracker manages the lifecycle and progress monitoring of scanning tasks within jobs.
// It acts as a coordinator between the scanning workers and the job service, ensuring task
// state transitions are properly tracked and job status is accurately maintained. The tracker
// processes domain events related to task execution (start, progress, completion, failure) and
// maintains real-time progress metrics that can be queried at both the task and job level.
type ExecutionTracker interface {
	// StartTracking initializes tracking for a new task by registering it with the job service
	// and setting up initial progress metrics. If this is the first task in a job, it will
	// transition the job from QUEUED to RUNNING status.
	StartTracking(ctx context.Context, evt scanning.TaskStartedEvent) error

	// UpdateProgress handles task progress events during scanning, updating metrics like
	// items processed, processing rate, and error counts. This data is used to detect
	// stalled tasks and calculate overall job progress.
	UpdateProgress(ctx context.Context, evt scanning.TaskProgressedEvent) error

	// StopTracking handles successful task completion by updating job metrics,
	// transitioning task status to COMPLETED, and potentially marking the job
	// as COMPLETED if all tasks are done.
	StopTracking(ctx context.Context, evt scanning.TaskCompletedEvent) error

	// MarkTaskFailure handles task failure scenarios by transitioning the task to FAILED status
	// and updating job metrics. If all tasks in a job fail, the job will be marked as FAILED.
	MarkTaskFailure(ctx context.Context, evt scanning.TaskFailedEvent) error

	// MarkTaskStale marks a task as stale, indicating it has stopped reporting progress.
	MarkTaskStale(ctx context.Context, evt scanning.TaskStaleEvent) error

	// GetJobProgress returns consolidated metrics for all tasks in a job, including
	// total tasks, completed tasks, failed tasks, and overall progress percentage.
	// This provides the data needed for job-level monitoring and reporting.
	GetJobProgress(ctx context.Context, jobID uuid.UUID) (*scanning.Progress, error)

	// GetTaskProgress returns detailed execution metrics for a specific task,
	// including items processed, processing rate, error counts, and duration.
	// This enables fine-grained monitoring of individual scanning operations.
	GetTaskProgress(ctx context.Context, taskID uuid.UUID) (*scanning.Progress, error)
}

// executionTracker coordinates task lifecycle events between the job service
// and progress tracking subsystems.
// It ensures consistent state transitions and maintains accurate progress metrics
// across the distributed system.
type executionTracker struct {
	jobService      ScanJobCoordinator // Manages job and task state transitions
	domainPublisher events.DomainEventPublisher
	logger          *logger.Logger // Structured logging for operational visibility
	tracer          trace.Tracer   // OpenTelemetry tracing for request flows
}

// NewExecutionTracker constructs a new ExecutionTracker with required dependencies.
// The jobService handles state persistence and transitions, while logger and tracer
// provide operational visibility into the progress tracking subsystem.
func NewExecutionTracker(
	jobService ScanJobCoordinator,
	domainPublisher events.DomainEventPublisher,
	logger *logger.Logger,
	tracer trace.Tracer,
) ExecutionTracker {
	return &executionTracker{
		jobService:      jobService,
		domainPublisher: domainPublisher,
		logger:          logger,
		tracer:          tracer,
	}
}

// StartTracking initializes progress tracking for a new scan task. It coordinates with
// the job service to:
// 1. Register the task in the job's task collection
// 2. Transition the job to RUNNING state if this is the first task
// 3. Initialize progress metrics for the task
// The operation is traced to maintain visibility into task startup sequences.
func (t *executionTracker) StartTracking(ctx context.Context, evt scanning.TaskStartedEvent) error {
	taskID, jobID, resourceURI := evt.TaskID, evt.JobID, evt.ResourceURI
	ctx, span := t.tracer.Start(ctx, "progress_tracker.scanning.start_tracking",
		trace.WithAttributes(
			attribute.String("task_id", taskID.String()),
			attribute.String("job_id", jobID.String()),
			attribute.String("resource_uri", resourceURI),
		))
	defer span.End()

	// Initialize task state in job aggregate before any other operations
	_, err := t.jobService.StartTask(ctx, jobID, taskID, resourceURI)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to start task tracking")
		return fmt.Errorf("failed to start task tracking: %w", err)
	}
	span.AddEvent("task_started")
	span.SetStatus(codes.Ok, "tracking started")

	return nil
}

// UpdateProgress processes incremental task progress events by:
// 1. Validating the progress metrics
// 2. Updating task-level progress state
// 3. Recalculating aggregated job progress
// This maintains accurate, real-time visibility into scan execution across the system.
func (t *executionTracker) UpdateProgress(ctx context.Context, evt scanning.TaskProgressedEvent) error {
	taskID := evt.Progress.TaskID()
	ctx, span := t.tracer.Start(ctx, "progress_tracker.scanning.update_progress",
		trace.WithAttributes(
			attribute.String("task_id", taskID.String()),
		))
	defer span.End()

	_, err := t.jobService.UpdateTaskProgress(ctx, evt.Progress)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to update task progress")
		return fmt.Errorf("failed to update task progress: %w", err)
	}
	span.AddEvent("task_progress_updated")
	span.SetStatus(codes.Ok, "task progress updated")

	return nil
}

// StopTracking handles normal task completion by:
// 1. Marking the task as COMPLETED in the job aggregate
// 2. Updating job status if all tasks are now complete
// 3. Recording final task metrics
// This ensures proper cleanup and maintains accurate job state.
func (t *executionTracker) StopTracking(ctx context.Context, evt scanning.TaskCompletedEvent) error {
	taskID := evt.TaskID
	ctx, span := t.tracer.Start(ctx, "progress_tracker.scanning.stop_tracking",
		trace.WithAttributes(
			attribute.String("task_id", taskID.String()),
		))
	defer span.End()

	_, err := t.jobService.CompleteTask(ctx, evt.JobID, evt.TaskID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to complete task")
		return fmt.Errorf("failed to complete task: %w", err)
	}
	span.AddEvent("task_completed")
	span.SetStatus(codes.Ok, "task tracking stopped")

	return nil
}

// MarkTaskFailure handles task failure scenarios by:
// 1. Marking the task as FAILED in the job aggregate
// 2. Potentially triggering job-level failure if configured
// 3. Recording error details and final metrics
// This ensures proper error handling and maintains system consistency during failures.
func (t *executionTracker) MarkTaskFailure(ctx context.Context, evt scanning.TaskFailedEvent) error {
	taskID := evt.TaskID
	ctx, span := t.tracer.Start(ctx, "progress_tracker.scanning.fail_task",
		trace.WithAttributes(
			attribute.String("task_id", taskID.String()),
		))
	defer span.End()

	_, err := t.jobService.FailTask(ctx, evt.JobID, evt.TaskID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to fail task")
		return fmt.Errorf("failed to fail task: %w", err)
	}
	span.AddEvent("task_failed_successfully")
	span.SetStatus(codes.Ok, "task failed")

	return nil
}

// MarkTaskStale handles task staleness by:
// 1. Marking the task as STALE in the job aggregate
// 2. Publishing a domain event to notify other components
// 3. Recording the event for system observability
func (et *executionTracker) MarkTaskStale(ctx context.Context, evt scanning.TaskStaleEvent) error {
	ctx, span := et.tracer.Start(ctx, "executionTracker.markTaskStale",
		trace.WithAttributes(
			attribute.String("task_id", evt.TaskID.String()),
			attribute.String("job_id", evt.JobID.String()),
			attribute.String("reason", string(evt.Reason)),
			attribute.String("stalled_since", evt.StalledSince.String()),
		))
	defer span.End()

	task, err := et.jobService.MarkTaskStale(ctx, evt.JobID, evt.TaskID, evt.Reason)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to mark task as stale")
		return err
	}

	resumeTask := scanning.NewTaskResumeEvent(
		task.JobID(),
		task.TaskID(),
		task.ResourceURI(),
		int(task.LastSequenceNum()),
		task.LastCheckpoint(),
	)
	if err := et.domainPublisher.PublishDomainEvent(ctx, resumeTask); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to publish task resume event")
		return err
	}
	span.AddEvent("task_marked_stale_and_resume_task_event_published")
	span.SetStatus(codes.Ok, "task marked stale and resume task event published")

	return nil
}

func (t *executionTracker) GetJobProgress(ctx context.Context, jobID uuid.UUID) (*scanning.Progress, error) {
	return nil, nil
}

func (t *executionTracker) GetTaskProgress(ctx context.Context, taskID uuid.UUID) (*scanning.Progress, error) {
	return nil, nil
}
