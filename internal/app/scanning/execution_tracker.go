package scanning

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

// executionTracker coordinates task lifecycle events between the job service
// and progress tracking subsystems.
// It ensures consistent state transitions and maintains accurate progress metrics
// across the distributed system.
type executionTracker struct {
	controllerID    string
	jobService      scanning.ScanJobCoordinator // Manages job and task state transitions
	domainPublisher events.DomainEventPublisher
	logger          *logger.Logger // Structured logging for operational visibility
	tracer          trace.Tracer   // OpenTelemetry tracing for request flows
}

// NewExecutionTracker constructs a new ExecutionTracker with required dependencies.
// The jobService handles state persistence and transitions, while logger and tracer
// provide operational visibility into the progress tracking subsystem.
func NewExecutionTracker(
	controllerID string,
	jobService scanning.ScanJobCoordinator,
	domainPublisher events.DomainEventPublisher,
	logger *logger.Logger,
	tracer trace.Tracer,
) *executionTracker {
	logger = logger.With("component", "execution_tracker")
	return &executionTracker{
		controllerID:    controllerID,
		jobService:      jobService,
		domainPublisher: domainPublisher,
		logger:          logger,
		tracer:          tracer,
	}
}

// HandleTaskStart initializes progress tracking for a new scan task. It coordinates with
// the job service to:
// 1. Register the task in the job's task collection
// 2. Transition the job to RUNNING state if this is the first task
// 3. Initialize progress metrics for the task
// The operation is traced to maintain visibility into task startup sequences.
func (t *executionTracker) HandleTaskStart(ctx context.Context, evt scanning.TaskStartedEvent) error {
	taskID, jobID, resourceURI := evt.TaskID, evt.JobID, evt.ResourceURI
	ctx, span := t.tracer.Start(ctx, "execution_tracker.scanning.start_tracking",
		trace.WithAttributes(
			attribute.String("controller_id", t.controllerID),
			attribute.String("task_id", taskID.String()),
			attribute.String("job_id", jobID.String()),
			attribute.String("resource_uri", resourceURI),
		))
	defer span.End()

	// Initialize task state in job aggregate before any other operations.
	_, err := t.jobService.StartTask(ctx, jobID, taskID, resourceURI, t.controllerID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to start task tracking")
		return fmt.Errorf("start task failed (controller_id: %s): %w", t.controllerID, err)
	}
	span.AddEvent("task_started")
	span.SetStatus(codes.Ok, "tracking started")
	t.logger.Info(ctx, "Task started",
		"task_id", taskID,
		"job_id", jobID,
		"resource_uri", resourceURI,
	)

	return nil
}

// HandleTaskProgress processes incremental task progress events by:
// 1. Validating the progress metrics
// 2. Updating task-level progress state
// 3. Recalculating aggregated job progress
// This maintains accurate, real-time visibility into scan execution across the system.
func (t *executionTracker) HandleTaskProgress(ctx context.Context, evt scanning.TaskProgressedEvent) error {
	taskID := evt.Progress.TaskID()
	ctx, span := t.tracer.Start(ctx, "execution_tracker.scanning.update_progress",
		trace.WithAttributes(
			attribute.String("controller_id", t.controllerID),
			attribute.String("task_id", taskID.String()),
		))
	defer span.End()

	_, err := t.jobService.UpdateTaskProgress(ctx, evt.Progress)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to update task progress")
		return fmt.Errorf("update task progress failed (sequence_num: %d): %w",
			evt.Progress.SequenceNum(), err)
	}
	span.AddEvent("task_progress_updated")
	span.SetStatus(codes.Ok, "task progress updated")
	t.logger.Info(ctx, "Task progress updated", "task_id", taskID)

	return nil
}

// HandleTaskCompletion handles normal task completion by:
// 1. Marking the task as COMPLETED in the job aggregate
// 2. Updating job status if all tasks are now complete
// 3. Recording final task metrics
// This ensures proper cleanup and maintains accurate job state.
func (t *executionTracker) HandleTaskCompletion(ctx context.Context, evt scanning.TaskCompletedEvent) error {
	taskID := evt.TaskID
	ctx, span := t.tracer.Start(ctx, "execution_tracker.scanning.stop_tracking",
		trace.WithAttributes(
			attribute.String("controller_id", t.controllerID),
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
	t.logger.Info(ctx, "Task completed", "task_id", taskID, "job_id", evt.JobID)

	return nil
}

// HandleTaskFailure handles task failure scenarios by:
// 1. Marking the task as FAILED in the job aggregate
// 2. Potentially triggering job-level failure if configured
// 3. Recording error details and final metrics
// This ensures proper error handling and maintains system consistency during failures.
func (t *executionTracker) HandleTaskFailure(ctx context.Context, evt scanning.TaskFailedEvent) error {
	taskID := evt.TaskID
	ctx, span := t.tracer.Start(ctx, "execution_tracker.scanning.fail_task",
		trace.WithAttributes(
			attribute.String("controller_id", t.controllerID),
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
	t.logger.Info(ctx, "Task failed", "task_id", taskID, "job_id", evt.JobID)

	return nil
}

// HandleTaskStale handles task staleness by:
// 1. Marking the task as STALE in the job aggregate
// 2. Publishing a domain event to notify other components
// 3. Recording the event for system observability
func (t *executionTracker) HandleTaskStale(ctx context.Context, evt scanning.TaskStaleEvent) error {
	ctx, span := t.tracer.Start(ctx, "execution_tracker.markTaskStale",
		trace.WithAttributes(
			attribute.String("controller_id", t.controllerID),
			attribute.String("task_id", evt.TaskID.String()),
			attribute.String("job_id", evt.JobID.String()),
			attribute.String("reason", string(evt.Reason)),
			attribute.String("stalled_since", evt.StalledSince.String()),
		))
	defer span.End()

	task, err := t.jobService.MarkTaskStale(ctx, evt.JobID, evt.TaskID, evt.Reason)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to mark task as stale")
		return fmt.Errorf("mark task stale failed (reason: %s, stalled_since: %s): %w",
			evt.Reason, evt.StalledSince, err)
	}

	sourceType, err := t.jobService.GetTaskSourceType(ctx, task.TaskID())
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to get task source type")
		return fmt.Errorf("get task source type failed (task_id: %s): %w",
			task.TaskID(), err)
	}
	span.AddEvent("task_source_type_retrieved", trace.WithAttributes(
		attribute.String("source_type", string(sourceType)),
	))

	resumeEvent := scanning.NewTaskResumeEvent(
		task.JobID(),
		task.TaskID(),
		sourceType,
		task.ResourceURI(),
		int(task.LastSequenceNum()),
		task.LastCheckpoint(),
	)
	if err := t.domainPublisher.PublishDomainEvent(
		ctx, resumeEvent, events.WithKey(evt.TaskID.String()),
	); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to publish task resume event")
		return fmt.Errorf("publish resume event failed (source_type: %s): %w",
			sourceType, err)
	}
	span.AddEvent("task_marked_stale_and_resume_task_event_published")
	span.SetStatus(codes.Ok, "task marked stale and resume task event published")
	t.logger.Info(ctx, "Task marked stale and resume task event published",
		"task_id", evt.TaskID, "job_id", evt.JobID,
		"reason", evt.Reason,
		"stalled_since", evt.StalledSince,
	)

	return nil
}
