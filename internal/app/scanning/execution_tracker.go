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
	domain "github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

var _ scanning.ExecutionTracker = (*executionTracker)(nil)

// executionTracker implements scanning.ExecutionTracker, coordinating job and task
// state transitions across the system. It centralizes updates and publishes domain
// events to keep external components informed.
// TODO: Consider splitting this up into multiple components. (eg. JobScheduler, TaskScheduler, etc.)
type executionTracker struct {
	controllerID string

	// jobTaskSvc handles lower-level job and task persistence and state transitions.
	jobTaskSvc scanning.JobTaskService

	// publisher publishes domain events (e.g., job created, enumeration completed).
	publisher events.DomainEventPublisher

	logger *logger.Logger
	tracer trace.Tracer
}

// NewExecutionTracker returns a scanning.ExecutionTracker that coordinates job and task
// state transitions. It requires a job-task service, a domain event publisher, and
// logger/tracer instances for instrumentation.
func NewExecutionTracker(
	controllerID string,
	jobTaskSvc scanning.JobTaskService,
	publisher events.DomainEventPublisher,
	logger *logger.Logger,
	tracer trace.Tracer,
) *executionTracker {
	logger = logger.With("component", "execution_tracker")
	return &executionTracker{
		controllerID: controllerID,
		jobTaskSvc:   jobTaskSvc,
		publisher:    publisher,
		logger:       logger,
		tracer:       tracer,
	}
}

// ProcessEnumerationStream consumes channels from a scanning.ScanningResult, updating the
// job in stages (e.g., enumerating, linking enumerated targets, creating tasks). It
// signals when enumeration starts and completes, ensuring the job transitions properly.
func (t *executionTracker) ProcessEnumerationStream(
	ctx context.Context,
	jobID uuid.UUID,
	result *scanning.ScanningResult,
) error {
	logger := t.logger.With("operation", "process_enumeration_stream", "job_id", jobID)
	ctx, span := t.tracer.Start(ctx, "execution_tracker.process_enumeration_stream",
		trace.WithAttributes(
			attribute.String("controller_id", t.controllerID),
			attribute.String("job_id", jobID.String()),
		),
	)
	defer span.End()

	if err := t.signalEnumerationStarted(ctx, jobID); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to signal enumeration started")
		return fmt.Errorf("failed to signal enumeration started: %w", err)
	}
	span.AddEvent("enumeration_started_signal_sent")
	logger.Debug(ctx, "Enumeration started signal sent")

	allChannelsClosed := func() bool {
		return result.ScanTargetsCh == nil && result.TasksCh == nil && result.ErrCh == nil
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case scanTargetIDs, ok := <-result.ScanTargetsCh:
			if !ok {
				result.ScanTargetsCh = nil
				logger.Debug(ctx, "ScanTargetsCh closed, setting to nil")
				if allChannelsClosed() {
					break
				}
				continue
			}
			if err := t.associateEnumeratedTargetsToJob(ctx, jobID, scanTargetIDs); err != nil {
				span.RecordError(err)
				span.SetStatus(codes.Error, "failed to link enumerated targets")
				return fmt.Errorf("failed to link enumerated targets: %w", err)
			}
			logger.Debug(ctx, "Enumerated targets linked to job")

		case translationRes, ok := <-result.TasksCh:
			if !ok {
				result.TasksCh = nil
				logger.Debug(ctx, "TasksCh closed, setting to nil")
				if allChannelsClosed() {
					break
				}
				continue
			}
			if err := t.handleEnumeratedScanTask(
				ctx,
				jobID,
				translationRes.Task,
				translationRes.Auth,
				translationRes.Metadata,
			); err != nil {
				span.RecordError(err)
				span.SetStatus(codes.Error, "failed to handle enumerated scan task")
				return fmt.Errorf("failed to handle enumerated scan task: %w", err)
			}
			logger.Debug(ctx, "Enumerated scan task handled",
				"task_id", translationRes.Task.ID,
				"job_id", jobID,
				"metadata", translationRes.Metadata,
			)

		case errVal, ok := <-result.ErrCh:
			if !ok {
				result.ErrCh = nil
				logger.Debug(ctx, "ErrCh closed, setting to nil")
				if allChannelsClosed() {
					break
				}
				continue
			}
			if errVal != nil {
				span.RecordError(errVal)
				span.SetStatus(codes.Error, "enumeration error")
				return fmt.Errorf("enumeration error: %w", errVal)
			}
		}

		if allChannelsClosed() {
			break
		}
	}

	// End-of-stream logic.
	if err := t.signalEnumerationComplete(ctx, jobID); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to signal enumeration complete")
		return fmt.Errorf("failed to signal enumeration complete: %w", err)
	}
	logger.Debug(ctx, "Enumeration complete signal sent")
	span.AddEvent("enumeration_complete_signal_sent")
	span.SetStatus(codes.Ok, "enumeration completed")

	span.AddEvent("finished_processing_enumeration_stream")
	span.SetStatus(codes.Ok, "finished processing enumeration stream")

	return nil
}

// signalEnumerationStarted updates the job status to Enumerating to indicate that the
// enumeration phase has begun for the given job.
func (t *executionTracker) signalEnumerationStarted(ctx context.Context, jobID uuid.UUID) error {
	ctx, span := t.tracer.Start(ctx, "execution_tracker.scanning.signal_enumeration_started",
		trace.WithAttributes(
			attribute.String("controller_id", t.controllerID),
			attribute.String("job_id", jobID.String()),
		))
	defer span.End()

	if err := t.jobTaskSvc.UpdateJobStatus(ctx, jobID, domain.JobStatusEnumerating); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to update job status")
		return fmt.Errorf("failed to update job status: %w", err)
	}
	span.AddEvent("job_status_updated", trace.WithAttributes(
		attribute.String("status", string(domain.JobStatusEnumerating)),
	))
	span.SetStatus(codes.Ok, "enumeration started")

	return nil
}

// associateEnumeratedTargetsToJob links newly discovered targets to the specified job
// and updates aggregate counts. This is invoked when enumerated targets are received
// from the ScanningResult channel.
func (t *executionTracker) associateEnumeratedTargetsToJob(
	ctx context.Context,
	jobID uuid.UUID,
	scanTargetIDs []uuid.UUID,
) error {
	ctx, span := t.tracer.Start(ctx, "execution_tracker.scanning.link_enumerated_targets",
		trace.WithAttributes(
			attribute.String("controller_id", t.controllerID),
			attribute.String("job_id", jobID.String()),
			attribute.Int("target_count", len(scanTargetIDs)),
		))
	defer span.End()

	if err := t.jobTaskSvc.AssociateEnumeratedTargets(ctx, jobID, scanTargetIDs); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to associate enumerated targets")
		return fmt.Errorf("failed to associate enumerated targets: %w", err)
	}

	span.SetStatus(codes.Ok, "enumerated targets associated with job")
	t.logger.Info(ctx, "Enumerated targets associated with job",
		"job_id", jobID,
		"target_count", len(scanTargetIDs),
	)

	return nil
}

// handleEnumeratedScanTask processes a task discovered during enumeration and publishes
// a TaskCreatedEvent with relevant task info. This ensures downstream consumers can
// pick up the newly created task for further execution.
func (t *executionTracker) handleEnumeratedScanTask(
	ctx context.Context,
	jobID uuid.UUID,
	task *scanning.Task,
	auth scanning.Auth,
	metadata map[string]string,
) error {
	ctx, span := t.tracer.Start(ctx, "execution_tracker.scanning.handle_enumerated_task",
		trace.WithAttributes(
			attribute.String("controller_id", t.controllerID),
			attribute.String("job_id", jobID.String()),
			attribute.String("task_id", task.ID.String()),
		))
	defer span.End()

	newTask := domain.NewScanTask(jobID, task.SourceType, task.ID, task.ResourceURI())
	if err := t.jobTaskSvc.CreateTask(ctx, newTask); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to create task in repo")
		return fmt.Errorf("creating task: %w", err)
	}
	span.AddEvent("task_created_in_repo")

	// Create and publish scanning domain event with the task info, credentials, and metadata
	evt := scanning.NewTaskCreatedEvent(
		jobID,
		task.ID,
		task.SourceType,
		task.ResourceURI(),
		metadata,
		auth,
	)

	if err := t.publisher.PublishDomainEvent(
		ctx,
		evt,
		events.WithKey(task.ID.String()),
	); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to publish task created event")
		return fmt.Errorf("failed to publish task created event: %w", err)
	}

	span.AddEvent("task_event_published")
	span.SetStatus(codes.Ok, "task handled successfully")
	t.logger.Info(ctx, "Enumerated task handled",
		"job_id", jobID,
		"task_id", task.ID,
	)

	return nil
}

// signalEnumerationComplete marks enumeration as complete for the job, retrieves job
// metrics, and publishes a JobEnumerationCompletedEvent to indicate that all tasks
// have been discovered.
func (t *executionTracker) signalEnumerationComplete(ctx context.Context, jobID uuid.UUID) error {
	ctx, span := t.tracer.Start(ctx, "execution_tracker.scanning.signal_enumeration_complete",
		trace.WithAttributes(
			attribute.String("controller_id", t.controllerID),
			attribute.String("job_id", jobID.String()),
		))
	defer span.End()

	jobMetrics, err := t.jobTaskSvc.CompleteEnumeration(ctx, jobID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to complete enumeration")
		return fmt.Errorf("failed to complete enumeration: %w", err)
	}
	span.AddEvent("enumeration_completed_successfully")

	evt := scanning.NewJobEnumerationCompletedEvent(jobID, jobMetrics.TotalTasks())
	if err := t.publisher.PublishDomainEvent(ctx, evt, events.WithKey(jobID.String())); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to publish job enumeration completed event")
		return fmt.Errorf("failed to publish job enumeration completed event: %w", err)
	}
	span.AddEvent("job_enumeration_completed_event_published")

	return nil
}

// HandleTaskStart registers and initializes progress tracking for a newly started task.
// This may transition the job's overall status to RUNNING if this is the first active task.
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

	err := t.jobTaskSvc.StartTask(ctx, taskID, resourceURI)
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

// HandleTaskProgress updates the task progress in the job's aggregate view,
// recalculating any aggregated metrics if needed. It ensures real-time visibility
// into scan progress at both the task and job levels.
func (t *executionTracker) HandleTaskProgress(ctx context.Context, evt scanning.TaskProgressedEvent) error {
	taskID := evt.Progress.TaskID()
	ctx, span := t.tracer.Start(ctx, "execution_tracker.scanning.update_progress",
		trace.WithAttributes(
			attribute.String("controller_id", t.controllerID),
			attribute.String("task_id", taskID.String()),
			attribute.Int64("sequence_num", evt.Progress.SequenceNum()),
			attribute.Int64("items_processed", evt.Progress.ItemsProcessed()),
		))
	defer span.End()

	_, err := t.jobTaskSvc.UpdateTaskProgress(ctx, evt.Progress)
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

// HandleTaskPaused handles task pause events by transitioning the task to PAUSED status
// and storing the final progress checkpoint for later resumption.
func (t *executionTracker) HandleTaskPaused(ctx context.Context, evt scanning.TaskPausedEvent) error {
	taskID := evt.TaskID
	ctx, span := t.tracer.Start(ctx, "execution_tracker.scanning.pause_task",
		trace.WithAttributes(
			attribute.String("controller_id", t.controllerID),
			attribute.String("task_id", taskID.String()),
			attribute.String("job_id", evt.JobID.String()),
			attribute.String("requested_by", evt.RequestedBy),
		))
	defer span.End()

	_, err := t.jobTaskSvc.PauseTask(ctx, evt.TaskID, evt.Progress, evt.RequestedBy)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to pause task")
		return fmt.Errorf("failed to pause task: %w", err)
	}

	span.AddEvent("task_paused")
	span.SetStatus(codes.Ok, "task paused successfully")
	t.logger.Info(ctx, "Task paused",
		"task_id", taskID,
		"job_id", evt.JobID,
		"requested_by", evt.RequestedBy,
	)

	return nil
}

// HandleTaskCompletion marks a task as COMPLETED, updates aggregate job status if
// all tasks are done, and performs any final cleanup.
func (t *executionTracker) HandleTaskCompletion(ctx context.Context, evt scanning.TaskCompletedEvent) error {
	taskID := evt.TaskID
	ctx, span := t.tracer.Start(ctx, "execution_tracker.scanning.stop_tracking",
		trace.WithAttributes(
			attribute.String("controller_id", t.controllerID),
			attribute.String("task_id", taskID.String()),
		))
	defer span.End()

	_, err := t.jobTaskSvc.CompleteTask(ctx, evt.TaskID)
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

// HandleTaskFailure marks a task as FAILED, updating the job's aggregate state if needed
// and logging the error. Downstream consumers may respond to the event for remediation
// or re-try logic.
func (t *executionTracker) HandleTaskFailure(ctx context.Context, evt scanning.TaskFailedEvent) error {
	taskID := evt.TaskID
	ctx, span := t.tracer.Start(ctx, "execution_tracker.scanning.fail_task",
		trace.WithAttributes(
			attribute.String("controller_id", t.controllerID),
			attribute.String("task_id", taskID.String()),
		))
	defer span.End()

	_, err := t.jobTaskSvc.FailTask(ctx, evt.TaskID)
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

// HandleTaskStale marks a task as STALE, publishes a TaskResumeEvent for possible
// continuation, and logs relevant telemetry. This is used when a task appears
// unresponsive or stalled.
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

	task, err := t.jobTaskSvc.MarkTaskStale(ctx, evt.TaskID, evt.Reason)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to mark task as stale")
		return fmt.Errorf("mark task stale failed (reason: %s, stalled_since: %s): %w",
			evt.Reason, evt.StalledSince, err)
	}

	sourceType, err := t.jobTaskSvc.GetTaskSourceType(ctx, task.TaskID())
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to get task source type")
		return fmt.Errorf("get task source type failed (task_id: %s): %w",
			task.TaskID(), err)
	}
	span.AddEvent("task_source_type_retrieved", trace.WithAttributes(
		attribute.String("source_type", string(sourceType)),
	))

	// TODO: We still need to handle getting auth creds for the task.
	// We should probably use our Target type here similar to when we create a JobScheduledEvent.
	resumeEvent := scanning.NewTaskResumeEvent(
		task.JobID(),
		task.TaskID(),
		sourceType,
		task.ResourceURI(),
		int(task.LastSequenceNum()),
		task.LastCheckpoint(),
	)
	if err := t.publisher.PublishDomainEvent(
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

// HandleTaskCancelled handles task cancellation events by transitioning the task to CANCELLED status
// and storing the final progress checkpoint. It properly records the cancellation reason and requestor.
func (t *executionTracker) HandleTaskCancelled(ctx context.Context, evt scanning.TaskCancelledEvent) error {
	taskID := evt.TaskID
	ctx, span := t.tracer.Start(ctx, "execution_tracker.cancel_task",
		trace.WithAttributes(
			attribute.String("controller_id", t.controllerID),
			attribute.String("task_id", taskID.String()),
			attribute.String("job_id", evt.JobID.String()),
			attribute.String("requested_by", evt.RequestedBy),
		))
	defer span.End()

	_, err := t.jobTaskSvc.CancelTask(ctx, evt.TaskID, evt.RequestedBy)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to cancel task")
		return fmt.Errorf("failed to cancel task: %w", err)
	}

	span.AddEvent("task_cancelled")
	span.SetStatus(codes.Ok, "task cancelled successfully")
	t.logger.Info(ctx, "Task cancelled",
		"task_id", taskID,
		"job_id", evt.JobID,
		"requested_by", evt.RequestedBy,
	)

	return nil
}
