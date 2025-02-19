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

// executionTracker coordinates job and task state transitions across the system.
// It ensures consistent state transitions across the system.
type executionTracker struct {
	controllerID string

	jobTaskSvc scanning.JobTaskService // Manages job and task state transitions
	publisher  events.DomainEventPublisher

	logger *logger.Logger
	tracer trace.Tracer
}

// NewExecutionTracker constructs a new ExecutionTracker with required dependencies.
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

// CreateJobForTarget creates a new scan job for the given target and publishes a JobCreatedEvent.
func (t *executionTracker) CreateJobForTarget(ctx context.Context, target scanning.Target) error {
	ctx, span := t.tracer.Start(ctx, "execution_tracker.scanning.create_job",
		trace.WithAttributes(
			attribute.String("controller_id", t.controllerID),
			attribute.String("target_name", target.Name()),
			attribute.String("source_type", target.SourceType().String()),
		))
	defer span.End()

	job, err := t.jobTaskSvc.CreateJob(ctx)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to create job")
		return fmt.Errorf("failed to create job for target %s: %w", target.Name(), err)
	}

	// Publish JobCreatedEvent with target information.
	// The target information is required by downstream consumers of the JobCreatedEvent
	// to link scan targets to a single scan job.
	evt := scanning.NewJobCreatedEvent(job, target)
	if err := t.publisher.PublishDomainEvent(
		ctx, evt, events.WithKey(job.JobID().String()),
	); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to publish job created event")
		return fmt.Errorf("failed to publish job created event (job_id: %s, source_type: %s, source_name: %s): %w",
			job.JobID(), target.SourceType().String(), target.Name(), err)
	}

	span.AddEvent("job_created_and_event_published")
	span.SetStatus(codes.Ok, "job created and event published")
	t.logger.Info(ctx, "Job created",
		"job_id", job.JobID(),
		"target_name", target.Name(),
		"source_type", target.SourceType().String(),
	)

	return nil
}

// ProcessEnumerationStream consumes a stream of enumerated scan targets and tasks,
// converting them into scanning-domain entities, associating them with the specified
// job, and publishing the necessary domain events. Specifically, it:
func (t *executionTracker) ProcessEnumerationStream(
	ctx context.Context,
	jobID uuid.UUID,
	result *scanning.ScanningResult,
) error {
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

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case scanTargetIDs, ok := <-result.ScanTargetsCh:
			if !ok {
				result.ScanTargetsCh = nil
				continue
			}
			if err := t.associateEnumeratedTargetsToJob(ctx, jobID, scanTargetIDs); err != nil {
				span.RecordError(err)
				span.SetStatus(codes.Error, "failed to link enumerated targets")
				return fmt.Errorf("failed to link enumerated targets: %w", err)
			}

		case translationRes, ok := <-result.TasksCh:
			if !ok {
				result.TasksCh = nil
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

		case errVal, ok := <-result.ErrCh:
			if !ok {
				result.ErrCh = nil
				continue
			}
			if errVal != nil {
				span.RecordError(errVal)
				span.SetStatus(codes.Error, "enumeration error")
				return fmt.Errorf("enumeration error: %w", errVal)
			}
		}

		// All channels exhausted?
		if result.ScanTargetsCh == nil && result.TasksCh == nil && result.ErrCh == nil {
			break
		}
	}

	// End-of-stream logic.
	if err := t.signalEnumerationComplete(ctx, jobID); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to signal enumeration complete")
		return fmt.Errorf("failed to signal enumeration complete: %w", err)
	}
	span.AddEvent("enumeration_complete_signal_sent")
	span.SetStatus(codes.Ok, "enumeration completed")

	span.AddEvent("finished_processing_enumeration_stream")
	span.SetStatus(codes.Ok, "finished processing enumeration stream")

	return nil
}

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

// associateEnumeratedTargetsToJob wraps jobTaskSvc.AssociateEnumeratedTargets with
// the tracing and logging instrumentation. It ensures newly enumerated target IDs
// are atomically linked to the specified job and that the job’s total task count is
// updated, maintaining consistency across job state and discovered targets.
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

// handleEnumeratedScanTask processes a scanning task discovered during enumeration
// and publishes a TaskCreatedEvent with the task info, credentials, and metadata.
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

// signalEnumerationComplete signals that the enumeration phase is complete for a job.
// It retrieves the job metrics and publishes an EnumerationCompleteEvent.
// This allows for accurate job metrics tracking.
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

// HandleTaskStart initializes progress tracking for a new scan task. It coordinates with
// the coordinator to:
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

// HandleTaskFailure handles task failure.
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
