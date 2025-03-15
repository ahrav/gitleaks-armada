package handlers

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/app/acl"
	"github.com/ahrav/gitleaks-armada/internal/domain/enumeration"
	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/pkg/common/uuid"
)

// ScanningHandler processes all events related to the scanning bounded context.
// It follows Domain-Driven Design principles by delegating domain logic to
// appropriate domain services while handling cross-cutting concerns like tracing.
type ScanningHandler struct {
	// controllerID uniquely identifies the controller running this handler.
	controllerID string

	// jobScheduler coordinates the creation and orchestration of new scanning jobs.
	jobScheduler scanning.JobScheduler
	// executionTracker manages the lifecycle of scanning tasks.
	executionTracker scanning.ExecutionTracker
	// taskHealthSupervisor monitors heartbeats for ongoing tasks.
	taskHealthSupervisor scanning.TaskHealthMonitor
	// jobMetricsAggregator handles incoming job metrics and updates associated telemetry.
	jobMetricsAggregator scanning.JobMetricsAggregator
	// enumService starts enumeration and produces domain-specific results.
	enumService enumeration.Service

	// scanToEnumACL translates scanning domain objects into enumeration domain objects.
	scanToEnumACL acl.ScanningToEnumerationTranslator
	// enumToScanACL translates enumeration domain objects back into scanning domain objects.
	enumToScanACL acl.EnumerationToScanningTranslator

	// tracer instruments method calls with OpenTelemetry spans for distributed tracing.
	tracer trace.Tracer
}

// NewScanningHandler creates a new ScanningHandler with all dependencies required
// to process scanning-related events.
func NewScanningHandler(
	controllerID string,
	jobScheduler scanning.JobScheduler,
	executionTracker scanning.ExecutionTracker,
	taskHealthSupervisor scanning.TaskHealthMonitor,
	jobMetricsAggregator scanning.JobMetricsAggregator,
	enumService enumeration.Service,
	tracer trace.Tracer,
) *ScanningHandler {
	return &ScanningHandler{
		controllerID:         controllerID,
		jobScheduler:         jobScheduler,
		executionTracker:     executionTracker,
		taskHealthSupervisor: taskHealthSupervisor,
		jobMetricsAggregator: jobMetricsAggregator,
		enumService:          enumService,
		tracer:               tracer,
	}
}

// HandleEvent implements the events.EventHandler interface.
// It routes the event to the appropriate handler based on the event type.
func (h *ScanningHandler) HandleEvent(
	ctx context.Context,
	evt events.EventEnvelope,
	ack events.AckFunc,
) error {
	switch evt.Type {
	// Job-related events.
	case scanning.EventTypeJobRequested:
		return h.HandleScanJobRequested(ctx, evt, ack)
	case scanning.EventTypeJobScheduled:
		return h.HandleScanJobScheduled(ctx, evt, ack)
	case scanning.EventTypeJobPausing:
		return h.HandleJobPausing(ctx, evt, ack)
	case scanning.EventTypeJobCancelling:
		return h.HandleJobCancelling(ctx, evt, ack)
	case scanning.EventTypeJobResuming:
		return h.HandleJobResuming(ctx, evt, ack)

	// Task-related events.
	case scanning.EventTypeTaskStarted:
		return h.HandleTaskStarted(ctx, evt, ack)
	case scanning.EventTypeTaskProgressed:
		return h.HandleTaskProgressed(ctx, evt, ack)
	case scanning.EventTypeTaskCompleted:
		return h.HandleTaskCompleted(ctx, evt, ack)
	case scanning.EventTypeTaskPaused:
		return h.HandleTaskPaused(ctx, evt, ack)
	case scanning.EventTypeTaskFailed:
		return h.HandleTaskFailed(ctx, evt, ack)
	case scanning.EventTypeTaskCancelled:
		return h.HandleTaskCancelled(ctx, evt, ack)

	// Health and metrics events.
	case scanning.EventTypeTaskHeartbeat:
		return h.HandleTaskHeartbeat(ctx, evt, ack)
	case scanning.EventTypeTaskJobMetric, scanning.EventTypeJobEnumerationCompleted:
		return h.HandleTaskJobMetric(ctx, evt, ack)

	default:
		return fmt.Errorf("unsupported event type: %s", evt.Type)
	}
}

// SupportedEvents implements the events.EventHandler interface.
// It returns the list of event types this handler can process.
func (h *ScanningHandler) SupportedEvents() []events.EventType {
	return []events.EventType{
		// Job-related events.
		scanning.EventTypeJobRequested,
		scanning.EventTypeJobScheduled,
		scanning.EventTypeJobPausing,
		scanning.EventTypeJobCancelling,
		scanning.EventTypeJobResuming,

		// Task-related events.
		scanning.EventTypeTaskStarted,
		scanning.EventTypeTaskProgressed,
		scanning.EventTypeTaskCompleted,
		scanning.EventTypeTaskPaused,
		scanning.EventTypeTaskFailed,
		scanning.EventTypeTaskCancelled,

		// Health and metrics events.
		scanning.EventTypeTaskHeartbeat,
		scanning.EventTypeTaskJobMetric,
	}
}

// withSpan creates a new trace span, executes the given function, records any errors,
// and ends the span. If no error occurs, it automatically acknowledges the event.
func (h *ScanningHandler) withSpan(
	ctx context.Context,
	operationName string,
	fn func(ctx context.Context, span trace.Span) error,
	ack events.AckFunc,
) error {
	ctx, span := h.tracer.Start(ctx, operationName)
	defer func() {
		span.End()
		ack(nil)
	}()

	span.SetAttributes(attribute.String("controller_id", h.controllerID))

	if err := fn(ctx, span); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("%s: %w", operationName, err)
	}

	return nil
}

// recordPayloadTypeError standardizes error creation and recording for invalid payload types.
func recordPayloadTypeError(span trace.Span, payload any) error {
	err := fmt.Errorf("invalid event payload type: %T", payload)
	span.RecordError(err)
	span.SetAttributes(
		attribute.String("actual_type", fmt.Sprintf("%T", payload)),
	)
	span.SetStatus(codes.Error, "invalid event payload type")
	return err
}

// -------------------------------------------------------------------------------------------------
// Job-related event handlers
// -------------------------------------------------------------------------------------------------

// HandleScanJobRequested processes a scanning.JobRequestedEvent by scheduling scanning jobs
// for the specified targets.
func (h *ScanningHandler) HandleScanJobRequested(
	ctx context.Context,
	evt events.EventEnvelope,
	ack events.AckFunc,
) error {
	return h.withSpan(ctx, "scanning_handler.handle_job_requested", func(ctx context.Context, span trace.Span) error {
		jobEvt, ok := evt.Payload.(scanning.JobRequestedEvent)
		if !ok {
			return recordPayloadTypeError(span, evt.Payload)
		}

		span.AddEvent("processing_job_requested", trace.WithAttributes(
			attribute.String("requested_by", jobEvt.RequestedBy),
			attribute.String("job_id", jobEvt.JobID().String()),
		))

		cmd := scanning.NewScheduleJobCommand(jobEvt.JobID(), jobEvt.RequestedBy, jobEvt.Targets)
		if err := h.jobScheduler.Schedule(ctx, cmd); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "failed to schedule job")
			return fmt.Errorf("failed to schedule job (job_id: %s): %w", jobEvt.JobID(), err)
		}

		span.AddEvent("jobs_created_successfully")
		span.SetStatus(codes.Ok, "jobs created successfully")
		return nil
	}, ack)
}

// HandleScanJobScheduled processes a scanning.JobScheduledEvent by starting enumeration for
// the scheduled job.
func (h *ScanningHandler) HandleScanJobScheduled(
	ctx context.Context,
	evt events.EventEnvelope,
	ack events.AckFunc,
) error {
	return h.withSpan(ctx, "scanning_handler.handle_job_scheduled", func(ctx context.Context, span trace.Span) error {
		jobEvt, ok := evt.Payload.(scanning.JobScheduledEvent)
		if !ok {
			return recordPayloadTypeError(span, evt.Payload)
		}

		span.AddEvent("processing_job_scheduled", trace.WithAttributes(
			attribute.String("job_id", jobEvt.JobID.String()),
		))

		targetSpec, err := h.scanToEnumACL.ToEnumerationTargetSpec(jobEvt.Target)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "failed to convert scanning target to enumeration spec")
			return fmt.Errorf("failed to convert scanning target to enumeration spec: %w", err)
		}

		enumResult := h.enumService.StartEnumeration(ctx, targetSpec)

		// Translate with job-level context.
		auth := jobEvt.Target.Auth()
		metadata := jobEvt.Target.Metadata()
		scanningResult := h.enumToScanACL.TranslateEnumerationResultToScanning(
			ctx,
			enumResult,
			jobEvt.JobID,
			*auth,
			metadata,
		)

		err = h.executionTracker.ProcessEnumerationStream(ctx, jobEvt.JobID, scanningResult)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "enumeration stream processing failed")
			return err
		}

		span.AddEvent("enumeration_completed_successfully")
		span.SetStatus(codes.Ok, "enumeration completed")
		return nil
	}, ack)
}

// HandleJobPausing processes a scanning.JobPausingEvent by updating the job status
// to PAUSED.
func (h *ScanningHandler) HandleJobPausing(
	ctx context.Context,
	evt events.EventEnvelope,
	ack events.AckFunc,
) error {
	return h.withSpan(ctx, "scanning_handler.handle_job_pausing", func(ctx context.Context, span trace.Span) error {
		span.AddEvent("processing_job_pausing")

		pausingEvt, ok := evt.Payload.(scanning.JobPausingEvent)
		if !ok {
			return recordPayloadTypeError(span, evt.Payload)
		}

		jobID, err := uuid.Parse(pausingEvt.JobID)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "invalid job ID")
			return fmt.Errorf("invalid job ID: %w", err)
		}

		span.AddEvent("job_pausing_event_valid", trace.WithAttributes(
			attribute.String("job_id", jobID.String()),
			attribute.String("requested_by", pausingEvt.RequestedBy),
		))

		cmd := scanning.NewJobControlCommand(jobID, pausingEvt.RequestedBy)
		if err := h.jobScheduler.Pause(ctx, cmd); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "failed to pause job")
			return fmt.Errorf("failed to pause job (job_id: %s): %w", jobID, err)
		}

		span.AddEvent("job_paused_successfully")
		span.SetStatus(codes.Ok, "job paused successfully")
		return nil
	}, ack)
}

// HandleJobCancelling processes a scanning.JobCancellingEvent by updating the job status
// to CANCELLED.
func (h *ScanningHandler) HandleJobCancelling(
	ctx context.Context,
	evt events.EventEnvelope,
	ack events.AckFunc,
) error {
	return h.withSpan(ctx, "scanning_handler.handle_job_cancelling", func(ctx context.Context, span trace.Span) error {
		span.AddEvent("processing_job_cancelling")

		cancellingEvt, ok := evt.Payload.(scanning.JobCancellingEvent)
		if !ok {
			return recordPayloadTypeError(span, evt.Payload)
		}

		span.AddEvent("job_cancelling_event_valid", trace.WithAttributes(
			attribute.String("job_id", cancellingEvt.JobID),
			attribute.String("requested_by", cancellingEvt.RequestedBy),
		))

		jobID, err := uuid.Parse(cancellingEvt.JobID)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "invalid job ID")
			return fmt.Errorf("invalid job ID: %w", err)
		}

		cmd := scanning.NewJobControlCommand(jobID, cancellingEvt.RequestedBy)
		if err := h.jobScheduler.Cancel(ctx, cmd); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "failed to cancel job")
			return fmt.Errorf("failed to cancel job (job_id: %s): %w", jobID, err)
		}

		span.AddEvent("job_cancellation_initiated")
		span.SetStatus(codes.Ok, "job cancellation initiated")
		return nil
	}, ack)
}

// HandleJobResuming processes a scanning.JobResumingEvent by updating the job status
// to RUNNING.
func (h *ScanningHandler) HandleJobResuming(
	ctx context.Context,
	evt events.EventEnvelope,
	ack events.AckFunc,
) error {
	return h.withSpan(ctx, "scanning_handler.handle_job_resuming", func(ctx context.Context, span trace.Span) error {
		span.AddEvent("processing_job_resuming")

		resumingEvt, ok := evt.Payload.(scanning.JobResumingEvent)
		if !ok {
			return recordPayloadTypeError(span, evt.Payload)
		}

		span.AddEvent("job_resuming_event_valid", trace.WithAttributes(
			attribute.String("job_id", resumingEvt.JobID),
			attribute.String("requested_by", resumingEvt.RequestedBy),
		))

		jobID, err := uuid.Parse(resumingEvt.JobID)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "invalid job ID")
			return fmt.Errorf("invalid job ID: %w", err)
		}

		cmd := scanning.NewJobControlCommand(jobID, resumingEvt.RequestedBy)
		if err := h.jobScheduler.Resume(ctx, cmd); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "failed to resume job")
			return fmt.Errorf("failed to resume job (job_id: %s): %w", jobID, err)
		}

		span.AddEvent("job_resumption_initiated")
		span.SetStatus(codes.Ok, "job resumption initiated")
		return nil
	}, ack)
}

// -------------------------------------------------------------------------------------------------
// Task-related event handlers
// -------------------------------------------------------------------------------------------------

// HandleTaskStarted processes a scanning.TaskStartedEvent by recording the task status.
func (h *ScanningHandler) HandleTaskStarted(
	ctx context.Context,
	evt events.EventEnvelope,
	ack events.AckFunc,
) error {
	return h.withSpan(ctx, "scanning_handler.handle_task_started", func(ctx context.Context, span trace.Span) error {
		span.AddEvent("processing_task_started")

		startedEvt, ok := evt.Payload.(scanning.TaskStartedEvent)
		if !ok {
			return recordPayloadTypeError(span, evt.Payload)
		}

		span.AddEvent("task_started_tracking", trace.WithAttributes(
			attribute.String("task_id", startedEvt.TaskID.String()),
			attribute.String("job_id", startedEvt.JobID.String()),
			attribute.String("scanner_id", startedEvt.ScannerID.String()),
			attribute.String("resource_uri", startedEvt.ResourceURI),
		))

		if err := h.executionTracker.HandleTaskStart(ctx, startedEvt); err != nil {
			return fmt.Errorf(
				"failed to start tracking task (task_id: %s, job_id: %s, scanner_id: %s, "+
					"resource_uri: %s, partition: %d, offset: %d): %w",
				startedEvt.TaskID, startedEvt.JobID, startedEvt.ScannerID,
				startedEvt.ResourceURI, evt.Metadata.Partition, evt.Metadata.Offset, err)
		}

		span.AddEvent("task_started_tracking_completed")
		span.SetStatus(codes.Ok, "task started tracking completed")
		return nil
	}, ack)
}

// HandleTaskProgressed processes a scanning.TaskProgressedEvent by recording the task progress.
func (h *ScanningHandler) HandleTaskProgressed(
	ctx context.Context,
	evt events.EventEnvelope,
	ack events.AckFunc,
) error {
	return h.withSpan(ctx, "scanning_handler.handle_task_progressed", func(ctx context.Context, span trace.Span) error {
		span.AddEvent("processing_task_progressed")

		progressEvt, ok := evt.Payload.(scanning.TaskProgressedEvent)
		if !ok {
			return recordPayloadTypeError(span, evt.Payload)
		}

		span.AddEvent("task_progressed_event_valid", trace.WithAttributes(
			attribute.String("task_id", progressEvt.Progress.TaskID().String()),
			attribute.String("job_id", progressEvt.Progress.JobID().String()),
			attribute.Int64("sequence_num", progressEvt.Progress.SequenceNum()),
		))

		if err := h.executionTracker.HandleTaskProgress(ctx, progressEvt); err != nil {
			return fmt.Errorf("failed to update progress (task_id: %s, job_id: %s, sequence_num: %d, partition: %d, offset: %d): %w",
				progressEvt.Progress.TaskID(), progressEvt.Progress.JobID(), progressEvt.Progress.SequenceNum(), evt.Metadata.Partition, evt.Metadata.Offset, err)
		}

		span.AddEvent("task_progressed_event_updated")
		span.SetStatus(codes.Ok, "task progressed event updated")
		return nil
	}, ack)
}

// HandleTaskCompleted processes a scanning.TaskCompletedEvent by recording the task completion.
func (h *ScanningHandler) HandleTaskCompleted(
	ctx context.Context,
	evt events.EventEnvelope,
	ack events.AckFunc,
) error {
	return h.withSpan(ctx, "scanning_handler.handle_task_completed", func(ctx context.Context, span trace.Span) error {
		span.AddEvent("processing_task_completed")

		completedEvt, ok := evt.Payload.(scanning.TaskCompletedEvent)
		if !ok {
			return recordPayloadTypeError(span, evt.Payload)
		}

		span.AddEvent("task_completed_event_valid", trace.WithAttributes(
			attribute.String("task_id", completedEvt.TaskID.String()),
			attribute.String("job_id", completedEvt.JobID.String()),
		))

		if err := h.executionTracker.HandleTaskCompletion(ctx, completedEvt); err != nil {
			return fmt.Errorf("failed to stop tracking task (task_id: %s, job_id: %s, partition: %d, offset: %d): %w",
				completedEvt.TaskID, completedEvt.JobID, evt.Metadata.Partition, evt.Metadata.Offset, err)
		}

		span.AddEvent("task_completed_event_updated")
		span.SetStatus(codes.Ok, "task completed event updated")
		return nil
	}, ack)
}

// HandleTaskPaused processes a scanning.TaskPausedEvent by recording the task as paused.
func (h *ScanningHandler) HandleTaskPaused(
	ctx context.Context,
	evt events.EventEnvelope,
	ack events.AckFunc,
) error {
	return h.withSpan(ctx, "scanning_handler.handle_task_paused", func(ctx context.Context, span trace.Span) error {
		span.AddEvent("processing_task_paused")

		pausedEvt, ok := evt.Payload.(scanning.TaskPausedEvent)
		if !ok {
			return recordPayloadTypeError(span, evt.Payload)
		}

		span.AddEvent("task_paused_event_valid", trace.WithAttributes(
			attribute.String("task_id", pausedEvt.TaskID.String()),
			attribute.String("job_id", pausedEvt.JobID.String()),
			attribute.String("requested_by", pausedEvt.RequestedBy),
		))

		if err := h.executionTracker.HandleTaskPaused(ctx, pausedEvt); err != nil {
			return fmt.Errorf("failed to pause task (task_id: %s, job_id: %s, requested_by: %s, partition: %d, offset: %d): %w",
				pausedEvt.TaskID, pausedEvt.JobID, pausedEvt.RequestedBy, evt.Metadata.Partition, evt.Metadata.Offset, err)
		}

		span.AddEvent("task_paused_event_handled")
		span.SetStatus(codes.Ok, "task paused event handled")
		return nil
	}, ack)
}

// HandleTaskFailed processes a scanning.TaskFailedEvent by recording the task as failed.
func (h *ScanningHandler) HandleTaskFailed(
	ctx context.Context,
	evt events.EventEnvelope,
	ack events.AckFunc,
) error {
	return h.withSpan(ctx, "scanning_handler.handle_task_failed", func(ctx context.Context, span trace.Span) error {
		span.AddEvent("processing_task_failed")

		failedEvt, ok := evt.Payload.(scanning.TaskFailedEvent)
		if !ok {
			return recordPayloadTypeError(span, evt.Payload)
		}

		span.AddEvent("task_failed_event_valid", trace.WithAttributes(
			attribute.String("task_id", failedEvt.TaskID.String()),
			attribute.String("job_id", failedEvt.JobID.String()),
			attribute.String("reason", failedEvt.Reason),
		))

		if err := h.executionTracker.HandleTaskFailure(ctx, failedEvt); err != nil {
			return fmt.Errorf("failed to fail task (task_id: %s, job_id: %s, reason: %s, partition: %d, offset: %d): %w",
				failedEvt.TaskID, failedEvt.JobID, failedEvt.Reason, evt.Metadata.Partition, evt.Metadata.Offset, err)
		}

		span.AddEvent("task_failed_event_updated")
		span.SetStatus(codes.Ok, "task failed event updated")
		return nil
	}, ack)
}

// HandleTaskCancelled processes a scanning.TaskCancelledEvent by recording the task as cancelled.
func (h *ScanningHandler) HandleTaskCancelled(
	ctx context.Context,
	evt events.EventEnvelope,
	ack events.AckFunc,
) error {
	return h.withSpan(ctx, "scanning_handler.handle_task_cancelled", func(ctx context.Context, span trace.Span) error {
		span.AddEvent("processing_task_cancelled")

		cancelledEvt, ok := evt.Payload.(scanning.TaskCancelledEvent)
		if !ok {
			return recordPayloadTypeError(span, evt.Payload)
		}

		jobID, err := uuid.Parse(cancelledEvt.JobID.String())
		if err != nil {
			return fmt.Errorf("invalid job ID: %w", err)
		}

		taskID, err := uuid.Parse(cancelledEvt.TaskID.String())
		if err != nil {
			return fmt.Errorf("invalid task ID: %w", err)
		}

		span.AddEvent("task_cancelled_event_valid", trace.WithAttributes(
			attribute.String("job_id", jobID.String()),
			attribute.String("task_id", taskID.String()),
			attribute.String("requested_by", cancelledEvt.RequestedBy),
		))

		if err := h.executionTracker.HandleTaskCancelled(ctx, cancelledEvt); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "failed to handle task cancelled")
			return fmt.Errorf("failed to handle task cancelled (task_id: %s): %w", taskID, err)
		}

		span.AddEvent("task_cancelled_successfully")
		span.SetStatus(codes.Ok, "task cancelled successfully")
		return nil
	}, ack)
}

// HandleTaskHeartbeat processes a scanning.TaskHeartbeatEvent by updating the task's last heartbeat time.
func (h *ScanningHandler) HandleTaskHeartbeat(
	ctx context.Context,
	evt events.EventEnvelope,
	ack events.AckFunc,
) error {
	return h.withSpan(ctx, "scanning_handler.handle_task_heartbeat", func(ctx context.Context, span trace.Span) error {
		span.AddEvent("processing_task_heartbeat")

		heartbeatEvt, ok := evt.Payload.(scanning.TaskHeartbeatEvent)
		if !ok {
			return recordPayloadTypeError(span, evt.Payload)
		}

		span.AddEvent("task_heartbeat_event_valid", trace.WithAttributes(
			attribute.String("task_id", heartbeatEvt.TaskID.String()),
		))

		h.taskHealthSupervisor.HandleHeartbeat(ctx, heartbeatEvt)

		span.AddEvent("task_heartbeat_processed")
		span.SetStatus(codes.Ok, "task heartbeat processed")
		return nil
	}, ack)
}

// HandleTaskJobMetric processes scanning.TaskJobMetricEvent by delegating metric
// handling to jobMetricsAggregator. Note that this handler does NOT call ack
// automatically, since offset commits are managed in jobMetricsAggregator.
func (h *ScanningHandler) HandleTaskJobMetric(
	ctx context.Context,
	evt events.EventEnvelope,
	ack events.AckFunc,
) error {
	// Special case - don't use withSpan as we don't want to auto-ack.
	ctx, span := h.tracer.Start(ctx, "scanning_handler.handle_task_job_metric")
	defer span.End()

	span.SetAttributes(attribute.String("controller_id", h.controllerID))
	span.AddEvent("processing_task_job_metric")

	switch evt.Payload.(type) {
	case scanning.TaskJobMetricEvent:
		if err := h.jobMetricsAggregator.HandleJobMetrics(ctx, evt, ack); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "failed to handle job metrics")
			return fmt.Errorf("failed to handle job metrics (partition: %d, offset: %d): %w",
				evt.Metadata.Partition, evt.Metadata.Offset, err)
		}

	case scanning.JobEnumerationCompletedEvent:
		if err := h.jobMetricsAggregator.HandleEnumerationCompleted(ctx, evt, ack); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "failed to handle enumeration completed")
			return fmt.Errorf("failed to handle enumeration completed (partition: %d, offset: %d): %w",
				evt.Metadata.Partition, evt.Metadata.Offset, err)
		}
	default:
		span.SetStatus(codes.Error, "unexpected event type for job metrics tracker")
		return fmt.Errorf("unexpected event type for job metrics tracker: %T", evt.Payload)
	}

	span.AddEvent("job_metrics_handled")
	span.SetStatus(codes.Ok, "job metrics handled")
	return nil
}
