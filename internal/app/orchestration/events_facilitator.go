package orchestration

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/app/acl"
	rulessvc "github.com/ahrav/gitleaks-armada/internal/app/rules"
	"github.com/ahrav/gitleaks-armada/internal/domain/enumeration"
	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/domain/rules"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
)

// EventsFacilitator orchestrates domain event handling across multiple bounded contexts
// (e.g., scanning tasks and rules). It offloads domain logic to dedicated services like
// scanning.ExecutionTracker and rulessvc.Service while centralizing telemetry (tracing),
// error handling, and event acknowledgment.
type EventsFacilitator struct {
	// controllerID uniquely identifies the controller running this event facilitator.
	controllerID string

	// jobScheduler coordinates the creation and orchestration of new scanning jobs.
	// It delegates persistence to a JobTaskService and publishes domain events to notify
	// external subscribers about newly scheduled work, ensuring consistent job setup
	// while maintaining loose coupling with other system components.
	jobScheduler scanning.JobScheduler

	// executionTracker manages the lifecycle of scanning tasks (e.g., start, update, stop).
	// EventsFacilitator delegates most task-related operations here.
	executionTracker scanning.ExecutionTracker

	// taskHealthSupervisor monitors heartbeats for ongoing tasks, failing them if they
	// do not report within the configured threshold.
	taskHealthSupervisor scanning.TaskHealthMonitor

	// jobMetricsAggregator handles incoming job metrics and updates associated telemetry.
	jobMetricsAggregator scanning.JobMetricsAggregator

	// enumService starts enumeration and produces domain-specific channels for results,
	// which are then translated and passed to the scanning context.
	enumService enumeration.Service

	// scanToEnumACL translates scanning domain objects into enumeration domain objects.
	scanToEnumACL acl.ScanningToEnumerationTranslator

	// enumToScanACL translates enumeration domain objects back into scanning domain objects.
	enumToScanACL acl.EnumerationToScanningTranslator

	// rulesService persists and updates rules (e.g., for security scanning).
	rulesService rulessvc.Service

	// tracer instruments method calls with OpenTelemetry spans for distributed tracing.
	tracer trace.Tracer
}

// NewEventsFacilitator returns a new EventsFacilitator configured to process
// both scanning- and rules-related events. It requires all necessary services
// and a tracer for delegating domain-specific logic and instrumenting events.
func NewEventsFacilitator(
	controllerID string,
	jobScheduler scanning.JobScheduler,
	tracker scanning.ExecutionTracker,
	taskHealthSupervisor scanning.TaskHealthMonitor,
	metricsTracker scanning.JobMetricsAggregator,
	enumSvc enumeration.Service,
	rulesSvc rulessvc.Service,
	tracer trace.Tracer,
) *EventsFacilitator {
	return &EventsFacilitator{
		controllerID:         controllerID,
		jobScheduler:         jobScheduler,
		executionTracker:     tracker,
		taskHealthSupervisor: taskHealthSupervisor,
		jobMetricsAggregator: metricsTracker,
		enumService:          enumSvc,
		rulesService:         rulesSvc,
		tracer:               tracer,
	}
}

// withSpan creates a new trace span, executes the given function, records any errors,
// and ends the span. If no error occurs, it automatically acks the event.
func (ef *EventsFacilitator) withSpan(
	ctx context.Context,
	operationName string,
	fn func(ctx context.Context, span trace.Span) error,
	ack events.AckFunc,
) error {
	ctx, span := ef.tracer.Start(ctx, operationName)
	defer func() {
		span.End()
		ack(nil)
	}()

	span.SetAttributes(attribute.String("controller_id", ef.controllerID))

	if err := fn(ctx, span); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("%s: %w", operationName, err)
	}

	return nil
}

// withSpanNoAck behaves like withSpan but does not automatically call ack.
// This is useful for handlers that manage offsets or acknowledgments themselves.
func (ef *EventsFacilitator) withSpanNoAck(
	ctx context.Context,
	operationName string,
	fn func(ctx context.Context, span trace.Span) error,
) error {
	ctx, span := ef.tracer.Start(ctx, operationName)
	defer span.End()

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
// -------------------------------------------------------------------------------------------------
// Scanning

// HandleScanJobRequested processes a scanning.JobRequestedEvent by creating scanning jobs
// for each target. Once complete, it acks the event.
func (ef *EventsFacilitator) HandleScanJobRequested(
	ctx context.Context,
	evt events.EventEnvelope,
	ack events.AckFunc,
) error {
	return ef.withSpan(ctx, "events_facilitator.handle_scan_job_requested", func(ctx context.Context, span trace.Span) error {
		jobEvt, ok := evt.Payload.(scanning.JobRequestedEvent)
		if !ok {
			return recordPayloadTypeError(span, evt.Payload)
		}

		span.AddEvent("processing_job_requested", trace.WithAttributes(
			attribute.String("requested_by", jobEvt.RequestedBy),
			attribute.String("job_id", jobEvt.JobID().String()),
		))

		if err := ef.jobScheduler.Schedule(ctx, jobEvt.JobID(), jobEvt.Targets); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "failed to schedule job")
			return fmt.Errorf("failed to schedule job (job_id: %s): %w", jobEvt.JobID(), err)
		}

		span.AddEvent("jobs_created_successfully")
		span.SetStatus(codes.Ok, "jobs created successfully")
		return nil
	}, ack)
}

// HandleScanJobScheduled processes a scanning.JobScheduledEvent by converting
// the scanning target to an enumeration spec, starting enumeration, and then
// routing its results back into the scanning domain. Acks on success or error.
func (ef *EventsFacilitator) HandleScanJobScheduled(
	ctx context.Context,
	evt events.EventEnvelope,
	ack events.AckFunc,
) error {
	return ef.withSpan(ctx, "events_facilitator.handle_scan_job_scheduled", func(ctx context.Context, span trace.Span) error {
		jobEvt, ok := evt.Payload.(scanning.JobScheduledEvent)
		if !ok {
			return recordPayloadTypeError(span, evt.Payload)
		}

		span.AddEvent("processing_job_scheduled", trace.WithAttributes(
			attribute.String("job_id", jobEvt.JobID.String()),
		))

		// ACL check: convert scanning target to enumeration target.
		targetSpec, err := ef.scanToEnumACL.ToEnumerationTargetSpec(jobEvt.Target)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "failed to convert scanning target to enumeration spec")
			return fmt.Errorf("failed to convert scanning target to enumeration spec: %w", err)
		}

		// Start enumeration (returns enumeration domain channels).
		enumResult := ef.enumService.StartEnumeration(ctx, targetSpec)

		// Translate enumeration domain channels -> scanning domain channels.
		scanningResult := ef.enumToScanACL.TranslateEnumerationResultToScanning(
			ctx,
			enumResult,
			jobEvt.JobID,
		)

		err = ef.executionTracker.ProcessEnumerationStream(ctx, jobEvt.JobID, scanningResult)
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

// HandleTaskStarted processes a scanning.TaskStartedEvent and delegates
// the start-tracking operation to the executionTracker. Acks on success or error.
func (ef *EventsFacilitator) HandleTaskStarted(
	ctx context.Context,
	evt events.EventEnvelope,
	ack events.AckFunc,
) error {
	return ef.withSpan(ctx, "events_facilitator.handle_task_started", func(ctx context.Context, span trace.Span) error {
		span.AddEvent("processing_task_started")

		startedEvt, ok := evt.Payload.(scanning.TaskStartedEvent)
		if !ok {
			return recordPayloadTypeError(span, evt.Payload)
		}

		span.AddEvent("task_started_tracking", trace.WithAttributes(
			attribute.String("task_id", startedEvt.TaskID.String()),
			attribute.String("job_id", startedEvt.JobID.String()),
			attribute.String("resource_uri", startedEvt.ResourceURI),
		))

		if err := ef.executionTracker.HandleTaskStart(ctx, startedEvt); err != nil {
			return fmt.Errorf("failed to start tracking task (task_id: %s, job_id: %s, resource_uri: %s, partition: %d, offset: %d): %w",
				startedEvt.TaskID, startedEvt.JobID, startedEvt.ResourceURI, evt.Metadata.Partition, evt.Metadata.Offset, err)
		}

		span.AddEvent("task_started_tracking_completed")
		span.SetStatus(codes.Ok, "task started tracking completed")
		return nil
	}, ack)
}

// HandleTaskProgressed processes a scanning.TaskProgressedEvent and updates
// the task progress in executionTracker.
func (ef *EventsFacilitator) HandleTaskProgressed(
	ctx context.Context,
	evt events.EventEnvelope,
	ack events.AckFunc,
) error {
	return ef.withSpan(ctx, "events_facilitator.handle_task_progressed", func(ctx context.Context, span trace.Span) error {
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

		if err := ef.executionTracker.HandleTaskProgress(ctx, progressEvt); err != nil {
			return fmt.Errorf("failed to update progress (task_id: %s, job_id: %s, sequence_num: %d, partition: %d, offset: %d): %w",
				progressEvt.Progress.TaskID(), progressEvt.Progress.JobID(), progressEvt.Progress.SequenceNum(), evt.Metadata.Partition, evt.Metadata.Offset, err)
		}

		span.AddEvent("task_progressed_event_updated")
		span.SetStatus(codes.Ok, "task progressed event updated")
		return nil
	}, ack)
}

// HandleTaskCompleted processes a scanning.TaskCompletedEvent and finalizes
// tracking for the completed task.
func (ef *EventsFacilitator) HandleTaskCompleted(
	ctx context.Context,
	evt events.EventEnvelope,
	ack events.AckFunc,
) error {
	return ef.withSpan(ctx, "events_facilitator.handle_task_completed", func(ctx context.Context, span trace.Span) error {
		span.AddEvent("processing_task_completed")

		completedEvt, ok := evt.Payload.(scanning.TaskCompletedEvent)
		if !ok {
			return recordPayloadTypeError(span, evt.Payload)
		}

		span.AddEvent("task_completed_event_valid", trace.WithAttributes(
			attribute.String("task_id", completedEvt.TaskID.String()),
			attribute.String("job_id", completedEvt.JobID.String()),
		))

		if err := ef.executionTracker.HandleTaskCompletion(ctx, completedEvt); err != nil {
			return fmt.Errorf("failed to stop tracking task (task_id: %s, job_id: %s, partition: %d, offset: %d): %w",
				completedEvt.TaskID, completedEvt.JobID, evt.Metadata.Partition, evt.Metadata.Offset, err)
		}

		span.AddEvent("task_completed_event_updated")
		span.SetStatus(codes.Ok, "task completed event updated")
		return nil
	}, ack)
}

// HandleTaskFailed processes a scanning.TaskFailedEvent and updates the
// executionTracker with the failure reason.
func (ef *EventsFacilitator) HandleTaskFailed(
	ctx context.Context,
	evt events.EventEnvelope,
	ack events.AckFunc,
) error {
	return ef.withSpan(ctx, "events_facilitator.handle_task_failed", func(ctx context.Context, span trace.Span) error {
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

		if err := ef.executionTracker.HandleTaskFailure(ctx, failedEvt); err != nil {
			return fmt.Errorf("failed to fail task (task_id: %s, job_id: %s, reason: %s, partition: %d, offset: %d): %w",
				failedEvt.TaskID, failedEvt.JobID, failedEvt.Reason, evt.Metadata.Partition, evt.Metadata.Offset, err)
		}

		span.AddEvent("task_failed_event_updated")
		span.SetStatus(codes.Ok, "task failed event updated")
		return nil
	}, ack)
}

// HandleTaskJobMetric processes scanning.TaskJobMetricEvent by delegating metric
// handling to jobMetricsAggregator. Note that this handler does NOT call ack
// automatically, since offset commits are managed in jobMetricsAggregator.
// TODO: This might need a slight rename since it also handles JobEnumerationCompletedEvent.
func (ef *EventsFacilitator) HandleTaskJobMetric(
	ctx context.Context,
	evt events.EventEnvelope,
	ack events.AckFunc,
) error {
	return ef.withSpanNoAck(ctx, "events_facilitator.handle_task_job_metric", func(ctx context.Context, span trace.Span) error {
		span.AddEvent("processing_task_job_metric")

		switch evt.Payload.(type) {
		case scanning.TaskJobMetricEvent:
			if err := ef.jobMetricsAggregator.HandleJobMetrics(ctx, evt, ack); err != nil {
				span.RecordError(err)
				span.SetStatus(codes.Error, "failed to handle job metrics")
				return fmt.Errorf("failed to handle job metrics (partition: %d, offset: %d): %w",
					evt.Metadata.Partition, evt.Metadata.Offset, err)
			}

		case scanning.JobEnumerationCompletedEvent:
			if err := ef.jobMetricsAggregator.HandleEnumerationCompleted(ctx, evt, ack); err != nil {
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
	})
}

// HandleTaskHeartbeat processes a scanning.TaskHeartbeatEvent, using the
// taskHealthSupervisor to track heartbeats.
func (ef *EventsFacilitator) HandleTaskHeartbeat(
	ctx context.Context,
	evt events.EventEnvelope,
	ack events.AckFunc,
) error {
	return ef.withSpan(ctx, "events_facilitator.handle_task_heartbeat", func(ctx context.Context, span trace.Span) error {
		span.AddEvent("processing_task_heartbeat")

		heartbeatEvt, ok := evt.Payload.(scanning.TaskHeartbeatEvent)
		if !ok {
			return recordPayloadTypeError(span, evt.Payload)
		}

		span.AddEvent("task_heartbeat_event_valid", trace.WithAttributes(
			attribute.String("task_id", heartbeatEvt.TaskID.String()),
		))

		ef.taskHealthSupervisor.HandleHeartbeat(ctx, heartbeatEvt)

		span.AddEvent("task_heartbeat_processed")
		span.SetStatus(codes.Ok, "task heartbeat processed")
		return nil
	}, ack)
}

// -------------------------------------------------------------------------------------------------
// -------------------------------------------------------------------------------------------------
// Rules

// HandleRule processes a rules.RuleUpdatedEvent, calling rulesService.SaveRule
// to persist the updated rule.
func (ef *EventsFacilitator) HandleRule(
	ctx context.Context,
	evt events.EventEnvelope,
	ack events.AckFunc,
) error {
	return ef.withSpan(ctx, "events_facilitator.handle_rule", func(ctx context.Context, span trace.Span) error {
		span.AddEvent("processing_rule_update")

		ruleEvt, ok := evt.Payload.(rules.RuleUpdatedEvent)
		if !ok {
			return recordPayloadTypeError(span, evt.Payload)
		}

		if err := ef.rulesService.SaveRule(ctx, ruleEvt.Rule.GitleaksRule); err != nil {
			return fmt.Errorf("failed to persist rule (rule_id: %s, rule_hash: %s, partition: %d, offset: %d): %w",
				ruleEvt.Rule.RuleID, ruleEvt.Rule.Hash, evt.Metadata.Partition, evt.Metadata.Offset, err)
		}
		span.AddEvent("rule_persisted")

		span.AddEvent("rule_processed", trace.WithAttributes(
			attribute.String("rule_id", ruleEvt.Rule.RuleID),
			attribute.String("rule_hash", ruleEvt.Rule.Hash),
		))
		span.SetStatus(codes.Ok, "rule processed")
		return nil
	}, ack)
}

// HandleRulesPublished processes a rules.RulePublishingCompletedEvent
// indicating that all rules have been published.
func (ef *EventsFacilitator) HandleRulesPublished(
	ctx context.Context,
	evt events.EventEnvelope,
	ack events.AckFunc,
) error {
	return ef.withSpan(ctx, "events_facilitator.handle_rules_published", func(ctx context.Context, span trace.Span) error {
		span.AddEvent("processing_rules_published")

		if _, ok := evt.Payload.(rules.RulePublishingCompletedEvent); !ok {
			return recordPayloadTypeError(span, evt.Payload)
		}

		span.AddEvent("rules_update_completed")
		span.SetStatus(codes.Ok, "rules update completed")
		return nil
	}, ack)
}
