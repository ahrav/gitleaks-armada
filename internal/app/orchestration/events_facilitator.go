package orchestration

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	rulessvc "github.com/ahrav/gitleaks-armada/internal/app/rules"
	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/domain/rules"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
)

// EventsFacilitator orchestrates the handling of domain events that span multiple
// bounded contexts (e.g., scanning tasks and rules). It performs minimal domain logic
// itself, delegating to dedicated services like ExecutionTracker and RulesService to
// carry out actual business operations.
//
// It centralizes event handling for scanning tasks (start, progress, complete) and
// rule updates/publish events, ensuring consistent tracing and error handling across
// all events. This avoids duplicating telemetry logic and provides a unified interface
// for event processing.
//
// The facilitator acts as a single point of integration for events from different
// bounded contexts while keeping domain-service responsibilities properly separated
// (e.g., progress tracking in scanning package, rule logic in rules package).
type EventsFacilitator struct {
	controllerID string

	// executionTracker is responsible for starting, updating, and stopping tracking of
	// scanning tasks. The EventsFacilitator delegates task-related domain operations here.
	executionTracker scanning.ExecutionTracker

	// taskHealthSupervisor is responsible for monitoring task heartbeats and failing
	// tasks that have not sent a heartbeat within a given threshold.
	taskHealthSupervisor scanning.TaskHealthMonitor

	// metricsTracker is responsible for handling job metrics events.
	metricsTracker scanning.JobMetricsTracker

	// rulesService is responsible for persisting rules, updating rule states, etc.
	// The EventsFacilitator calls into it when handling rule-related events.
	rulesService rulessvc.Service

	tracer trace.Tracer
}

// NewEventsFacilitator constructs an EventsFacilitator that can process both
// scanning task events and rule-related events. It receives a executionTracker,
// rulesService, taskHealthSupervisor, metricsTracker, and tracer so it can delegate domain-specific logic
// to the correct bounded context service and instrument event handling with traces.
func NewEventsFacilitator(
	controllerID string,
	tracker scanning.ExecutionTracker,
	taskHealthSupervisor scanning.TaskHealthMonitor,
	metricsTracker scanning.JobMetricsTracker,
	rulesSvc rulessvc.Service,
	tracer trace.Tracer,
) *EventsFacilitator {
	return &EventsFacilitator{
		controllerID:         controllerID,
		executionTracker:     tracker,
		taskHealthSupervisor: taskHealthSupervisor,
		metricsTracker:       metricsTracker,
		rulesService:         rulesSvc,
		tracer:               tracer,
	}
}

// withSpan is a helper that centralizes trace creation and error recording.
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

// withSpanNoAck is similar to withSpan but doesn't automatically call ack.
// This is used for handlers that manage their own offset commits, like HandleTaskJobMetric.
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

// recordPayloadTypeError standardizes error creation and recording
// for invalid event payload types.
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

// HandleTaskStarted processes a TaskStartedEvent.
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

// HandleTaskProgressed processes a TaskProgressedEvent.
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

// HandleTaskCompleted processes a TaskCompletedEvent.
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

// HandleTaskFailed processes a TaskFailedEvent.
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

// HandleTaskHeartbeat processes a TaskHeartbeatEvent.
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

// HandleTaskJobMetric processes a TaskJobMetricEvent.
// Note: This handler does not ack messages as the JobMetricsTracker handles offset
// management internally after ensuring persistence.
func (ef *EventsFacilitator) HandleTaskJobMetric(
	ctx context.Context,
	evt events.EventEnvelope,
	ack events.AckFunc,
) error {
	return ef.withSpanNoAck(ctx, "events_facilitator.handle_task_job_metric", func(ctx context.Context, span trace.Span) error {
		if err := ef.metricsTracker.HandleJobMetrics(ctx, evt); err != nil {
			return fmt.Errorf("failed to handle job metrics (partition: %d, offset: %d): %w",
				evt.Metadata.Partition, evt.Metadata.Offset, err)
		}

		span.SetStatus(codes.Ok, "job metrics handled")
		return nil
	})
}

// -------------------------------------------------------------------------------------------------
// -------------------------------------------------------------------------------------------------
// Rules

// HandleRule processes a RuleUpdatedEvent.
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

// HandleRulesPublished processes a RulePublishingCompletedEvent.
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
