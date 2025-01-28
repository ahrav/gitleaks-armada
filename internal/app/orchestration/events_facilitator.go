package orchestration

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	rulessvc "github.com/ahrav/gitleaks-armada/internal/app/rules"
	scansvc "github.com/ahrav/gitleaks-armada/internal/app/scanning"
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
	// executionTracker is responsible for starting, updating, and stopping tracking of
	// scanning tasks. The EventsFacilitator delegates task-related domain operations here.
	executionTracker scansvc.ExecutionTracker

	// taskHealthSupervisor is responsible for monitoring task heartbeats and failing
	// tasks that have not sent a heartbeat within a given threshold.
	taskHealthSupervisor *scansvc.TaskHealthSupervisor

	// rulesService is responsible for persisting rules, updating rule states, etc.
	// The EventsFacilitator calls into it when handling rule-related events.
	rulesService rulessvc.Service

	tracer trace.Tracer
}

// NewEventsFacilitator constructs an EventsFacilitator that can process both
// scanning task events and rule-related events. It receives a executionTracker,
// rulesService, taskHealthSupervisor, and tracer so it can delegate domain-specific logic
// to the correct bounded context service and instrument event handling with traces.
func NewEventsFacilitator(
	tracker scansvc.ExecutionTracker,
	taskHealthSupervisor *scansvc.TaskHealthSupervisor,
	rulesSvc rulessvc.Service,
	tracer trace.Tracer,
) *EventsFacilitator {
	return &EventsFacilitator{
		executionTracker:     tracker,
		taskHealthSupervisor: taskHealthSupervisor,
		rulesService:         rulesSvc,
		tracer:               tracer,
	}
}

// withSpan is a helper that centralizes trace creation and error recording.
// TODO: Revist if ack should live in here.
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

	if err := fn(ctx, span); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	return nil
}

// recordPayloadTypeError standardizes error creation and recording
// for invalid event payload types.
func recordPayloadTypeError(span trace.Span, payload interface{}) error {
	err := fmt.Errorf("invalid event payload type: %T", payload)
	span.RecordError(err)
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
		))

		if err := ef.executionTracker.HandleTaskStart(ctx, startedEvt); err != nil {
			return fmt.Errorf("failed to start tracking task: %w", err)
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

		span.AddEvent("task_progressed_event_valid")

		if err := ef.executionTracker.HandleTaskProgress(ctx, progressEvt); err != nil {
			return fmt.Errorf("failed to update progress: %w", err)
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

		span.AddEvent("task_completed_event_valid")

		if err := ef.executionTracker.HandleTaskCompletion(ctx, completedEvt); err != nil {
			return fmt.Errorf("failed to stop tracking task: %w", err)
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

		if err := ef.executionTracker.HandleTaskFailure(ctx, failedEvt); err != nil {
			return fmt.Errorf("failed to fail task: %w", err)
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

		ef.taskHealthSupervisor.HandleHeartbeat(ctx, heartbeatEvt)

		span.AddEvent("task_heartbeat_processed")
		span.SetStatus(codes.Ok, "task heartbeat processed")
		return nil
	}, ack)
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
			return fmt.Errorf("failed to persist rule: %w", err)
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
