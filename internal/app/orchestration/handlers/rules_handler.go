package handlers

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	rulessvc "github.com/ahrav/gitleaks-armada/internal/app/rules"
	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/domain/rules"
)

// RulesHandler processes all events related to scanning rules.
// It follows Domain-Driven Design principles by coordinating domain events
// between the rules domain and other bounded contexts.
type RulesHandler struct {
	// controllerID uniquely identifies the controller running this handler.
	controllerID string

	// rulesService persists and retrieves rules from the database.
	rulesService rulessvc.Service

	// tracer instruments method calls with OpenTelemetry spans for distributed tracing.
	tracer trace.Tracer
}

// NewRulesHandler creates a new RulesHandler with the provided dependencies.
func NewRulesHandler(
	controllerID string,
	rulesService rulessvc.Service,
	tracer trace.Tracer,
) *RulesHandler {
	return &RulesHandler{
		controllerID: controllerID,
		rulesService: rulesService,
		tracer:       tracer,
	}
}

// HandleEvent implements the events.EventHandler interface.
// It routes events to the appropriate handler based on the event type.
func (h *RulesHandler) HandleEvent(
	ctx context.Context,
	evt events.EventEnvelope,
	ack events.AckFunc,
) error {
	switch evt.Type {
	case rules.EventTypeRulesUpdated:
		return h.HandleRule(ctx, evt, ack)
	case rules.EventTypeRulesPublished:
		return h.HandleRulesPublished(ctx, evt, ack)
	default:
		return fmt.Errorf("unsupported event type: %s", evt.Type)
	}
}

// SupportedEvents implements the events.EventHandler interface.
// It returns the list of event types this handler supports.
func (h *RulesHandler) SupportedEvents() []events.EventType {
	return []events.EventType{
		rules.EventTypeRulesUpdated,
		rules.EventTypeRulesPublished,
	}
}

// withSpan creates a new trace span, executes the given function, records any errors,
// and ends the span. If no error occurs, it automatically acknowledges the event.
func (h *RulesHandler) withSpan(
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
func recordRulesPayloadTypeError(span trace.Span, payload any) error {
	err := fmt.Errorf("invalid event payload type: %T", payload)
	span.RecordError(err)
	span.SetAttributes(
		attribute.String("actual_type", fmt.Sprintf("%T", payload)),
	)
	span.SetStatus(codes.Error, "invalid event payload type")
	return err
}

// HandleRule processes a rules.RuleUpdatedEvent, calling rulesService.SaveRule
// to persist the updated rule.
func (h *RulesHandler) HandleRule(
	ctx context.Context,
	evt events.EventEnvelope,
	ack events.AckFunc,
) error {
	return h.withSpan(ctx, "rules_handler.handle_rule", func(ctx context.Context, span trace.Span) error {
		span.AddEvent("processing_rule_update")

		ruleEvt, ok := evt.Payload.(rules.RuleUpdatedEvent)
		if !ok {
			return recordRulesPayloadTypeError(span, evt.Payload)
		}

		if err := h.rulesService.SaveRule(ctx, ruleEvt.Rule.GitleaksRule); err != nil {
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
func (h *RulesHandler) HandleRulesPublished(
	ctx context.Context,
	evt events.EventEnvelope,
	ack events.AckFunc,
) error {
	return h.withSpan(ctx, "rules_handler.handle_rules_published", func(ctx context.Context, span trace.Span) error {
		span.AddEvent("processing_rules_published")

		if _, ok := evt.Payload.(rules.RulePublishingCompletedEvent); !ok {
			return recordRulesPayloadTypeError(span, evt.Payload)
		}

		span.AddEvent("rules_update_completed")
		span.SetStatus(codes.Ok, "rules update completed")
		return nil
	}, ack)
}
