package grpc

import (
	"context"
	"errors"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

// DomainEventHandler provides a way to handle domain events received from the gRPC event bus.
// It routes incoming events to the appropriate domain handlers.
type DomainEventHandler struct {
	eventBus   events.EventBus
	translator *events.DomainEventTranslator
	logger     *logger.Logger
}

// NewDomainEventHandler creates a new domain event handler that uses a gRPC event bus.
func NewDomainEventHandler(
	bus events.EventBus,
	translator *events.DomainEventTranslator,
	logger *logger.Logger,
) *DomainEventHandler {
	return &DomainEventHandler{eventBus: bus, translator: translator, logger: logger}
}

// RegisterHandler registers a handler function to be called when events of the given type are received.
// This adapts between the general event bus subscription and domain-specific handler functions.
func (h *DomainEventHandler) RegisterHandler(
	ctx context.Context,
	eventType events.EventType,
	handler func(ctx context.Context, event events.DomainEvent) error,
) error {
	// Define a subscription callback that will transform events to domain events
	callback := func(ctx context.Context, envelope events.EventEnvelope, ack events.AckFunc) error {
		// Extract the domain event from the envelope payload
		domainEvent, ok := envelope.Payload.(events.DomainEvent)
		if !ok {
			err := errors.New("envelope payload is not a domain event")
			h.logger.Error(ctx, "Failed to convert payload to domain event",
				"event_type", envelope.Type,
				"error", err)
			ack(err)
			return err
		}

		// Important: routing keys and headers are preserved during message transformation
		// in the processIncomingMessage method, which extracts them from the message
		// and sets them on the event envelope before passing it to handlers.

		// Call the domain event handler.
		err := handler(ctx, domainEvent)

		// When processing the ack, we preserve all routing keys and headers
		// for proper message forwarding.
		ack(err)
		return err
	}

	// Subscribe to the event bus for this event type
	return h.eventBus.Subscribe(ctx, []events.EventType{eventType}, callback)
}

// Shutdown gracefully closes all subscriptions and resources.
func (h *DomainEventHandler) Shutdown(ctx context.Context) error {
	// Close the underlying event bus connection
	return h.eventBus.Close()
}
