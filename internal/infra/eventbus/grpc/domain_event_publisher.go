package grpc

import (
	"context"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
)

var _ events.DomainEventPublisher = (*DomainEventPublisher)(nil)

// DomainEventPublisher is an implementation of the events.DomainEventPublisher interface
// that uses a gRPC-based event bus for communication. This publisher is used by scanners
// to send domain events to the gateway over gRPC, which functions as a bridge to the
// central event system without directly exposing Kafka to on-prem deployments.
type DomainEventPublisher struct {
	eventBus   events.EventBus
	translator *events.DomainEventTranslator
	// Additional fields for metrics, logging, etc. would go here
}

// NewDomainEventPublisher creates a new domain event publisher that uses a gRPC event bus.
func NewDomainEventPublisher(bus events.EventBus, translator *events.DomainEventTranslator) *DomainEventPublisher {
	return &DomainEventPublisher{eventBus: bus, translator: translator}
}

// PublishDomainEvent publishes a domain event to the event bus.
// It first converts the domain event to an event envelope,
// then publishes it to the event bus.
func (pub *DomainEventPublisher) PublishDomainEvent(
	ctx context.Context,
	event events.DomainEvent,
	opts ...events.PublishOption,
) error {
	// Create the event envelope directly.
	envelope := events.EventEnvelope{
		Type:      event.EventType(),
		Timestamp: event.OccurredAt(),
		Payload:   event,
	}

	// Convert domain options to event bus options.
	busOpts := pub.translator.ConvertDomainOptions(opts)

	return pub.eventBus.Publish(ctx, envelope, busOpts...)
}
