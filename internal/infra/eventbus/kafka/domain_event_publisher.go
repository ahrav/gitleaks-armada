package kafka

import (
	"context"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
)

var _ events.DomainEventPublisher = (*DomainEventPublisher)(nil)

// DomainEventPublisher implements the domain.DomainEventPublisher interface using
// Kafka as the underlying message transport. It adapts domain-level events to the
// event bus abstraction for reliable, asynchronous event distribution.
type DomainEventPublisher struct {
	eventBus   events.EventBus
	translator *events.DomainEventTranslator
	// TODO: add logger, metrics, etc.
}

// NewDomainEventPublisher creates a new publisher that will distribute domain
// events through the provided event bus. The event bus handles the actual
// interaction with Kafka.
func NewDomainEventPublisher(bus events.EventBus, translator *events.DomainEventTranslator) *DomainEventPublisher {
	return &DomainEventPublisher{eventBus: bus, translator: translator}
}

// PublishDomainEvent sends a domain event through the Kafka event bus. It automatically
// adds a timestamp and converts domain-level publishing options to event bus options.
func (pub *DomainEventPublisher) PublishDomainEvent(
	ctx context.Context,
	event events.DomainEvent,
	domainOpts ...events.PublishOption,
) error {
	evt := events.EventEnvelope{
		Type:      event.EventType(),
		Timestamp: event.OccurredAt(),
		Payload:   event,
	}

	opts := pub.translator.ConvertDomainOptions(domainOpts)

	return pub.eventBus.Publish(ctx, evt, opts...)
}
