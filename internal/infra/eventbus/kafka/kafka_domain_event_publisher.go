package kafka

import (
	"context"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
)

// Verify KafkaDomainEventPublisher implements domain.DomainEventPublisher interface.
var _ events.DomainEventPublisher = (*KafkaDomainEventPublisher)(nil)

// KafkaDomainEventPublisher implements the domain.DomainEventPublisher interface using
// Kafka as the underlying message transport. It adapts domain-level events to the
// event bus abstraction for reliable, asynchronous event distribution.
type KafkaDomainEventPublisher struct {
	eventBus events.EventBus
	// TODO: add logger, metrics, etc.
}

// NewKafkaDomainEventPublisher creates a new publisher that will distribute domain
// events through the provided event bus. The event bus handles the actual
// interaction with Kafka.
func NewKafkaDomainEventPublisher(eventBus events.EventBus) *KafkaDomainEventPublisher {
	return &KafkaDomainEventPublisher{eventBus: eventBus}
}

// PublishDomainEvent sends a domain event through the Kafka event bus. It automatically
// adds a timestamp and converts domain-level publishing options to event bus options.
func (pub *KafkaDomainEventPublisher) PublishDomainEvent(ctx context.Context, event events.DomainEvent, domainOpts ...events.PublishOption) error {
	evt := events.EventEnvelope{
		Type:      event.EventType(),
		Timestamp: event.OccurredAt(),
		Payload:   event,
	}

	opts := convertDomainOptionsToEventOptions(domainOpts)

	return pub.eventBus.Publish(ctx, evt, opts...)
}

// convertDomainOptionsToEventOptions transforms domain-level publishing options into
// event bus options. This allows the domain layer to remain decoupled from the
// event bus implementation while preserving configuration like routing keys and headers.
func convertDomainOptionsToEventOptions(domainOpts []events.PublishOption) []events.PublishOption {
	dp := events.PublishParams{}
	for _, dOpt := range domainOpts {
		dOpt(&dp)
	}

	var eventOpts []events.PublishOption
	if dp.Key != "" {
		eventOpts = append(eventOpts, events.WithKey(dp.Key))
	}
	if len(dp.Headers) > 0 {
		eventOpts = append(eventOpts, events.WithHeaders(dp.Headers))
	}

	return eventOpts
}
