package kafka

import (
	"context"
	"time"

	"github.com/ahrav/gitleaks-armada/pkg/domain"
	"github.com/ahrav/gitleaks-armada/pkg/events"
)

// Verify KafkaDomainEventPublisher implements domain.DomainEventPublisher interface.
var _ domain.DomainEventPublisher = (*KafkaDomainEventPublisher)(nil)

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

// PublishDomainEvent sends a domain event with the specified type and payload through
// the Kafka event bus. It automatically adds a timestamp and converts domain-level
// publishing options to event bus options.
func (pub *KafkaDomainEventPublisher) PublishDomainEvent(ctx context.Context, eventType domain.EventType, payload any, domainOpts ...domain.PublishOption) error {
	evt := events.DomainEvent{
		Type:      eventType,
		Timestamp: time.Now(),
		Payload:   payload,
	}

	opts := convertDomainOptionsToEventOptions(domainOpts)

	return pub.eventBus.Publish(ctx, evt, opts...)
}

// convertDomainOptionsToEventOptions transforms domain-level publishing options into
// event bus options. This allows the domain layer to remain decoupled from the
// event bus implementation while preserving configuration like routing keys and headers.
func convertDomainOptionsToEventOptions(domainOpts []domain.PublishOption) []events.PublishOption {
	dp := domain.PublishParams{}
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
