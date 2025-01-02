package domain

import "context"

// PublishOption is a function type that modifies PublishParams.
// It enables flexible configuration of event publishing behavior through functional options.
type PublishOption func(*PublishParams)

// PublishParams contains configuration options for publishing domain events.
// It encapsulates parameters that may affect how events are routed and processed.
type PublishParams struct {
	// Key is used as a partition key to control event routing and ordering.
	Key string
	// Headers contain metadata key-value pairs attached to the event.
	Headers map[string]string
}

// DomainEventPublisher defines the contract for publishing domain events.
// It provides a technology-agnostic way to notify other parts of the system about
// important domain changes and activities.
type DomainEventPublisher interface {
	// PublishDomainEvent sends a domain event with the specified type and payload.
	// It accepts optional PublishOptions to configure event routing behavior.
	// The context allows for cancellation and deadline control.
	PublishDomainEvent(ctx context.Context, eventType EventType, payload any, opts ...PublishOption) error
}

// WithKey returns a PublishOption that sets the partition key for event routing.
// The key helps ensure related events are processed in order by the same consumer.
func WithKey(key string) PublishOption {
	return func(p *PublishParams) { p.Key = key }
}

// WithHeaders returns a PublishOption that attaches metadata headers to an event.
// Headers provide additional context and control over event processing.
func WithHeaders(headers map[string]string) PublishOption {
	return func(p *PublishParams) { p.Headers = headers }
}
