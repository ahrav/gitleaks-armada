package events

import (
	"context"
	"time"
)

// EventType represents a domain event category, enabling type-safe event routing and handling.
// It allows the system to distinguish between different kinds of events like task creation,
// scan progress updates, and rule changes.
type EventType string

// DomainEvent encapsulates all event data flowing through the system, providing
// a standardized format for event processing and distribution.
type DomainEvent struct {
	// Type identifies the category of this event for routing and handling.
	Type EventType

	// Key enables consistent event routing, typically containing a business identifier
	// like a TaskID that events can be grouped or partitioned by.
	Key string

	// Timestamp records when this event was created, enabling temporal tracking
	// and debugging of event flows.
	Timestamp time.Time

	// Payload contains the actual event data (e.g., Task, ScanProgress).
	// The concrete type depends on the EventType.
	Payload any
}

// PublishOption is a function type that modifies PublishOptions, enabling a flexible
// and extensible way to configure event publishing behavior.
type PublishOption func(*PublishOptions)

// PublishOptions contains configuration settings for event publishing.
// It allows specifying routing keys and metadata headers to control how events
// are processed by the underlying message transport.
type PublishOptions struct {
	// Key determines message routing in the transport layer.
	Key string
	// Headers contain metadata key-value pairs attached to the event.
	Headers map[string]string
}

// WithKey returns a PublishOption that sets the routing key for an event.
// The key helps ensure related events are processed consistently.
func WithKey(key string) PublishOption {
	return func(opts *PublishOptions) { opts.Key = key }
}

// WithHeaders returns a PublishOption that attaches metadata headers to an event.
// Headers provide additional context and control over event processing.
func WithHeaders(headers map[string]string) PublishOption {
	return func(opts *PublishOptions) { opts.Headers = headers }
}

// EventBus defines the contract for publishing and subscribing to domain events.
// It abstracts the underlying message transport (e.g., Kafka, GCP Pub/Sub, RabbitMQ)
// to keep business logic independent of specific messaging implementations.
type EventBus interface {
	// Publish sends a domain event to all interested subscribers.
	// It accepts optional configuration via PublishOptions.
	// Returns an error if publishing fails.
	Publish(ctx context.Context, event DomainEvent, opts ...PublishOption) error

	// Subscribe registers a handler for processing events of specified types.
	// The handler is called for each matching event received.
	// Returns an error if subscription setup fails.
	Subscribe(ctx context.Context, eventTypes []EventType, handler func(context.Context, DomainEvent) error) error

	// Close cleanly shuts down the event bus, releasing all associated resources.
	// This should be called when the event bus is no longer needed.
	Close() error
}
