package events

import (
	"context"
)

// DomainEventPublisher defines the contract for publishing domain events.
// It provides a technology-agnostic way to notify other parts of the system about
// important domain changes and activities.
type DomainEventPublisher interface {
	// PublishDomainEvent sends a domain event with the specified type and payload.
	// It accepts optional PublishOptions to configure event routing behavior.
	// The context allows for cancellation and deadline control.
	PublishDomainEvent(ctx context.Context, eventType EventType, payload any, opts ...PublishOption) error
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
