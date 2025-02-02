// Package events provides domain event handling capabilities for communicating state changes
// and important activities across system boundaries in a decoupled way.
package events

import (
	"context"
)

// DomainEventPublisher publishes domain events to notify other parts of the system about
// important domain changes. It provides a technology-agnostic interface to decouple event
// producers from the underlying messaging infrastructure.
type DomainEventPublisher interface {
	// PublishDomainEvent sends a domain event to interested subscribers. The provided context
	// controls cancellation and deadlines. Optional PublishOptions configure routing behavior.
	// Returns an error if publishing fails.
	PublishDomainEvent(ctx context.Context, event DomainEvent, opts ...PublishOption) error
}

// EventBus enables publishing and subscribing to domain events across system boundaries.
// It abstracts messaging infrastructure details (like Kafka or RabbitMQ) to keep domain
// logic focused on business concerns rather than transport mechanisms.
type EventBus interface {
	// Publish broadcasts a domain event to all interested subscribers. The provided context
	// controls the operation lifecycle. Optional PublishOptions configure delivery behavior.
	// Returns an error if publishing fails.
	Publish(ctx context.Context, event EventEnvelope, opts ...PublishOption) error

	// Subscribe registers a handler function to process events of specified types.
	// The handler executes for each matching event received on this bus.
	// Returns an error if subscription setup fails.
	Subscribe(ctx context.Context, eventTypes []EventType, handler HandlerFunc) error

	// Close gracefully shuts down the event bus and releases associated resources.
	// This should be called during system shutdown to prevent resource leaks.
	Close() error
}

// PositionTranslator translates position metadata into a messaging system-specific position.
type PositionTranslator interface {
	// ToStreamPosition converts position metadata into a messaging system-specific position.
	ToStreamPosition(metadata PositionMetadata) (StreamPosition, error)
}

// DomainEventReplayer enables replaying domain events from a specific position in the event stream.
type DomainEventReplayer interface {
	// ReplayFromPosition replays domain events from a specific position in the event stream.
	ReplayFromPosition(ctx context.Context, position DomainPosition) (<-chan EventEnvelope, error)
}

// EventReplayer enables replaying events from a specific position in the event stream.
type EventReplayer interface {
	// ReplayEvents replays events from a specific position
	// Returns a channel of events to allow for streaming processing
	ReplayEvents(ctx context.Context, position StreamPosition) (<-chan EventEnvelope, error)

	// Close the replayer and release associated resources.
	Close() error
}
