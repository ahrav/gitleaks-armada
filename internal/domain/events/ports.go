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

// DomainOffsetCommitter is used to commit the position of the last event processed.
// This is used to track the position of the last event processed so that we
// can replay events from the same position.
// This is useful for recovering from a system failure or for resuming from a
// specific point in the event stream.
type DomainOffsetCommitter interface {
	// CommitPosition commits the position of the last event processed.
	CommitPosition(ctx context.Context, position DomainPosition) error
}

// OffsetCommitter is used to commit the position of the last event processed.
// This is used to track the position of the last event processed so that we
// can replay events from the same position.
// This is useful for recovering from a system failure or for resuming from a
type OffsetCommitter interface {
	// CommitPosition signals that we've successfully processed
	// everything up to 'pos' in the domain stream.
	CommitPosition(ctx context.Context, pos StreamPosition) error

	// Close closes the offset committer and releases associated resources.
	Close() error
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
