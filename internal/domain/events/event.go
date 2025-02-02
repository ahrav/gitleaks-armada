package events

import (
	"context"
	"time"
)

// EventEnvelope encapsulates all event data flowing through the system, providing
// a standardized format for event processing and distribution.
// TODO: Come around and remove this.
type EventEnvelope struct {
	// Type identifies the category of this event for routing and handling.
	Type EventType

	// Key enables consistent event routing, typically containing a business identifier
	// like a TaskID that events can be grouped or partitioned by.
	Key string

	// Headers contain metadata key-value pairs attached to the event.
	Headers map[string]string

	// Timestamp records when this event was created, enabling temporal tracking
	// and debugging of event flows.
	Timestamp time.Time

	// Payload contains the actual event data (e.g., Task, ScanProgress).
	// The concrete type depends on the EventType.
	Payload any

	// Metadata contains transport-specific information about the event.
	Metadata EventMetadata
}

// EventMetadata contains transport-specific information about the event.
type EventMetadata struct {
	Partition int32
	Offset    int64
}

// DomainEvent is the interface that *all* strongly typed domain events implement.
// Each event has an event type and an occurrence timestamp.
type DomainEvent interface {
	// EventType returns a constant that identifies the kind of event (e.g., "TaskCreated").
	EventType() EventType

	// OccurredAt returns when this event happened in the domain.
	OccurredAt() time.Time
}

// PositionMetadata contains metadata about the position of an event in the event stream.
type PositionMetadata struct {
	// EntityType is the type of entity this position is for (e.g. "job_metrics", "task_progress").
	EntityType StreamType
	// EntityID is an opaque identifier for this position.
	EntityID string
}

// DomainPosition represents a unique position in a domain event stream.
// It is used to identify the position of an event in the event stream.
type DomainPosition interface {
	// StreamType returns the type of entity this position is for (e.g. "job_metrics", "task_progress").
	StreamType() StreamType
	// StreamID returns an opaque identifier for this position.
	StreamID() string
}

// StreamPosition represents a unique position in an event stream
// from which replay can begin. The exact meaning of the position
// is specific to each message bus implementation.
type StreamPosition interface {
	// Identifier returns a unique identifier for this position
	// in the event stream
	Identifier() string

	// Validate checks if this position is valid
	// Returns an error if the position is invalid for this implementation
	Validate() error
}

// AckFunc is a function that can be used to acknowledge an event.
type AckFunc func(error)

// HandlerFunc is a function that can be used to handle an event.
// It is passed an AckFunc that can be used to acknowledge the event asynchronously.
type HandlerFunc func(ctx context.Context, evt EventEnvelope, ack AckFunc) error
