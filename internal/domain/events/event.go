package events

import "time"

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
}

// DomainEvent is the interface that *all* strongly typed domain events implement.
// Each event has an event type and an occurrence timestamp.
type DomainEvent interface {
	// EventType returns a constant that identifies the kind of event (e.g., "TaskCreated").
	EventType() EventType

	// OccurredAt returns when this event happened in the domain.
	OccurredAt() time.Time
}
