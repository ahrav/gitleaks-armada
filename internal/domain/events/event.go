package events

import "time"

// DomainEvent encapsulates all event data flowing through the system, providing
// a standardized format for event processing and distribution.
type DomainEvent struct {
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
