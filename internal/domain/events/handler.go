package events

import "context"

// EventHandler defines the contract for components that process domain events.
// Each handler must declare which event types it can process and implement the
// logic to handle those events. The event dispatcher routes events to the
// appropriate handlers based on the event type.
type EventHandler interface {
	// HandleEvent processes a domain event and returns an error if processing fails.
	HandleEvent(ctx context.Context, evt EventEnvelope, ack AckFunc) error

	// SupportedEvents returns the event types this handler can process.
	SupportedEvents() []EventType
}
