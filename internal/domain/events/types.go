package events

// EventType represents a domain event category, enabling type-safe event routing and handling.
// It allows the system to distinguish between different kinds of events like task creation,
// scan progress updates, and rule changes.
type EventType string

// Domain event type constants.
// These describe "something happened" in your scanning system.
const (
	EventTypeScanProgressUpdated EventType = "ScanProgressUpdated"
	EventTypeScanResultReceived  EventType = "ScanResultReceived"
	// e.g. "TaskCompleted", "TaskFailed", etc. if desired
)

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
