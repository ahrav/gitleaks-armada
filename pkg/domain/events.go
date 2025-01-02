package domain

// EventType represents a domain event category, enabling type-safe event routing and handling.
// It allows the system to distinguish between different kinds of events like task creation,
// scan progress updates, and rule changes.
type EventType string

// Domain event type constants.
// These describe "something happened" in your scanning system.
const (
	EventTypeTaskCreated         EventType = "TaskCreated"
	EventTypeTaskBatchCreated    EventType = "TaskBatchCreated"
	EventTypeRuleUpdated         EventType = "RuleUpdated"
	EventTypeScanProgressUpdated EventType = "ScanProgressUpdated"
	EventTypeScanResultReceived  EventType = "ScanResultReceived"
	// e.g. "TaskCompleted", "TaskFailed", etc. if desired
)
