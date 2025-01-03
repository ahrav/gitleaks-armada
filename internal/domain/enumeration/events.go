package enumeration

import "github.com/ahrav/gitleaks-armada/internal/domain/events"

// Domain event type constants.
// These describe "something happened" in your scanning system.
const (
	EventTypeTaskCreated      events.EventType = "TaskCreated"
	EventTypeTaskBatchCreated events.EventType = "TaskBatchCreated"
)
