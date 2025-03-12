package protocol

import "github.com/ahrav/gitleaks-armada/internal/domain/events"

// EventType constants specific to gRPC communication infrastructure.
// These are deliberately kept in the infrastructure layer rather than the domain layer
// because they represent implementation details of the messaging system, not domain concepts.
const (
	// EventTypeMessageAck represents an acknowledgment message for critical events.
	EventTypeMessageAck events.EventType = "MessageAck"

	// EventTypeScannerRegistrationAck represents a scanner registration acknowledgment.
	EventTypeScannerRegistrationAck events.EventType = "ScannerRegistrationAck"

	// EventTypeSystemNotification represents a system-wide notification message.
	EventTypeSystemNotification events.EventType = "SystemNotification"
)
