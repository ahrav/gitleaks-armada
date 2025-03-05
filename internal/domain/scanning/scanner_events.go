package scanning

import (
	"time"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/pkg/common/uuid"
)

// Event types for scanner registration and lifecycle management.
const (
	// EventTypeScannerRegistered represents the event when a scanner registers itself with the system.
	EventTypeScannerRegistered events.EventType = "ScannerRegistered"

	// EventTypeScannerHeartbeat represents a periodic heartbeat from a scanner to indicate it's still alive.
	EventTypeScannerHeartbeat events.EventType = "ScannerHeartbeat"

	// EventTypeScannerStatusChanged represents a change in scanner status (online, offline, etc.).
	EventTypeScannerStatusChanged events.EventType = "ScannerStatusChanged"

	// EventTypeScannerDeregistered represents the event when a scanner gracefully deregisters from the system.
	EventTypeScannerDeregistered events.EventType = "ScannerDeregistered"
)

// ScannerRegisteredEvent is emitted when a scanner registers with the system.
// It contains all information needed to identify and track the scanner.
type ScannerRegisteredEvent struct {
	scannerID     uuid.UUID
	name          string
	version       string
	capabilities  []string
	groupName     string // Optional: if not provided, assigned to default group
	hostname      string
	ipAddress     string
	tags          map[string]string
	initialStatus ScannerStatus
	occurredAt    time.Time
}

// NewScannerRegisteredEvent creates a new scanner registration event.
func NewScannerRegisteredEvent(
	scannerID uuid.UUID,
	name string,
	version string,
	capabilities []string,
	hostname string,
	ipAddress string,
	groupName string,
	tags map[string]string,
	initialStatus ScannerStatus,
) ScannerRegisteredEvent {
	return ScannerRegisteredEvent{
		occurredAt:    time.Now().UTC(),
		scannerID:     scannerID,
		name:          name,
		version:       version,
		capabilities:  capabilities,
		groupName:     groupName,
		hostname:      hostname,
		ipAddress:     ipAddress,
		tags:          tags,
		initialStatus: initialStatus,
	}
}

// EventType returns the type of this event.
func (e ScannerRegisteredEvent) EventType() events.EventType { return EventTypeScannerRegistered }

// OccurredAt returns when this event occurred.
func (e ScannerRegisteredEvent) OccurredAt() time.Time { return e.occurredAt }

// ScannerID returns the unique identifier for the scanner.
func (e ScannerRegisteredEvent) ScannerID() uuid.UUID { return e.scannerID }

// Name returns the scanner's name.
func (e ScannerRegisteredEvent) Name() string { return e.name }

// Version returns the scanner's software version.
func (e ScannerRegisteredEvent) Version() string { return e.version }

// Capabilities returns the scanner's capabilities.
func (e ScannerRegisteredEvent) Capabilities() []string { return e.capabilities }

// GroupName returns the scanner's group name.
func (e ScannerRegisteredEvent) GroupName() string { return e.groupName }

// Hostname returns the scanner's hostname.
func (e ScannerRegisteredEvent) Hostname() string { return e.hostname }

// IPAddress returns the scanner's IP address.
func (e ScannerRegisteredEvent) IPAddress() string { return e.ipAddress }

// Tags returns the scanner's metadata tags.
func (e ScannerRegisteredEvent) Tags() map[string]string { return e.tags }

// InitialStatus returns the scanner's initial status.
func (e ScannerRegisteredEvent) InitialStatus() ScannerStatus { return e.initialStatus }

// ScannerHeartbeatEvent is emitted periodically by scanners to indicate they're still alive.
type ScannerHeartbeatEvent struct {
	occurredAt time.Time
	scannerID  uuid.UUID
	status     ScannerStatus
	metrics    map[string]float64 // Optional metrics about scanner health/performance
}

// NewScannerHeartbeatEvent creates a new scanner heartbeat event.
func NewScannerHeartbeatEvent(
	scannerID uuid.UUID,
	status ScannerStatus,
	metrics map[string]float64,
) ScannerHeartbeatEvent {
	return ScannerHeartbeatEvent{
		occurredAt: time.Now().UTC(),
		scannerID:  scannerID,
		status:     status,
		metrics:    metrics,
	}
}

// EventType returns the type of this event.
func (e ScannerHeartbeatEvent) EventType() events.EventType { return EventTypeScannerHeartbeat }

// OccurredAt returns when this event occurred.
func (e ScannerHeartbeatEvent) OccurredAt() time.Time { return e.occurredAt }

// ScannerID returns the unique identifier for the scanner.
func (e ScannerHeartbeatEvent) ScannerID() uuid.UUID { return e.scannerID }

// Status returns the scanner's current status.
func (e ScannerHeartbeatEvent) Status() ScannerStatus { return e.status }

// Metrics returns the scanner's metrics.
func (e ScannerHeartbeatEvent) Metrics() map[string]float64 { return e.metrics }

// ScannerStatusChangedEvent is emitted when a scanner's status changes.
type ScannerStatusChangedEvent struct {
	occurredAt     time.Time
	scannerID      uuid.UUID
	newStatus      ScannerStatus
	previousStatus ScannerStatus
	reason         string // Reason for the status change
}

// NewScannerStatusChangedEvent creates a new scanner status changed event.
func NewScannerStatusChangedEvent(
	scannerID uuid.UUID,
	newStatus ScannerStatus,
	previousStatus ScannerStatus,
	reason string,
) ScannerStatusChangedEvent {
	return ScannerStatusChangedEvent{
		occurredAt:     time.Now().UTC(),
		scannerID:      scannerID,
		newStatus:      newStatus,
		previousStatus: previousStatus,
		reason:         reason,
	}
}

// EventType returns the type of this event.
func (e ScannerStatusChangedEvent) EventType() events.EventType { return EventTypeScannerStatusChanged }

// OccurredAt returns when this event occurred.
func (e ScannerStatusChangedEvent) OccurredAt() time.Time { return e.occurredAt }

// ScannerID returns the unique identifier for the scanner.
func (e ScannerStatusChangedEvent) ScannerID() uuid.UUID { return e.scannerID }

// NewStatus returns the scanner's new status.
func (e ScannerStatusChangedEvent) NewStatus() ScannerStatus { return e.newStatus }

// PreviousStatus returns the scanner's previous status.
func (e ScannerStatusChangedEvent) PreviousStatus() ScannerStatus { return e.previousStatus }

// Reason returns the reason for the status change.
func (e ScannerStatusChangedEvent) Reason() string { return e.reason }

// ScannerDeregisteredEvent is emitted when a scanner gracefully deregisters from the system.
type ScannerDeregisteredEvent struct {
	occurredAt time.Time
	scannerID  uuid.UUID
	reason     string
}

// NewScannerDeregisteredEvent creates a new scanner deregistration event.
func NewScannerDeregisteredEvent(
	scannerID uuid.UUID,
	reason string,
) ScannerDeregisteredEvent {
	return ScannerDeregisteredEvent{occurredAt: time.Now().UTC(), scannerID: scannerID, reason: reason}
}

// EventType returns the type of this event.
func (e ScannerDeregisteredEvent) EventType() events.EventType { return EventTypeScannerDeregistered }

// OccurredAt returns when this event occurred.
func (e ScannerDeregisteredEvent) OccurredAt() time.Time { return e.occurredAt }

// ScannerID returns the unique identifier for the scanner.
func (e ScannerDeregisteredEvent) ScannerID() uuid.UUID { return e.scannerID }

// Reason returns the reason for deregistration.
func (e ScannerDeregisteredEvent) Reason() string { return e.reason }
