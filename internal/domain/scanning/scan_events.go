package scanning

import (
	"time"

	"github.com/google/uuid"

	"github.com/ahrav/gitleaks-armada/internal/config"
	"github.com/ahrav/gitleaks-armada/internal/domain/events"
)

const (
	EventTypeScanRequested events.EventType = "ScanRequested"
)

// ScanRequestedEvent represents the initial request to start a scan.
type ScanRequestedEvent struct {
	id          string
	occurredAt  time.Time
	Name        string
	SourceType  string
	Target      config.TargetSpec
	RequestedBy string
}

// NewScanRequestedEvent creates a new ScanRequestedEvent.
func NewScanRequestedEvent(name string, sourceType string, target config.TargetSpec, requestedBy string) ScanRequestedEvent {
	return ScanRequestedEvent{
		id:          uuid.New().String(),
		occurredAt:  time.Now(),
		Name:        name,
		SourceType:  sourceType,
		Target:      target,
		RequestedBy: requestedBy,
	}
}

func (e ScanRequestedEvent) EventType() events.EventType { return EventTypeScanRequested }
func (e ScanRequestedEvent) OccurredAt() time.Time       { return e.occurredAt }
func (e ScanRequestedEvent) EventID() string             { return e.id }
