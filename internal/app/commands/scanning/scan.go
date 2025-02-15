// Package scanning provides commands for managing security scanning operations.
package scanning

import (
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/ahrav/gitleaks-armada/internal/config"
	"github.com/ahrav/gitleaks-armada/internal/domain/events"
)

// CommandTypeStartScan represents the event type for initiating a new scan operation.
const CommandTypeStartScan events.EventType = "CommandScanStart"

// StartScanCommand encapsulates the parameters for starting a scan
type StartScanCommand struct {
	id          string
	occurredAt  time.Time
	Config      *config.Config
	RequestedBy string
}

// NewStartScanCommand creates a new scan command.
func NewStartScanCommand(cfg *config.Config, requestedBy string) StartScanCommand {
	return StartScanCommand{
		id:          uuid.New().String(),
		occurredAt:  time.Now(),
		Config:      cfg,
		RequestedBy: requestedBy,
	}
}

// EventType returns the type identifier for this command.
func (c StartScanCommand) EventType() events.EventType { return CommandTypeStartScan }

// OccurredAt returns when this command was created.
func (c StartScanCommand) OccurredAt() time.Time { return c.occurredAt }

// CommandID returns the unique identifier for this command.
func (c StartScanCommand) CommandID() string { return c.id }

// ValidateCommand ensures all required fields are properly set.
func (c StartScanCommand) ValidateCommand() error {
	if c.Config == nil {
		return errors.New("config is required")
	}
	if len(c.Config.Targets) == 0 {
		return errors.New("at least one target is required")
	}
	if c.RequestedBy == "" {
		return errors.New("requestedBy is required")
	}
	return nil
}
