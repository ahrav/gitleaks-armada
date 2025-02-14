// Package enumeration provides commands for managing security enumeration operations.
package enumeration

import (
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/ahrav/gitleaks-armada/internal/config"
	"github.com/ahrav/gitleaks-armada/internal/domain/events"
)

// CommandTypeStartEnumeration represents the event type for initiating a new enumeration operation.
const CommandTypeStartEnumeration events.EventType = "CommandEnumerationStart"

// StartEnumerationCommand encapsulates the parameters for starting enumeration
type StartEnumerationCommand struct {
	id          string
	occurredAt  time.Time
	Config      *config.Config
	RequestedBy string
}

// NewStartEnumerationCommand creates a new enumeration command
func NewStartEnumerationCommand(cfg *config.Config, requestedBy string) StartEnumerationCommand {
	return StartEnumerationCommand{
		id:          uuid.New().String(),
		occurredAt:  time.Now(),
		Config:      cfg,
		RequestedBy: requestedBy,
	}
}

// EventType returns the type identifier for this command
func (c StartEnumerationCommand) EventType() events.EventType { return CommandTypeStartEnumeration }

// OccurredAt returns when this command was created
func (c StartEnumerationCommand) OccurredAt() time.Time { return c.occurredAt }

// CommandID returns the unique identifier for this command
func (c StartEnumerationCommand) CommandID() string { return c.id }

// ValidateCommand ensures all required fields are properly set
func (c StartEnumerationCommand) ValidateCommand() error {
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
