// Package scanning provides commands for managing security scan operations.
package scanning

import (
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/ahrav/gitleaks-armada/internal/config"
	"github.com/ahrav/gitleaks-armada/internal/domain/events"
)

// CommandTypeStartScan represents the event type for initiating a new scan operation.
const CommandTypeStartScan events.EventType = "Command.Scan.Start"

// StartScanCommand encapsulates the parameters and metadata required to initiate
// a scan operation. It maintains scan configuration, authentication details,
// and tracking information for audit purposes.
type StartScanCommand struct {
	id          string
	occurredAt  time.Time
	Name        string            // Unique identifier for the scan operation
	SourceType  config.SourceType // Type of repository source (e.g., GitHub, GitLab)
	Auth        config.AuthConfig // Authentication configuration for source access
	Target      config.TargetSpec // Specification of the scan target
	RequestedBy string            // Identity of the user/system initiating the scan
}

// NewStartScan creates a new scan command with a unique identifier and timestamp.
// It initializes all required fields for starting a scan operation.
func NewStartScan(
	name string,
	sourceType config.SourceType,
	auth config.AuthConfig,
	target config.TargetSpec,
	requestedBy string,
) StartScanCommand {
	return StartScanCommand{
		id:          uuid.New().String(),
		occurredAt:  time.Now(),
		Name:        name,
		SourceType:  sourceType,
		Auth:        auth,
		Target:      target,
		RequestedBy: requestedBy,
	}
}

// EventType returns the type identifier for this command.
func (c StartScanCommand) EventType() events.EventType { return CommandTypeStartScan }

// OccurredAt returns the timestamp when this command was created.
func (c StartScanCommand) OccurredAt() time.Time { return c.occurredAt }

// CommandID returns the unique identifier for this command instance.
func (c StartScanCommand) CommandID() string { return c.id }

// ValidateCommand ensures all required fields are properly set before
// the scan command can be executed.
func (c StartScanCommand) ValidateCommand() error {
	if c.Name == "" {
		return errors.New("name is required")
	}
	if c.SourceType == "" {
		return errors.New("source type is required")
	}
	if c.Target.Name == "" {
		return errors.New("target is required")
	}
	return nil
}
