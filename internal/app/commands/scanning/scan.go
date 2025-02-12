package scanning

import (
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/ahrav/gitleaks-armada/internal/config"
	"github.com/ahrav/gitleaks-armada/internal/domain/events"
)

const CommandTypeStartScan events.EventType = "Command.Scan.Start"

type StartScanCommand struct {
	id          string
	occurredAt  time.Time
	Name        string
	SourceType  config.SourceType
	Auth        config.AuthConfig
	Target      config.TargetSpec
	RequestedBy string
}

func NewStartScan(name string, sourceType config.SourceType, auth config.AuthConfig, target config.TargetSpec, requestedBy string) StartScanCommand {
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

func (c StartScanCommand) EventType() events.EventType { return CommandTypeStartScan }
func (c StartScanCommand) OccurredAt() time.Time       { return c.occurredAt }
func (c StartScanCommand) CommandID() string           { return c.id }
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
