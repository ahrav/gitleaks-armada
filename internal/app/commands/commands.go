package commands

import (
	"context"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
)

// Handler defines the interface for processing commands
type Handler interface {
	Handle(ctx context.Context, cmd Command) error
}

// Command represents a base command interface
type Command interface {
	events.DomainEvent // Reuse event interface for type/occurred at
	CommandID() string
	ValidateCommand() error
}
