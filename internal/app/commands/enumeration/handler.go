package enumeration

import (
	"context"
	"errors"

	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/app/commands"
	"github.com/ahrav/gitleaks-armada/internal/domain/enumeration"
	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

// CommandHandler processes enumeration-related commands and publishes corresponding domain events.
// It implements the command handling pattern for the enumeration domain.
type CommandHandler struct {
	logger   *logger.Logger
	tracer   trace.Tracer
	eventBus events.DomainEventPublisher
}

// NewCommandHandler creates a new instance of CommandHandler with the required dependencies
// for logging, tracing, and event publishing.
func NewCommandHandler(logger *logger.Logger, tracer trace.Tracer, eventBus events.DomainEventPublisher) *CommandHandler {
	return &CommandHandler{
		logger:   logger,
		tracer:   tracer,
		eventBus: eventBus,
	}
}

// Handle processes incoming enumeration commands and routes them to appropriate handlers.
// It returns an error if the command type is unknown or if processing fails.
func (h *CommandHandler) Handle(ctx context.Context, cmd commands.Command) error {
	ctx, span := h.tracer.Start(ctx, "enumeration.CommandHandler.Handle")
	defer span.End()

	switch c := cmd.(type) {
	case StartEnumerationCommand:
		return h.handleStartEnumeration(ctx, c)
	default:
		h.logger.Error(ctx, "unknown command type",
			"type", cmd.EventType(),
			"command_id", cmd.CommandID(),
		)
		return errors.New("unknown command type")
	}
}

// handleStartEnumeration processes a StartEnumerationCommand by validating the config
// and publishing an enumeration requested event.
func (h *CommandHandler) handleStartEnumeration(ctx context.Context, cmd StartEnumerationCommand) error {
	if err := cmd.ValidateCommand(); err != nil {
		h.logger.Error(ctx, "invalid enumeration command",
			"error", err,
			"command_id", cmd.CommandID(),
		)
		return err
	}

	evt := enumeration.NewEnumerationRequestedEvent(cmd.Config, cmd.RequestedBy)
	if err := h.eventBus.PublishDomainEvent(ctx, evt); err != nil {
		h.logger.Error(ctx, "failed to publish enumeration requested event",
			"error", err,
			"command_id", cmd.CommandID(),
		)
		return err
	}

	h.logger.Info(ctx, "enumeration requested", "command_id", cmd.CommandID(), "requested_by", cmd.RequestedBy)

	return nil
}
