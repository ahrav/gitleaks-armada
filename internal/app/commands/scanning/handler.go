package scanning

import (
	"context"
	"errors"

	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/app/commands"
	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

// CommandHandler processes scanning-related commands and publishes corresponding domain events.
// It implements the command handling pattern for the scanning domain.
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

// Handle processes incoming scanning commands and routes them to appropriate handlers.
// It returns an error if the command type is unknown or if processing fails.
func (h *CommandHandler) Handle(ctx context.Context, cmd commands.Command) error {
	ctx, span := h.tracer.Start(ctx, "scanning.CommandHandler.Handle")
	defer span.End()

	switch c := cmd.(type) {
	case StartScanCommand:
		return h.handleStartScan(ctx, c)
	default:
		h.logger.Error(ctx, "unknown command type",
			"type", cmd.EventType(),
			"command_id", cmd.CommandID(),
		)
		return errors.New("unknown command type")
	}
}

// handleStartScan processes a StartScanCommand by validating it and publishing
// a scan requested event to the event bus.
func (h *CommandHandler) handleStartScan(ctx context.Context, cmd StartScanCommand) error {
	if err := cmd.ValidateCommand(); err != nil {
		h.logger.Error(ctx, "invalid scan command",
			"error", err,
			"command_id", cmd.CommandID(),
		)
		return err
	}

	// Create and publish event for the validated scan request.
	evt := scanning.NewScanRequestedEvent(
		cmd.Name,
		string(cmd.SourceType),
		cmd.Target,
		cmd.RequestedBy,
	)

	if err := h.eventBus.PublishDomainEvent(ctx, evt); err != nil {
		h.logger.Error(ctx, "failed to publish scan requested event",
			"error", err,
			"command_id", cmd.CommandID(),
		)
		return err
	}

	h.logger.Info(ctx, "scan requested",
		"command_id", cmd.CommandID(),
		"name", cmd.Name,
		"source_type", cmd.SourceType,
		"requested_by", cmd.RequestedBy,
	)

	return nil
}
