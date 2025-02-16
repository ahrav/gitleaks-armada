package scanning

import (
	"context"
	"errors"

	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/app/commands"
	"github.com/ahrav/gitleaks-armada/internal/config"
	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
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

// handleStartScan processes a StartScanCommand by validating the config
// and publishing a job requested event.
func (h *CommandHandler) handleStartScan(ctx context.Context, cmd StartScanCommand) error {
	if err := cmd.ValidateCommand(); err != nil {
		h.logger.Error(ctx, "invalid enumeration command",
			"error", err,
			"command_id", cmd.CommandID(),
		)
		return err
	}

	// Convert config types to domain types.
	targets := make([]scanning.Target, 0, len(cmd.Config.Targets))

	for _, targetCfg := range cmd.Config.Targets {
		targets = append(targets, configToDomainTarget(targetCfg))
	}

	evt := scanning.NewJobRequestedEvent(targets, cmd.RequestedBy)
	if err := h.eventBus.PublishDomainEvent(ctx, evt); err != nil {
		h.logger.Error(ctx, "failed to publish job requested event",
			"error", err,
			"command_id", cmd.CommandID(),
		)
		return err
	}

	h.logger.Info(ctx, "job requested", "command_id", cmd.CommandID(), "requested_by", cmd.RequestedBy)
	return nil
}

// configToDomainTarget converts a config.TargetSpec to a domain scanning.Target
func configToDomainTarget(cfg config.TargetSpec) scanning.Target {
	var auth *scanning.Auth
	if cfg.SourceAuth != nil {
		domainAuth := scanning.NewAuth(
			cfg.SourceAuth.Type,
			cfg.SourceAuth.Credentials,
		)
		auth = &domainAuth
	}

	return scanning.NewTarget(
		cfg.Name,
		cfg.SourceType,
		auth,
		cfg.Metadata,
	)
}

// configToDomainAuth converts a config.AuthConfig to a domain scanning.Auth
func configToDomainAuth(cfg config.AuthConfig) scanning.Auth {
	return scanning.NewAuth(cfg.Type, cfg.Credentials)
}
