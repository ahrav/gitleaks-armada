package handlers

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

// ScannerHandler handles scanner registration and lifecycle events.
type ScannerHandler struct {
	// controllerID uniquely identifies the controller running this handler.
	controllerID string

	// scannerService provides operations to manage scanner entities.
	scannerService scanning.ScannerService

	// tracer instruments method calls with OpenTelemetry spans for distributed tracing.
	tracer trace.Tracer

	// logger provides structured logging.
	logger *logger.Logger
}

// NewScannerHandler creates a new handler for scanner-related events.
func NewScannerHandler(
	controllerID string,
	scannerService scanning.ScannerService,
	logger *logger.Logger,
	tracer trace.Tracer,
) *ScannerHandler {
	logger = logger.With("component", "scanner_handler")
	return &ScannerHandler{
		controllerID:   controllerID,
		scannerService: scannerService,
		logger:         logger,
		tracer:         tracer,
	}
}

// HandleEvent processes all scanner-related events.
func (h *ScannerHandler) HandleEvent(
	ctx context.Context,
	evt events.EventEnvelope,
	ack events.AckFunc,
) error {
	switch evt.Type {
	case scanning.EventTypeScannerRegistered:
		return h.HandleScannerRegistered(ctx, evt, ack)
	case scanning.EventTypeScannerHeartbeat:
		return h.HandleScannerHeartbeat(ctx, evt, ack)
	case scanning.EventTypeScannerStatusChanged:
		return h.HandleScannerStatusChanged(ctx, evt, ack)
	case scanning.EventTypeScannerDeregistered:
		return h.HandleScannerDeregistered(ctx, evt, ack)
	default:
		return fmt.Errorf("unsupported event type: %s", evt.Type)
	}
}

// SupportedEvents returns the event types this handler supports.
func (h *ScannerHandler) SupportedEvents() []events.EventType {
	return []events.EventType{
		scanning.EventTypeScannerRegistered,
		scanning.EventTypeScannerHeartbeat,
		scanning.EventTypeScannerStatusChanged,
		scanning.EventTypeScannerDeregistered,
	}
}

// withSpan wraps the handler logic with a trace span for better observability.
// TODO: Consider moving this and recordPayloadTypeError to a span or similar file.
func (h *ScannerHandler) withSpan(
	ctx context.Context,
	operationName string,
	fn func(ctx context.Context, span trace.Span) error,
	ack events.AckFunc,
) error {
	ctx, span := h.tracer.Start(ctx, operationName)
	defer span.End()

	if err := fn(ctx, span); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		ack(nil)
		return err
	}

	ack(nil)
	return nil
}

// HandleScannerRegistered processes a scanner registration event.
// TODO: Test needed!!!!
func (h *ScannerHandler) HandleScannerRegistered(
	ctx context.Context,
	evt events.EventEnvelope,
	ack events.AckFunc,
) error {
	return h.withSpan(ctx, "scanner_handler.handle_scanner_registered", func(ctx context.Context, span trace.Span) error {
		regEvent, ok := evt.Payload.(scanning.ScannerRegisteredEvent)
		if !ok {
			return recordPayloadTypeError(span, evt.Payload)
		}

		scannerID, groupName := regEvent.ScannerID(), regEvent.GroupName()
		span.SetAttributes(
			attribute.String("scanner_id", scannerID.String()),
			attribute.String("scanner_name", regEvent.Name()),
			attribute.String("scanner_group", groupName),
			attribute.String("scanner_version", regEvent.Version()),
		)

		cmd := scanning.NewCreateScannerCommand(scannerID, groupName, regEvent.Name(), regEvent.Version(), nil)
		scanner, err := h.scannerService.CreateScanner(ctx, cmd)
		if err != nil {
			return fmt.Errorf("failed to register scanner: %w", err)
		}

		h.logger.Info(ctx, "Scanner registered successfully",
			"scanner_id", scanner.ID,
			"scanner_name", scanner.Name)

		return nil
	}, ack)
}

// HandleScannerHeartbeat processes a scanner heartbeat event.
func (h *ScannerHandler) HandleScannerHeartbeat(
	ctx context.Context,
	evt events.EventEnvelope,
	ack events.AckFunc,
) error {
	return h.withSpan(ctx, "scanner_handler.handle_scanner_heartbeat", func(ctx context.Context, span trace.Span) error {
		heartbeatEvent, ok := evt.Payload.(scanning.ScannerHeartbeatEvent)
		if !ok {
			return recordPayloadTypeError(span, evt.Payload)
		}

		scannerID := heartbeatEvent.ScannerID()
		span.SetAttributes(
			attribute.String("scanner_id", scannerID.String()),
			// attribute.String("status", heartbeatEvent.Status()),
		)

		// TODO: Implement heartbeat handling in the scanner service
		// This would update the scanner's last_heartbeat_at timestamp and potentially status

		h.logger.Debug(ctx, "Received scanner heartbeat", "scanner_id", scannerID)

		return nil
	}, ack)
}

// HandleScannerStatusChanged processes a scanner status change event.
func (h *ScannerHandler) HandleScannerStatusChanged(
	ctx context.Context,
	evt events.EventEnvelope,
	ack events.AckFunc,
) error {
	return h.withSpan(ctx, "scanner_handler.handle_scanner_status_changed", func(ctx context.Context, span trace.Span) error {
		statusEvent, ok := evt.Payload.(scanning.ScannerStatusChangedEvent)
		if !ok {
			return recordPayloadTypeError(span, evt.Payload)
		}

		scannerID := statusEvent.ScannerID()
		span.SetAttributes(
			attribute.String("scanner_id", scannerID.String()),
			// attribute.String("new_status", statusEvent.NewStatus()),
			// attribute.String("previous_status", statusEvent.PreviousStatus()),
			// attribute.String("reason", statusEvent.Reason()),
		)

		// TODO: Implement status change handling in the scanner service
		// This would update the scanner's status and record the reason for the change

		h.logger.Info(ctx, "Scanner status changed",
			"scanner_id", scannerID,
			"new_status", statusEvent.NewStatus(),
			"previous_status", statusEvent.PreviousStatus(),
			"reason", statusEvent.Reason())

		return nil
	}, ack)
}

// HandleScannerDeregistered processes a scanner deregistration event.
func (h *ScannerHandler) HandleScannerDeregistered(
	ctx context.Context,
	evt events.EventEnvelope,
	ack events.AckFunc,
) error {
	return h.withSpan(ctx, "scanner_handler.handle_scanner_deregistered", func(ctx context.Context, span trace.Span) error {
		deregEvent, ok := evt.Payload.(scanning.ScannerDeregisteredEvent)
		if !ok {
			return recordPayloadTypeError(span, evt.Payload)
		}

		scannerID := deregEvent.ScannerID()
		span.SetAttributes(
			attribute.String("scanner_id", scannerID.String()),
			attribute.String("reason", deregEvent.Reason()),
		)

		// TODO: Implement deregistration handling in the scanner service
		// This would mark the scanner as offline and record the reason

		h.logger.Info(ctx, "Scanner deregistered",
			"scanner_id", scannerID,
			"reason", deregEvent.Reason())

		return nil
	}, ack)
}
