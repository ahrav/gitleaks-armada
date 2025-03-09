package gateway

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
	"github.com/ahrav/gitleaks-armada/pkg/common/timeutil"
	"github.com/ahrav/gitleaks-armada/proto"
)

// MessageConverter converts an event envelope to a gateway-to-scanner message.
type MessageConverter func(ctx context.Context, evt events.EventEnvelope) (*proto.GatewayToScannerMessage, error)

// ScannerStream represents a gRPC stream connection to a scanner.
type ScannerStream interface {
	Send(*proto.GatewayToScannerMessage) error
	Context() context.Context
}

// eventSubscriptionHandler manages event subscriptions and routes events to scanners.
//
// Why this component exists:
//
//  1. Reliability Model Implementation: It provides the core implementation of the reliability
//     pattern for gateway→scanner communication, where all commands require explicit
//     acknowledgments from the scanners to confirm receipt and processing.
//
//  2. Separation of Concerns: It isolates the subscription logic from event delivery,
//     allowing the EventSubscriptionManager to focus on higher-level coordination without
//     dealing with the mechanics of event bus subscriptions and delivery.
//
//  3. Stream Abstraction: It decouples the event bus from gRPC stream mechanics, providing
//     a clean interface that works with different event bus implementations and stream types
//     (regular or broadcast).
//
//  4. Reusability: The same handler logic is used for both regular and broadcast events,
//     preventing code duplication while allowing the EventSubscriptionManager to switch
//     between different event buses.
//
// This component represents the critical link in translating the central system's
// event-driven architecture to the gRPC streaming model used for communicating with
// on-premise scanners. It ensures commands are delivered reliably despite potential
// network issues or scanner disconnections.
type eventSubscriptionHandler struct {
	eventBus events.EventBus

	ackTracker *acknowledgmentTracker
	// Default timeout for waiting for acknowledgments.
	ackTimeout   time.Duration
	timeProvider timeutil.Provider

	logger *logger.Logger
	tracer trace.Tracer
}

// NewEventSubscriptionHandler creates a new handler for event subscriptions.
func NewEventSubscriptionHandler(
	eventBus events.EventBus,
	ackTracker *acknowledgmentTracker,
	ackTimeout time.Duration,
	timeProvider timeutil.Provider,
	logger *logger.Logger,
	tracer trace.Tracer,
) *eventSubscriptionHandler {
	return &eventSubscriptionHandler{
		eventBus:     eventBus,
		ackTracker:   ackTracker,
		timeProvider: timeProvider,
		ackTimeout:   ackTimeout,
		logger:       logger,
		tracer:       tracer,
	}
}

// Subscribe sets up event subscriptions and routes events to the provided stream.
//
// This method is the core implementation of the gateway→scanner communication pattern:
// 1. It subscribes to domain events from the internal event bus
// 2. Converts domain events to gRPC messages using the provided converter
// 3. Sends the messages to scanners via their gRPC stream
// 4. Sets up tracking for acknowledgments with timeouts
// 5. Handles acknowledgment responses asynchronously to avoid blocking
//
// Unlike traditional message queues where consumers pull messages, this push-based
// approach ensures scanners receive commands in real-time while still maintaining
// delivery guarantees through explicit acknowledgments. This creates a virtual event
// bus over gRPC that bridges the internal event system with external scanners,
// while respecting network boundaries and maintaining security.
func (h *eventSubscriptionHandler) Subscribe(
	ctx context.Context,
	scannerID string,
	stream ScannerStream,
	eventTypes []events.EventType,
	converter MessageConverter,
) error {
	ctx, span := h.tracer.Start(
		ctx,
		"gateway.EventSubscriptionHandler.Subscribe",
		trace.WithAttributes(attribute.String("scanner_id", scannerID)),
	)
	defer span.End()

	logger := h.logger.With("operation", "Subscribe", "scanner_id", scannerID)
	logger.Info(ctx, "Setting up event subscription", "event_types", eventTypes)

	// Subscribe to all requested event types.
	for _, eventType := range eventTypes {
		// Create a handler function for this event type.
		handler := func(ctx context.Context, envelope events.EventEnvelope, ack events.AckFunc) error {
			ctx, msgSpan := h.tracer.Start(
				ctx,
				"gateway.handleSubscribedEvent",
				trace.WithAttributes(
					attribute.String("scanner_id", scannerID),
					attribute.String("event_type", string(eventType)),
					attribute.String("event_type", string(envelope.Type)),
				),
			)
			defer msgSpan.End()

			// Convert the event to a gateway-to-scanner message.
			message, err := converter(ctx, envelope)
			if err != nil {
				msgSpan.RecordError(err)
				msgSpan.SetStatus(codes.Error, "failed to convert event to message")
				logger.Error(ctx, "Failed to convert event to message",
					"event_type", eventType,
					"error", err)
				ack(err)
				return err
			}

			messageID := message.MessageId
			ackCh := h.ackTracker.TrackMessage(messageID)

			// Send the message to the scanner.
			if err := stream.Send(message); err != nil {
				msgSpan.RecordError(err)
				msgSpan.SetStatus(codes.Error, "failed to send message to scanner")
				logger.Error(ctx, "Failed to send message to scanner",
					"event_type", eventType,
					"message_id", messageID,
					"error", err)

				h.ackTracker.StopTracking(messageID)
				ack(err)
				return err
			}

			// Avoid blocking the event handler on waiting for an acknowledgment
			// by running it in a goroutine.
			// We don't have to ensure this goroutine has manual cleanup because
			// the ackTracker will clean up the channel when the message is
			// acknowledged or timed out.
			go func() {
				ctx, span := h.tracer.Start(
					ctx,
					"gateway.waitForAcknowledgment",
					trace.WithAttributes(attribute.String("message_id", messageID)),
				)
				defer span.End()

				if err := h.ackTracker.WaitForAcknowledgment(ctx, messageID, ackCh, h.ackTimeout); err != nil {
					msgSpan.RecordError(err)
					msgSpan.SetStatus(codes.Error, "failed to get acknowledgment")
					logger.Error(ctx, "Failed to get acknowledgment",
						"event_type", eventType,
						"message_id", messageID,
						"error", err)
					ack(err)
					return
				}
				ack(nil)
			}()

			return nil
		}

		// Subscribe to the event type.
		if err := h.eventBus.Subscribe(ctx, []events.EventType{eventType}, handler); err != nil {
			err = fmt.Errorf("failed to subscribe to event type %s: %w", eventType, err)
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			logger.Error(ctx, "Failed to subscribe to event type",
				"event_type", eventType,
				"error", err)
			return err
		}

		logger.Info(ctx, "Subscribed to event type", "event_type", eventType)
	}

	span.SetStatus(codes.Ok, "successfully subscribed to events")
	return nil
}
