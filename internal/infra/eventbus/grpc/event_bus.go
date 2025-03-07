// Package grpc provides a gRPC implementation of the event bus interface.
// It enables bidirectional communication between scanners and gateway using gRPC streams,
// serving as an alternative to Kafka for on-premises scanners that can't directly
// access the central Kafka cluster.
package grpc

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/domain/rules"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/internal/infra/eventbus/serialization"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
	"github.com/ahrav/gitleaks-armada/pkg/common/timeutil"
	"github.com/ahrav/gitleaks-armada/pkg/common/uuid"
	pb "github.com/ahrav/gitleaks-armada/proto"
)

var _ events.EventBus = (*EventBus)(nil)

// GRPCMetrics interface defines the metrics required for the gRPC-based event bus.
// It provides methods to record metrics for message operations and errors.
type GRPCMetrics interface {
	// IncMessageSent increments the counter for messages sent of a specific type.
	IncMessageSent(ctx context.Context, messageType string)

	// IncMessageReceived increments the counter for messages received of a specific type.
	IncMessageReceived(ctx context.Context, messageType string)

	// IncSendError increments the counter for errors encountered when sending messages.
	IncSendError(ctx context.Context, messageType string)

	// IncReceiveError increments the counter for errors encountered when receiving messages.
	IncReceiveError(ctx context.Context, messageType string)
}

// EventBusConfig contains configuration for the gRPC-based event bus.
// It defines parameters needed to establish and maintain the event bus connection.
type EventBusConfig struct {
	// ScannerID is the unique identifier for the connected scanner.
	ScannerID string

	// ServiceType identifies the type of service ("gateway" or "scanner").
	ServiceType string

	// AuthToken is the authentication token used for the connection.
	AuthToken string

	// ConnectionTimeout specifies the maximum time to wait for connection establishment.
	ConnectionTimeout time.Duration

	// MaxRetries defines the maximum number of connection retry attempts.
	MaxRetries int

	// RetryBaseDelay is the initial delay between retry attempts, which may increase exponentially.
	RetryBaseDelay time.Duration

	// RetryMaxDelay caps the maximum delay between retry attempts.
	RetryMaxDelay time.Duration
}

// EventBus implements the events.EventBus interface using gRPC streaming as the
// transport mechanism. It provides bidirectional communication between the scanner
// and the gateway service through a persistent connection.
type EventBus struct {
	// Underlying stream for bidirectional communication.
	stream ClientStreamInterface

	// Configuration for the event bus.
	config *EventBusConfig

	// Maps event types to internal message types.
	eventToMessageType map[events.EventType]string

	// Maps internal message types to event types.
	messageToEventType map[string]events.EventType

	// Mapping from message ID to ack channel.
	ackChannelsMu sync.RWMutex
	ackChannels   map[string]chan error

	// Handlers for incoming messages.
	handlersMu sync.RWMutex
	handlers   map[events.EventType][]events.HandlerFunc

	// Context and cancellation for the receiver goroutine.
	ctx        context.Context
	cancelFunc context.CancelFunc

	// Signal when the receiver goroutine has exited.
	receiverDone chan struct{}

	// Bus closed signal.
	closed     bool
	closedLock sync.RWMutex

	timeProvider timeutil.Provider // Used for consistent time handling and testing

	logger  *logger.Logger
	tracer  trace.Tracer
	metrics GRPCMetrics
}

// NewScannerEventBus creates a new gRPC event bus specifically for scanners.
// It takes a scanner gRPC stream and configures the event bus for scanner-to-gateway
// communication. The event bus handles message serialization/deserialization and event routing.
func NewScannerEventBus(
	stream pb.ScannerGatewayService_ConnectScannerClient,
	cfg *EventBusConfig,
	logger *logger.Logger,
	metrics GRPCMetrics,
	tracer trace.Tracer,
) (*EventBus, error) {

	if cfg == nil {
		return nil, errors.New("event bus config is required")
	}

	if stream == nil {
		return nil, errors.New("gRPC stream is required")
	}

	logger = logger.With(
		"component", "grpc_event_bus",
		"scanner_id", cfg.ScannerID,
		"service_type", cfg.ServiceType,
	)

	// Map from domain event types to message types.
	eventTypeMap := mapEventTypeToMessageType()

	// Create reverse mapping.
	messageTypeMap := make(map[string]events.EventType)
	for evtType, msgType := range eventTypeMap {
		messageTypeMap[msgType] = evtType
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Create a stream adapter to handle type conversion.
	adapter := &ScannerStreamAdapter{Stream: stream}

	bus := &EventBus{
		stream:             adapter,
		config:             cfg,
		eventToMessageType: eventTypeMap,
		messageToEventType: messageTypeMap,
		ackChannels:        make(map[string]chan error),
		handlers:           make(map[events.EventType][]events.HandlerFunc),
		ctx:                ctx,
		cancelFunc:         cancel,
		receiverDone:       make(chan struct{}),
		timeProvider:       timeutil.Default(),
		logger:             logger,
		metrics:            metrics,
		tracer:             tracer,
	}

	go bus.receiveLoop()

	return bus, nil
}

// mapEventTypeToMessageType creates a mapping between domain event types and gRPC message types.
// This mapping is essential for proper serialization and deserialization of events.
func mapEventTypeToMessageType() map[events.EventType]string {
	return map[events.EventType]string{
		// Scanner lifecycle events.
		scanning.EventTypeScannerRegistered:    "registration",
		scanning.EventTypeScannerHeartbeat:     "heartbeat",
		scanning.EventTypeScannerStatusChanged: "status_changed",
		scanning.EventTypeScannerDeregistered:  "deregistered",

		// Task processing events.
		scanning.EventTypeTaskCreated:    "task",
		scanning.EventTypeTaskStarted:    "task_started",
		scanning.EventTypeTaskProgressed: "task_progressed",
		scanning.EventTypeTaskCompleted:  "task_completed",
		scanning.EventTypeTaskFailed:     "task_failed",
		scanning.EventTypeTaskResume:     "task_resume",
		scanning.EventTypeTaskPaused:     "pause_task",
		scanning.EventTypeTaskCancelled:  "cancel_task",

		// Job control events.
		scanning.EventTypeJobPausing:    "pause_job",
		scanning.EventTypeJobPaused:     "pause_job",
		scanning.EventTypeJobResuming:   "resume_job",
		scanning.EventTypeJobCancelling: "cancel_job",
		scanning.EventTypeJobCancelled:  "cancel_job",

		// Rules events - controller-initiated flow.
		// The controller initiates rule distribution to all scanners.
		// Scanners do NOT request rules; they receive them from the controller.
		rules.EventTypeRulesRequested: "controller_initiated_rule_distribution",
		rules.EventTypeRulesUpdated:   "controller_pushed_rule_update",
		rules.EventTypeRulesPublished: "controller_published_rules",
	}
}

// Publish sends an event to the stream and optionally waits for acknowledgment.
// It handles event serialization and transmission to the other service.
// The method returns an error if the transmission fails or if acknowledgment
// is requested but not received within the timeout period.
func (b *EventBus) Publish(ctx context.Context, event events.EventEnvelope, opts ...events.PublishOption) error {
	ctx, span := b.tracer.Start(ctx, "EventBus.Publish",
		trace.WithAttributes(
			attribute.String("event.type", string(event.Type)),
		),
	)
	defer span.End()

	b.closedLock.RLock()
	closed := b.closed
	b.closedLock.RUnlock()
	if closed {
		err := fmt.Errorf("event bus is closed")
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	messageType, ok := b.eventToMessageType[event.Type]
	if !ok {
		err := fmt.Errorf("unknown event type: %s", event.Type)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	span.SetAttributes(attribute.String("message.type", messageType))

	msgID := uuid.New().String()
	msg := &GatewayToScannerMessage{MessageId: msgID, Timestamp: b.timeProvider.Now().UnixNano()}

	var pParams events.PublishParams
	for _, opt := range opts {
		opt(&pParams)
	}

	if pParams.Key != "" {
		msg.RoutingKey = pParams.Key
		span.SetAttributes(attribute.String("message.routing_key", pParams.Key))
	}

	// Set any headers if provided.
	if len(pParams.Headers) > 0 {
		if msg.Headers == nil {
			msg.Headers = make(map[string]string)
		}

		maps.Copy(msg.Headers, pParams.Headers)
		span.SetAttributes(attribute.Int("message.headers.count", len(pParams.Headers)))
	}

	// Set the payload field based on the event type.
	// This will internally call serialization.DomainEventToProto
	if err := b.setPayloadFromDomainEvent(msg, event); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("failed to set payload: %w", err)
	}

	// Create a channel to receive acknowledgment.
	ackChan := make(chan error, 1)
	b.ackChannelsMu.Lock()
	b.ackChannels[msgID] = ackChan
	b.ackChannelsMu.Unlock()

	// Send the message over the stream.
	if err := b.stream.Send(msg); err != nil {
		b.ackChannelsMu.Lock()
		delete(b.ackChannels, msgID)
		b.ackChannelsMu.Unlock()
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		b.metrics.IncSendError(ctx, messageType)
		return fmt.Errorf("failed to send message: %w", err)
	}

	b.metrics.IncMessageSent(ctx, messageType)

	var waitForAck bool = true
	var ackTimeout time.Duration = 30 * time.Second // default timeout

	// Apply options (we're not using the actual options in this implementation).
	_ = opts

	if !waitForAck {
		// Clean up the ack channel if we're not waiting.
		b.ackChannelsMu.Lock()
		delete(b.ackChannels, msgID)
		b.ackChannelsMu.Unlock()
		return nil
	}

	// Create a timeout context for waiting for the ack.
	timeoutCtx, cancel := context.WithTimeout(ctx, ackTimeout)
	defer cancel()

	// Wait for acknowledgment or timeout.
	select {
	case <-b.ctx.Done():
		// The context was cancelled, so we don't need to wait for the ack.
		span.SetStatus(codes.Error, "context cancelled")
		span.RecordError(fmt.Errorf("context cancelled"))
		return nil

	case err := <-ackChan:
		// Clean up.
		b.ackChannelsMu.Lock()
		delete(b.ackChannels, msgID)
		b.ackChannelsMu.Unlock()

		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
		}
		return err

	case <-timeoutCtx.Done():
		// Timed out waiting for acknowledgment.
		b.ackChannelsMu.Lock()
		delete(b.ackChannels, msgID)
		b.ackChannelsMu.Unlock()

		err := fmt.Errorf("timeout waiting for acknowledgment: %w", timeoutCtx.Err())
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}
}

// setPayloadFromDomainEvent sets the appropriate field in a GatewayToScannerMessage based on the event type.
// It handles the conversion from domain events to protocol buffer messages.
func (b *EventBus) setPayloadFromDomainEvent(msg *GatewayToScannerMessage, evt events.EventEnvelope) error {
	// Create a span for tracking this operation
	_, span := b.tracer.Start(context.Background(), "EventBus.setPayloadFromDomainEvent",
		trace.WithAttributes(
			attribute.String("event.type", string(evt.Type)),
		),
	)
	defer span.End()

	// Convert domain event to proto message
	protoMsg, err := serialization.DomainEventToProto(evt.Type, evt.Payload)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("failed to convert domain event to proto: %w", err)
	}

	// Set the payload field based on the event type
	if err := SetGatewayToScannerPayload(msg, evt.Type, protoMsg); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("failed to set gateway message payload: %w", err)
	}

	return nil
}

// Subscribe registers a handler function to process domain events from specified event types.
// When events of the registered types are received, the handler function will be called
// with the event envelope and an acknowledgment function.
func (b *EventBus) Subscribe(
	ctx context.Context,
	eventTypes []events.EventType,
	handler events.HandlerFunc,
) error {
	b.closedLock.RLock()
	if b.closed {
		b.closedLock.RUnlock()
		return errors.New("event bus is closed")
	}
	b.closedLock.RUnlock()

	if handler == nil {
		return errors.New("handler cannot be nil")
	}

	b.handlersMu.Lock()
	defer b.handlersMu.Unlock()

	for _, evtType := range eventTypes {
		b.handlers[evtType] = append(b.handlers[evtType], handler)
		b.logger.Debug(ctx, "Subscribed to event type", "event_type", evtType)
	}

	return nil
}

// receiveLoop continuously receives messages from the gRPC stream and processes them.
// This method runs in a separate goroutine and handles incoming messages until the
// context is cancelled or the event bus is closed.
func (b *EventBus) receiveLoop() {
	defer close(b.receiverDone)

	for {
		select {
		case <-b.ctx.Done():
			b.logger.Info(b.ctx, "Stopping receive loop due to context cancellation")
			return
		default:
			// Continue receiving.
		}

		msg, err := b.stream.Recv()
		if err != nil {
			b.logger.Error(b.ctx, "Error receiving message from stream", "error", err)

			b.closedLock.RLock()
			isClosed := b.closed
			b.closedLock.RUnlock()

			if isClosed || b.ctx.Err() != nil {
				return
			}

			// TODO: Implement reconnect logic here if needed.

			// Sleep briefly before retrying.
			b.timeProvider.Sleep(100 * time.Millisecond)
			continue
		}

		// Process the received message in a separate goroutine.
		// TODO: Consider limiting the number of concurrent goroutines here.
		go b.processIncomingMessage(msg)
	}
}

// processIncomingMessage handles messages from the scanner stream.
// It dispatches the message to the appropriate handler based on its type,
// and sends acknowledgments back when required.
func (b *EventBus) processIncomingMessage(msg *ScannerToGatewayMessage) {
	ctx := context.Background()

	// Extract message ID for routing acknowledgments.
	msgID := msg.GetMessageId()
	isAck := msg.GetAck() != nil

	// Handle acknowledgments first.
	if isAck {
		b.ackChannelsMu.RLock()
		ch, exists := b.ackChannels[msgID]
		b.ackChannelsMu.RUnlock()

		if exists {
			ack := msg.GetAck()
			if ack.Success {
				ch <- nil
			} else {
				ch <- fmt.Errorf("acknowledgment error: %s", ack.ErrorMessage)
			}

			// Clean up the acknowledgment channel once processed.
			b.ackChannelsMu.Lock()
			delete(b.ackChannels, msgID)
			b.ackChannelsMu.Unlock()
		} else {
			b.logger.Warn(ctx, "Received acknowledgment for unknown message", "message_id", msgID)
		}
		return
	}

	// Define a callback function that will be invoked by the ProcessIncomingMessage helper.
	callback := func(callbackCtx context.Context, eventType events.EventType, protoPayload any) error {
		callbackCtx, span := b.tracer.Start(callbackCtx, "grpc.EventBus.handleEvent",
			trace.WithAttributes(
				attribute.String("event.type", string(eventType)),
				attribute.String("message.id", msgID),
			),
		)
		defer span.End()

		domainEvent, err := serialization.ProtoToDomainEvent(eventType, protoPayload)
		if err != nil {
			b.logger.Error(ctx, "Failed to convert proto to domain event",
				"event_type", eventType,
				"error", err)
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())

			if b.metrics != nil {
				b.metrics.IncReceiveError(ctx, string(eventType))
			}
			return err
		}

		if b.metrics != nil {
			b.metrics.IncMessageReceived(ctx, string(eventType))
		}

		envelope := events.EventEnvelope{Type: eventType, Payload: domainEvent, Timestamp: b.timeProvider.Now()}

		// Dispatch to handlers.
		b.handlersMu.RLock()
		handlers, exists := b.handlers[eventType]
		b.handlersMu.RUnlock()

		if !exists || len(handlers) == 0 {
			b.logger.Debug(ctx, "No handlers registered for event type", "event_type", eventType)
			return nil
		}

		// Dispatch to all handlers.
		for _, handler := range handlers {
			// Create a handler-specific context with the message ID for tracing.
			handlerCtx := context.WithValue(callbackCtx, "message_id", msgID)

			// Create an acknowledgment function that sends ACK back to the scanner.
			ackFunc := func(err error) {
				success := err == nil
				errMsg := ""
				if err != nil {
					errMsg = err.Error()
				}

				ackMsg := &pb.GatewayToScannerMessage{
					MessageId: fmt.Sprintf("ack-%s", msgID),
					Timestamp: b.timeProvider.Now().UnixNano(),
					Payload: &pb.GatewayToScannerMessage_RegistrationResponse{
						RegistrationResponse: &pb.ScannerRegistrationResponse{
							Success:   success,
							Message:   errMsg,
							ScannerId: msgID,
						},
					},
				}

				if err := b.stream.Send(ackMsg); err != nil {
					b.logger.Error(ctx, "Failed to send acknowledgment",
						"original_message_id", msgID,
						"error", err)
				}
			}

			// Call the handler with the ack function.
			if err := handler(handlerCtx, envelope, ackFunc); err != nil {
				b.logger.Error(ctx, "Handler failed for event",
					"event_type", eventType,
					"error", err)
				span.RecordError(err)

				if b.metrics != nil {
					b.metrics.IncReceiveError(ctx, string(eventType))
				}
			}
		}

		return nil
	}

	// Use the helper function to process the message.
	err := ProcessIncomingMessage(ctx, msg, b.logger, b.tracer, callback)
	if err != nil {
		b.logger.Error(ctx, "Failed to process incoming message", "error", err)
	}
}

// Close gracefully shuts down the event bus and releases associated resources.
// It cancels any pending operations, closes the connection, and ensures that
// the receive loop is terminated before returning.
func (b *EventBus) Close() error {
	b.closedLock.Lock()
	if b.closed {
		b.closedLock.Unlock()
		return nil
	}
	b.closed = true
	b.closedLock.Unlock()

	// Cancel the context to stop the receive loop.
	b.cancelFunc()

	// Close the send direction of the stream.
	if err := b.stream.CloseSend(); err != nil {
		b.logger.Error(b.ctx, "Error closing send direction of stream", "error", err)
	}

	// Wait for the receiver to complete.
	<-b.receiverDone

	return nil
}
