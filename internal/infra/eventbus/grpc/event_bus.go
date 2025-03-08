// Package grpc provides a gRPC implementation of the event bus interface.
// It enables bidirectional communication between scanners and gateway using gRPC streams,
// serving as an alternative to Kafka for on-premises scanners that can't directly
// access the central Kafka cluster.
package grpc

import (
	"context"
	"errors"
	"fmt"
	"io"
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

// // GRPCMetrics interface defines the metrics required for the gRPC-based event bus.
// // It provides methods to record metrics for message operations and errors.
// type GRPCMetrics interface {
// 	// IncMessageSent increments the counter for messages sent of a specific type.
// 	IncMessageSent(ctx context.Context, messageType string)

// 	// IncMessageReceived increments the counter for messages received of a specific type.
// 	IncMessageReceived(ctx context.Context, messageType string)

// 	// IncSendError increments the counter for errors encountered when sending messages.
// 	IncSendError(ctx context.Context, messageType string)

// 	// IncReceiveError increments the counter for errors encountered when receiving messages.
// 	IncReceiveError(ctx context.Context, messageType string)
// }

// EventBusConfig contains configuration for the gRPC-based event bus.
// It defines parameters needed to establish and maintain the event bus connection.
type EventBusConfig struct {
	// ScannerName is the name of the scanner.
	ScannerName string

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

// EventBus implements an asynchronous event bus for gRPC-based communication between
// scanners and the gateway. It establishes a bidirectional streaming connection where:
// - Scanner sends messages TO the gateway using ScannerToGatewayMessage
// - Scanner receives messages FROM the gateway using GatewayToScannerMessage
//
// Reliability Model:
// Unlike Kafka (which provides message persistence, consumer offsets, and replay capability),
// gRPC streams offer only transport-level guarantees without message persistence.
// To compensate for this fundamental difference, the EventBus implements a criticality-based
// acknowledgment system:
//
// 1. Non-Critical Messages (heartbeats, metrics, progress updates):
//   - Fire-and-forget approach (no waiting for acknowledgments)
//   - Higher throughput for frequent, routine updates
//   - Acceptable to occasionally miss processing confirmations
//
// 2. Critical Messages (task completions, final results, terminal status changes):
//   - Waits for application-level acknowledgments from the receiver
//   - Ensures important state transitions are confirmed
//   - Prevents data loss for events that won't be retransmitted
//
// 3. Gateway→Scanner Messages (all):
//   - Always send acknowledgments back to confirm processing
//   - Essential for the gateway to implement retry logic
//
// This approach automatically balances performance and reliability based on
// message criticality, without requiring clients to specify acknowledgment requirements.
type EventBus struct {
	// Underlying stream for bidirectional communication.
	stream ScannerGatewayStream

	// Configuration for the event bus.
	config *EventBusConfig

	// Maps event types to internal message types.
	eventToMessageType map[events.EventType]MessageType

	// Maps internal message types to event types.
	messageToEventType map[MessageType]events.EventType

	// Mapping from message ID to ack channel for critical messages.
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

	logger *logger.Logger
	tracer trace.Tracer
	// metrics GRPCMetrics
}

// newEventBus is a common helper function that creates and initializes an event bus
// with the provided configuration.
func newEventBus(
	stream ScannerGatewayStream,
	cfg *EventBusConfig,
	logger *logger.Logger,
	// metrics GRPCMetrics,
	tracer trace.Tracer,
	eventTypeMap map[events.EventType]MessageType,
) (*EventBus, error) {
	// Create reverse mapping.
	messageTypeMap := make(map[MessageType]events.EventType)
	for evtType, msgType := range eventTypeMap {
		messageTypeMap[msgType] = evtType
	}

	ctx, cancel := context.WithCancel(context.Background())

	bus := &EventBus{
		stream:             stream,
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
		// metrics:            metrics,
		tracer: tracer,
	}

	go bus.receiveLoop()

	return bus, nil
}

// NewScannerEventBus creates a new event bus for regular scanner communication.
// It uses the gRPC bidirectional stream directly, which already has the correct
// interface for scanner-to-gateway and gateway-to-scanner message flow.
func NewScannerEventBus(
	stream pb.ScannerGatewayService_ConnectScannerClient,
	cfg *EventBusConfig,
	logger *logger.Logger,
	// metrics GRPCMetrics,
	tracer trace.Tracer,
) (*EventBus, error) {
	// The gRPC stream implements ScannerGatewayStream interface with correct message directions:
	// - Send(ScannerToGatewayMessage) for scanner -> gateway communication
	// - Recv() -> GatewayToScannerMessage for gateway -> scanner communication
	return newEventBus(stream, cfg, logger, tracer, mapRegularEventTypes())
}

// mapRegularEventTypes creates a mapping between domain event types and gRPC message types
// specifically for regular scanner connections. This includes scanner lifecycle events,
// task processing, and rule distribution events.
func mapRegularEventTypes() map[events.EventType]MessageType {
	return map[events.EventType]MessageType{
		// Scanner lifecycle events - scanners send these to the gateway.
		scanning.EventTypeScannerRegistered:    MessageTypeScannerRegistered,
		scanning.EventTypeScannerHeartbeat:     MessageTypeScannerHeartbeat,
		scanning.EventTypeScannerStatusChanged: MessageTypeScannerStatusChanged,
		scanning.EventTypeScannerDeregistered:  MessageTypeScannerDeregistered,

		// Job control events - scanners receive job control events (broadcasted by the gateway).
		scanning.EventTypeJobPaused:    MessageTypeScanJobPaused,    // Gateway sends to scanner
		scanning.EventTypeJobCancelled: MessageTypeScanJobCancelled, // Gateway sends to scanner

		// Task processing events - scanners receive task assignments and send progress/results.
		scanning.EventTypeTaskCreated:    MessageTypeScanTask,           // Gateway sends to scanner
		scanning.EventTypeTaskStarted:    MessageTypeScanTaskStarted,    // Scanner sends to gateway
		scanning.EventTypeTaskProgressed: MessageTypeScanTaskProgressed, // Scanner sends to gateway
		scanning.EventTypeTaskCompleted:  MessageTypeScanTaskCompleted,  // Scanner sends to gateway
		scanning.EventTypeTaskFailed:     MessageTypeScanTaskFailed,     // Scanner sends to gateway
		scanning.EventTypeTaskResume:     MessageTypeScanTaskResume,     // Gateway sends to scanner
		scanning.EventTypeTaskHeartbeat:  MessageTypeScanTaskHeartbeat,  // Scanner sends to gateway
		scanning.EventTypeTaskJobMetric:  MessageTypeScanTaskJobMetric,  // Scanner sends to gateway

		// Rules events - controller initiates rule distribution to scanners.
		rules.EventTypeRulesRequested: MessageTypeRulesRequested,
	}
}

// NewBroadcastEventBus creates a new event bus for handling broadcast messages.
func NewBroadcastEventBus(
	stream pb.ScannerGatewayService_SubscribeToBroadcastsClient,
	cfg *EventBusConfig,
	logger *logger.Logger,
	// metrics GRPCMetrics,
	tracer trace.Tracer,
) (*EventBus, error) {
	// Both ConnectScanner and SubscribeToBroadcasts use the same stream interface
	// (grpc.BidiStreamingClient[ScannerToGatewayMessage, GatewayToScannerMessage])
	// So we can use the stream directly without an adapter
	return newEventBus(stream, cfg, logger, tracer, mapBroadcastEventTypes())
}

// mapBroadcastEventTypes creates a mapping between domain event types and gRPC message types
// specifically for broadcast connections. This primarily includes job control events that
// affect all scanners system-wide.
func mapBroadcastEventTypes() map[events.EventType]MessageType {
	return map[events.EventType]MessageType{
		// Job control events - broadcasted to all scanners
		scanning.EventTypeJobPaused:    MessageTypeScanJobPaused,    // Broadcast to all scanners
		scanning.EventTypeJobCancelled: MessageTypeScanJobCancelled, // Broadcast to all scanners

		// System-wide events that all scanners need to know about
		events.EventType("SystemNotification"): MessageTypeSystemNotification,
	}
}

func (b *EventBus) isClosed() bool {
	b.closedLock.RLock()
	defer b.closedLock.RUnlock()
	return b.closed
}

// Publish sends a domain event from the scanner to the gateway.
//
// This method implements a criticality-based reliability model:
// - For critical events (task completions, final results): Waits for acknowledgment
// - For non-critical events (heartbeats, metrics): Uses fire-and-forget approach
//
// The criticality determination is handled internally based on the event type,
// so clients don't need to specify any special options or change their code.
// See isCriticalEvent() for the complete classification of event types.
//
// This approach automatically balances:
// - Reliability for important state changes and terminal events
// - Performance for high-frequency, routine updates
//
// All messages still get transport-level delivery guarantees from gRPC,
// regardless of whether they wait for application-level acknowledgment.
func (b *EventBus) Publish(ctx context.Context, event events.EventEnvelope, opts ...events.PublishOption) error {
	logger := logger.NewLoggerContext(b.logger.With(
		"operation", "Publish",
		"scanner_id", b.config.ScannerName,
		"event_type", event.Type,
	))

	ctx, span := b.tracer.Start(ctx, "eventbus.Publish",
		trace.WithAttributes(
			attribute.String("event.type", string(event.Type)),
		),
	)
	defer span.End()

	if b.isClosed() {
		err := errors.New("event bus is closed")
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

	logger.Add("message.type", messageType.String())
	span.SetAttributes(attribute.String("message.type", messageType.String()))

	msgID := uuid.New().String()
	logger.Add("message.id", msgID)
	span.SetAttributes(attribute.String("message.id", msgID))

	msg := &ScannerToGatewayMessage{
		MessageId: msgID,
		Timestamp: b.timeProvider.Now().UnixNano(),
		ScannerId: b.config.ScannerName,
	}

	var pParams events.PublishParams
	for _, opt := range opts {
		opt(&pParams)
	}

	if pParams.Key != "" {
		msg.RoutingKey = pParams.Key
		logger.Add("message.routing_key", pParams.Key)
		span.SetAttributes(attribute.String("message.routing_key", pParams.Key))
	}

	if len(pParams.Headers) > 0 {
		if msg.Headers == nil {
			msg.Headers = make(map[string]string)
		}

		maps.Copy(msg.Headers, pParams.Headers)
		logger.Add("message.headers.count", len(pParams.Headers))
		span.SetAttributes(attribute.Int("message.headers.count", len(pParams.Headers)))
	}

	protoMsg, err := serialization.DomainEventToProto(event.Type, event.Payload)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("failed to convert domain event to proto: %w", err)
	}

	if err := SetScannerToGatewayPayload(msg, event.Type, protoMsg); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("failed to set payload: %w", err)
	}

	isCritical := b.isCriticalEvent(event.Type)
	logger.Add("message.is_critical", isCritical)
	span.SetAttributes(attribute.Bool("message.is_critical", isCritical))

	var ackChan chan error
	if isCritical {
		ackChan = make(chan error, 1)
		b.ackChannelsMu.Lock()
		b.ackChannels[msgID] = ackChan
		b.ackChannelsMu.Unlock()

		logger.Debug(ctx, "Created acknowledgment channel for critical message",
			"message_id", msgID,
			"event_type", string(event.Type))
	}

	if err := b.stream.Send(msg); err != nil {
		if isCritical {
			b.ackChannelsMu.Lock()
			delete(b.ackChannels, msgID)
			b.ackChannelsMu.Unlock()
		}

		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		logger.Error(ctx, "Failed to send message", "error", err)
		return fmt.Errorf("failed to send message: %w", err)
	}

	if !isCritical {
		span.AddEvent("non_critical_message_sent")
		span.SetStatus(codes.Ok, "non-critical message sent successfully")
		logger.Debug(ctx, "Non-critical message sent successfully")
		return nil
	}

	span.AddEvent("critical_message_sent")
	logger.Debug(ctx, "Critical message sent successfully")

	const defaultAckTimeout = 30 * time.Second
	timeoutCtx, cancel := context.WithTimeout(ctx, defaultAckTimeout)
	defer cancel()

	select {
	case err := <-ackChan:
		b.ackChannelsMu.Lock()
		delete(b.ackChannels, msgID)
		b.ackChannelsMu.Unlock()

		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			logger.Error(ctx, "Message acknowledged with error",
				"message_id", msgID,
				"error", err)
			return fmt.Errorf("message acknowledged with error: %w", err)
		}

		span.SetStatus(codes.Ok, "message acknowledged successfully")
		logger.Debug(ctx, "Message acknowledged successfully", "message_id", msgID)
		return nil

	case <-timeoutCtx.Done():
		b.ackChannelsMu.Lock()
		delete(b.ackChannels, msgID)
		b.ackChannelsMu.Unlock()

		err := fmt.Errorf(
			"timeout waiting for acknowledgment for (message_id: %s, event_type: %s): %w",
			msgID,
			event.Type,
			timeoutCtx.Err(),
		)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		logger.Error(ctx, "Timeout waiting for acknowledgment", "timeout", defaultAckTimeout)
		return err

	case <-b.ctx.Done():
		b.ackChannelsMu.Lock()
		delete(b.ackChannels, msgID)
		b.ackChannelsMu.Unlock()

		span.AddEvent("critical_message_timeout")
		span.SetStatus(codes.Error, "critical message timeout")

		return fmt.Errorf("event bus shutting down")
	}
}

// Subscribe registers a handler function to process domain events (commands) from the gateway.
//
// The reliability pattern for gateway→scanner communication requires that scanners:
// 1. Register handlers for specific event types they support
// 2. Process these events when received from the gateway
// 3. Send acknowledgments back to confirm successful processing
//
// Each handler function receives:
// - A context with request metadata
// - An event envelope with the domain event data
// - An acknowledgment function to report success/failure back to the gateway
//
// The acknowledgment function is a critical part of the reliability mechanism, allowing
// the gateway to track which commands have been processed and implement retry logic for
// commands that fail or aren't acknowledged.
//
// It's important that handlers use the provided acknowledgment function appropriately
// to maintain system consistency, especially for critical operations.
func (b *EventBus) Subscribe(
	ctx context.Context,
	eventTypes []events.EventType,
	handler events.HandlerFunc,
) error {
	logger := b.logger.With("operation", "Subscribe", "scanner_id", b.config.ScannerName)
	_, span := b.tracer.Start(ctx, "EventBus.Subscribe",
		trace.WithAttributes(
			attribute.String("scanner_id", b.config.ScannerName),
		),
	)
	defer span.End()

	if b.isClosed() {
		err := errors.New("event bus is closed")
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	if handler == nil {
		err := errors.New("handler cannot be nil")
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	b.handlersMu.Lock()
	defer b.handlersMu.Unlock()

	for _, evtType := range eventTypes {
		b.handlers[evtType] = append(b.handlers[evtType], handler)
		logger.Debug(ctx, "Subscribed to event type", "event_type", evtType)
		span.AddEvent("subscribed_to_event_type")
		span.SetAttributes(attribute.String("event_type", string(evtType)))
	}

	return nil
}

// receiveLoop continuously receives messages from the gRPC stream and processes them.
// This method runs in a separate goroutine and handles incoming messages until the
// context is cancelled or the event bus is closed.
func (b *EventBus) receiveLoop() {
	logger := b.logger.With("operation", "receiveLoop")
	ctx, span := b.tracer.Start(context.Background(), "EventBus.receiveLoop")
	defer close(b.receiverDone)

	span.AddEvent("receive_loop_started")
	logger.Info(ctx, "Receive loop started")
	span.End()

	for !b.isClosed() {
		ctx, span := b.tracer.Start(ctx, "EventBus.receiveLoop.recv")
		msg, err := b.stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) || b.isClosed() {
				span.AddEvent("receive_loop_ended")
				span.SetStatus(codes.Ok, "receive loop ended")
				logger.Info(ctx, "Receive loop ended")
				span.End()
				return
			}

			logger.Error(ctx, "Error receiving message from stream, continuing after short delay", "error", err)
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			time.Sleep(100 * time.Millisecond)
			continue
		}

		span.AddEvent("message_received")
		span.SetStatus(codes.Ok, "message received successfully")

		go b.processGatewayMessage(msg)
	}
}

// processGatewayMessage handles messages coming FROM the gateway TO the scanner.
// These are typically command messages like task assignments or job control operations
// that require reliable delivery and processing confirmation.
//
// The method:
// 1. Converts the gRPC message to a domain event
// 2. Dispatches it to registered handlers
// 3. Provides handlers with an acknowledgment function to confirm processing
//
// This implements the "Gateway→Scanner: Application-level acknowledgments" pattern
// described in the EventBus documentation, which is essential for reliability since
// gRPC streams don't provide message persistence or replay capabilities like Kafka.
func (b *EventBus) processGatewayMessage(msg *GatewayToScannerMessage) {
	logger := b.logger.With("operation", "processGatewayMessage", "message_id", msg.GetMessageId())
	ctx, span := b.tracer.Start(context.Background(), "EventBus.processGatewayMessage",
		trace.WithAttributes(
			attribute.String("message_id", msg.GetMessageId()),
		),
	)
	defer span.End()

	callback := func(callbackCtx context.Context, eventType events.EventType, protoPayload any) error {
		callbackCtx, span := b.tracer.Start(callbackCtx, "grpc.EventBus.handleGatewayEvent",
			trace.WithAttributes(
				attribute.String("event_type", string(eventType)),
			),
		)
		defer span.End()

		domainEvent, err := serialization.ProtoToDomainEvent(eventType, protoPayload)
		if err != nil {
			logger.Error(ctx, "Failed to convert proto to domain event",
				"event_type", eventType,
				"error", err)
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return err
		}

		envelope := events.EventEnvelope{
			Type:      eventType,
			Payload:   domainEvent,
			Timestamp: b.timeProvider.Now(),
		}

		b.handlersMu.RLock()
		handlers, exists := b.handlers[eventType]
		b.handlersMu.RUnlock()

		if !exists || len(handlers) == 0 {
			span.AddEvent("no_handlers_registered_for_event_type")
			span.RecordError(fmt.Errorf("no handlers registered for event type: %s", string(eventType)))
			logger.Error(ctx, "No handlers registered for event type", "event_type", eventType)
			return nil
		}

		// TODO: Timeouts?
		for _, handler := range handlers {
			ackFunc := func(ackErr error) {
				errorMsg := ""
				if ackErr != nil {
					errorMsg = ackErr.Error()
				}

				ackMsg := &ScannerToGatewayMessage{
					MessageId:  fmt.Sprintf("ack-%s", msg.GetMessageId()),
					Timestamp:  b.timeProvider.Now().UnixNano(),
					ScannerId:  b.config.ScannerName,
					RoutingKey: msg.GetRoutingKey(),
					Payload: &pb.ScannerToGatewayMessage_Ack{
						Ack: &pb.MessageAcknowledgment{
							OriginalMessageId: msg.GetMessageId(),
							Success:           ackErr == nil,
							ErrorMessage:      errorMsg,
						},
					},
				}

				if sendErr := b.stream.Send(ackMsg); sendErr != nil {
					span.RecordError(sendErr)
					logger.Error(ctx, "Failed to send acknowledgment", "error", sendErr)
					return
				}

				span.AddEvent("acknowledgment_sent")
			}

			if err := handler(callbackCtx, envelope, ackFunc); err != nil {
				span.RecordError(err)
				logger.Error(ctx, "Handler failed for event", "error", err)
				continue
			}
			span.AddEvent("successful_handler_execution")
		}
		span.AddEvent("all_handlers_executed")
		span.SetStatus(codes.Ok, "all handlers executed successfully")
		logger.Debug(ctx, "All handlers executed successfully")

		return nil
	}

	eventType, payload, err := extractGatewayMessageInfo(ctx, msg)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		logger.Error(ctx, "Failed to extract gateway message info", "error", err)
		return
	}

	if err := callback(ctx, eventType, payload); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		logger.Error(ctx, "Failed to process gateway message", "error", err)
		return
	}

	span.AddEvent("gateway_message_processed")
	span.SetStatus(codes.Ok, "gateway message processed successfully")
	logger.Debug(ctx, "Gateway message processed successfully")
}

// isCriticalEvent determines if an event type represents a critical message
// that requires acknowledgment for reliability. This is an internal implementation
// detail that clients don't need to be aware of.
//
// Critical events are usually terminal state changes or final results that:
// 1. Won't be naturally retransmitted by subsequent messages
// 2. Would result in data loss or inconsistency if not processed
// 3. Represent important state transitions in the system
func (b *EventBus) isCriticalEvent(eventType events.EventType) bool {
	switch eventType {
	case scanning.EventTypeTaskCompleted,
		scanning.EventTypeTaskFailed,
		scanning.EventTypeTaskCancelled:
		return true
	case scanning.EventTypeScannerRegistered,
		scanning.EventTypeScannerDeregistered,
		scanning.EventTypeScannerStatusChanged:
		return true
	case rules.EventTypeRulesUpdated, rules.EventTypeRulesPublished:
		return true
	case scanning.EventTypeTaskProgressed,
		scanning.EventTypeTaskJobMetric,
		scanning.EventTypeTaskHeartbeat:
		return false
	default:
		return false
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

	b.cancelFunc()

	if err := b.stream.CloseSend(); err != nil {
		b.logger.Error(b.ctx, "Error closing send direction of stream", "error", err)
	}

	<-b.receiverDone

	return nil
}
