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
	"os"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/domain/rules"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/internal/infra/eventbus/reliability"
	"github.com/ahrav/gitleaks-armada/internal/infra/eventbus/serialization"
	"github.com/ahrav/gitleaks-armada/internal/infra/messaging/acktracking"
	"github.com/ahrav/gitleaks-armada/internal/infra/messaging/protocol"
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

// EventBusConfig contains configuration settings for gRPC-based event buses.
//
// IMPORTANT: In our gRPC-based event bus implementation, we use two separate
// connections to the gateway:
//
// 1. Primary Connection (via ConnectScanner RPC):
//   - Used for bidirectional scanner-specific communication
//   - Requires full scanner registration
//   - Must be established first
//
// 2. Broadcast Connection (via SubscribeToBroadcasts RPC):
//   - Used for receiving system-wide broadcasts
//   - Requires simple scanner identification
//   - Optional but recommended for timely notifications
//
// Both connections use the same configuration settings for consistency,
// but they create separate logical streams in gRPC.
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

	// Registration details for scanner connections
	Version      string   // Scanner version
	GroupName    string   // Scanner group name
	Capabilities []string // Scanner capabilities
}

// handlerRegistry manages event handlers for different event types.
// It provides thread-safe operations for registering and executing handlers.
type handlerRegistry struct {
	mu       sync.RWMutex
	handlers map[events.EventType][]events.HandlerFunc
}

// newHandlerRegistry creates a new handler registry.
func newHandlerRegistry() *handlerRegistry {
	return &handlerRegistry{handlers: make(map[events.EventType][]events.HandlerFunc)}
}

// registerHandler registers a handler for an event type.
func (r *handlerRegistry) registerHandler(eventType events.EventType, handler events.HandlerFunc) {
	r.mu.Lock()
	r.handlers[eventType] = append(r.handlers[eventType], handler)
	r.mu.Unlock()
}

// getHandlers returns the handlers for an event type.
// Returns the handlers and true if handlers exist, empty slice and false otherwise.
func (r *handlerRegistry) getHandlers(eventType events.EventType) ([]events.HandlerFunc, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	handlers, exists := r.handlers[eventType]
	if !exists || len(handlers) == 0 {
		return nil, false
	}

	// Return a copy to avoid concurrent modification issues.
	result := make([]events.HandlerFunc, len(handlers))
	copy(result, handlers)

	return result, true
}

// busState manages the state of the event bus.
// It provides thread-safe operations for checking and changing the bus state.
type busState struct {
	mu     sync.RWMutex
	closed bool
}

// newBusState creates a new bus state tracker.
func newBusState() *busState { return &busState{closed: false} }

// isClosed checks if the bus is closed.
func (s *busState) isClosed() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.closed
}

// setClosed marks the bus as closed.
func (s *busState) setClosed() {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
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
	stream protocol.ScannerGatewayStream

	// Configuration for the event bus.
	config *EventBusConfig

	// Maps event types to internal message types.
	eventToMessageType map[events.EventType]protocol.MessageType

	// Manages acknowledgments for critical messages.
	ackTracker acktracking.AckTracker

	// Manages event handlers.
	handlerRegistry *handlerRegistry

	// Manages bus state.
	state *busState

	// Context and cancellation for the receiver goroutine.
	ctx        context.Context
	cancelFunc context.CancelFunc

	// Signal when the receiver goroutine has exited.
	receiverDone chan struct{}

	timeProvider timeutil.Provider // Used for consistent time handling and testing

	logger *logger.Logger
	tracer trace.Tracer
	// metrics GRPCMetrics
}

// newEventBus is a common helper function that creates and initializes an event bus
// with the provided configuration.
func newEventBus(
	stream protocol.ScannerGatewayStream,
	cfg *EventBusConfig,
	eventTypeMap map[events.EventType]protocol.MessageType,
	logger *logger.Logger,
	// metrics GRPCMetrics,
	tracer trace.Tracer,
) (*EventBus, error) {
	ctx, cancel := context.WithCancel(context.Background())

	// Use the shared AckTracker implementation
	ackTracker := acktracking.NewTracker(logger)

	bus := &EventBus{
		stream:             stream,
		config:             cfg,
		eventToMessageType: eventTypeMap,
		ackTracker:         ackTracker,
		handlerRegistry:    newHandlerRegistry(),
		state:              newBusState(),
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

// initializeStream handles sending an initial message to a stream and waiting for a response.
// This common logic is used by both regular scanner connections and broadcast connections.
func initializeStream(
	stream protocol.ScannerGatewayStream,
	msg *pb.ScannerToGatewayMessage,
	timeout time.Duration,
	logger *logger.Logger,
	tracer trace.Tracer,
) error {
	ctx, span := tracer.Start(context.Background(), "eventbus.initializeStream")
	defer span.End()

	if err := stream.Send(msg); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("failed to send initial message: %w", err)
	}
	span.AddEvent("sent_initial_message")

	logger.Info(ctx, "Sent initial message to gateway", "message_id", msg.MessageId)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	respChan := make(chan *pb.GatewayToScannerMessage, 1)
	errChan := make(chan error, 1)

	go func() {
		resp, err := stream.Recv()
		if err != nil {
			span.RecordError(err)
			errChan <- err
			return
		}
		respChan <- resp
	}()

	select {
	case resp := <-respChan:
		span.AddEvent("received_response_from_gateway")
		logger.Debug(ctx, "Received response from gateway", "message_id", resp.MessageId)

		ack := resp.GetAck()
		if ack == nil {
			span.RecordError(fmt.Errorf("expected acknowledgment response, but got different message type"))
			span.SetStatus(codes.Error, "expected acknowledgment response, but got different message type")
			return fmt.Errorf("expected acknowledgment response, but got different message type")
		}

		if !ack.Success {
			span.RecordError(fmt.Errorf("request rejected by gateway: %s", ack.ErrorMessage))
			span.SetStatus(codes.Error, "request rejected by gateway")
			return fmt.Errorf("request rejected by gateway: %s", ack.ErrorMessage)
		}

		if msg.GetRegistration() != nil {
			scannerId := ack.GetScannerId()
			if scannerId != "" && scannerId != msg.ScannerId {
				span.RecordError(fmt.Errorf("gateway assigned different scanner ID: %s", scannerId))
				span.SetStatus(codes.Error, "gateway assigned different scanner ID")
				logger.Warn(ctx, "Gateway assigned different scanner ID",
					"requested", msg.ScannerId,
					"assigned", scannerId)
				return fmt.Errorf("gateway assigned different scanner ID: %s", scannerId)
			}

			span.AddEvent("registration_confirmed_by_gateway")
			logger.Info(ctx, "Registration confirmed by gateway",
				"scanner_id", scannerId)
		} else {
			// For non-registration messages, just log the acknowledgment.
			span.AddEvent("message_acknowledged_by_gateway")
			logger.Info(ctx, "Message acknowledged by gateway",
				"original_message_id", ack.OriginalMessageId)
		}

		span.AddEvent("stream_initialized")
		span.SetStatus(codes.Ok, "Stream initialized successfully")
		logger.Info(ctx, "Stream initialized successfully")

		return nil
	case err := <-errChan:
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("error receiving response: %w", err)
	case <-ctx.Done():
		span.RecordError(ctx.Err())
		span.SetStatus(codes.Error, ctx.Err().Error())
		logger.Warn(ctx, "Timed out waiting for gateway response")
		return ctx.Err()
	}
}

// createBaseMessage creates a new ScannerToGatewayMessage with common fields set.
func createBaseMessage(cfg *EventBusConfig) *pb.ScannerToGatewayMessage {
	return &pb.ScannerToGatewayMessage{
		MessageId: uuid.New().String(),
		Timestamp: time.Now().UnixNano(),
		ScannerId: cfg.ScannerName,
		AuthToken: cfg.AuthToken,
	}
}

// getConnectionTimeout returns the connection timeout from config or a default value.
func getConnectionTimeout(cfg *EventBusConfig) time.Duration {
	timeout := cfg.ConnectionTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return timeout
}

// NewScannerEventBus creates a new event bus for regular scanner communication.
// It uses the gRPC bidirectional stream established via the ConnectScanner RPC method.
//
// IMPORTANT: gRPC Streaming Connection Behavior
// ---------------------------------------------
// In gRPC, each RPC method creates a separate logical stream, even if they share the
// same underlying TCP connection. This means:
//
// 1. We must send a registration message to identify this scanner to the gateway
// 2. We need to wait for a registration response to confirm success
// 3. This is required even if we also create a broadcast connection
//
// This method handles the complete protocol flow:
// - Send scanner registration with full details
// - Wait for gateway to confirm registration
// - Create event bus for bidirectional communication
//
// This is the PRIMARY connection for scanner-gateway communication and must be
// established before attempting to create a broadcast connection.
func NewScannerEventBus(
	stream pb.ScannerGatewayService_ConnectScannerClient,
	cfg *EventBusConfig,
	logger *logger.Logger,
	// metrics GRPCMetrics,
	tracer trace.Tracer,
) (*EventBus, error) {
	version := cfg.Version
	if version == "" {
		version = "1.0.0"
	}

	groupName := cfg.GroupName
	if groupName == "" {
		groupName = "system_default"
	}

	regMsg := createBaseMessage(cfg)
	regMsg.Payload = &pb.ScannerToGatewayMessage_Registration{
		Registration: &pb.ScannerRegistrationRequest{
			ScannerName:  cfg.ScannerName,
			Version:      version,
			Capabilities: cfg.Capabilities,
			GroupName:    groupName,
			Hostname:     hostname(),
		},
	}

	if err := initializeStream(stream, regMsg, getConnectionTimeout(cfg), logger, tracer); err != nil {
		return nil, fmt.Errorf("failed to initialize scanner connection: %w", err)
	}

	logger = logger.With("component", "scanner_event_bus")
	eventBus, err := newEventBus(stream, cfg, mapRegularEventTypes(), logger, tracer)
	if err != nil {
		return nil, err
	}

	return eventBus, nil
}

// hostname returns the machine's hostname or "unknown" if it can't be determined
func hostname() string {
	host, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return host
}

// mapRegularEventTypes creates a mapping between domain event types and gRPC message types
// specifically for regular scanner connections. This includes scanner lifecycle events,
// task processing, and rule distribution events.
func mapRegularEventTypes() map[events.EventType]protocol.MessageType {
	return map[events.EventType]protocol.MessageType{
		// Scanner lifecycle events - scanners send these to the gateway.
		scanning.EventTypeScannerRegistered:    protocol.MessageTypeScannerRegistered,
		scanning.EventTypeScannerHeartbeat:     protocol.MessageTypeScannerHeartbeat,
		scanning.EventTypeScannerStatusChanged: protocol.MessageTypeScannerStatusChanged,
		scanning.EventTypeScannerDeregistered:  protocol.MessageTypeScannerDeregistered,

		// Job control events - scanners receive job control events (broadcasted by the gateway).
		scanning.EventTypeJobPaused:    protocol.MessageTypeScanJobPaused,    // Gateway sends to scanner
		scanning.EventTypeJobCancelled: protocol.MessageTypeScanJobCancelled, // Gateway sends to scanner

		// Task processing events - scanners receive task assignments and send progress/results.
		scanning.EventTypeTaskCreated:    protocol.MessageTypeScanTask,           // Gateway sends to scanner
		scanning.EventTypeTaskStarted:    protocol.MessageTypeScanTaskStarted,    // Scanner sends to gateway
		scanning.EventTypeTaskProgressed: protocol.MessageTypeScanTaskProgressed, // Scanner sends to gateway
		scanning.EventTypeTaskCompleted:  protocol.MessageTypeScanTaskCompleted,  // Scanner sends to gateway
		scanning.EventTypeTaskFailed:     protocol.MessageTypeScanTaskFailed,     // Scanner sends to gateway
		scanning.EventTypeTaskResume:     protocol.MessageTypeScanTaskResume,     // Gateway sends to scanner
		scanning.EventTypeTaskHeartbeat:  protocol.MessageTypeScanTaskHeartbeat,  // Scanner sends to gateway
		scanning.EventTypeTaskJobMetric:  protocol.MessageTypeScanTaskJobMetric,  // Scanner sends to gateway

		// Rules events - controller initiates rule distribution to scanners.
		rules.EventTypeRulesRequested: protocol.MessageTypeRulesRequested,
	}
}

// NewBroadcastEventBus creates a new event bus for handling broadcast messages.
// It uses the gRPC bidirectional stream established via the SubscribeToBroadcasts RPC method.
//
// IMPORTANT: Why We Need Another Registration Message
// --------------------------------------------------
// Even if we've already registered via the primary connection (ConnectScanner),
// we still need to identify this scanner in the broadcast stream because:
//
// 1. In gRPC, each RPC method creates a separate logical stream with its own state
// 2. The gateway doesn't automatically know which scanner is connecting to the broadcast stream
// 3. The gateway needs to match this broadcast connection to an existing scanner registration
//
// This method handles a simpler protocol flow than the primary connection:
// - Send simple identification message (not full registration)
// - We should also verify the connection was accepted (TODO)
// - Create event bus for primarily receiving broadcast messages
//
// To avoid confusion, it's important to understand that this is a SEPARATE connection
// from the primary scanner connection, even though they connect to the same gateway.
func NewBroadcastEventBus(
	stream pb.ScannerGatewayService_SubscribeToBroadcastsClient,
	cfg *EventBusConfig,
	logger *logger.Logger,
	// metrics GRPCMetrics,
	tracer trace.Tracer,
) (*EventBus, error) {
	idMsg := createBaseMessage(cfg)

	if err := initializeStream(stream, idMsg, getConnectionTimeout(cfg), logger, tracer); err != nil {
		return nil, fmt.Errorf("failed to initialize broadcast connection: %w", err)
	}

	logger = logger.With("component", "broadcast_event_bus")
	eventBus, err := newEventBus(stream, cfg, mapBroadcastEventTypes(), logger, tracer)
	if err != nil {
		return nil, err
	}

	return eventBus, nil
}

// mapBroadcastEventTypes creates a mapping between domain event types and gRPC message types
// specifically for broadcast connections. This primarily includes job control events that
// affect all scanners system-wide.
func mapBroadcastEventTypes() map[events.EventType]protocol.MessageType {
	return map[events.EventType]protocol.MessageType{
		// Job control messages
		scanning.EventTypeJobPaused:    protocol.MessageTypeScanJobPaused,    // Broadcast to all scanners
		scanning.EventTypeJobCancelled: protocol.MessageTypeScanJobCancelled, // Broadcast to all scanners

		// System messages
		protocol.EventTypeSystemNotification: protocol.MessageTypeSystemNotification,
	}
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
			attribute.String("event_type", string(event.Type)),
		),
	)
	defer span.End()

	if b.state.isClosed() {
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

	logger.Add("message_type", messageType.String())
	span.SetAttributes(attribute.String("message_type", messageType.String()))

	msgID := uuid.New().String()
	logger.Add("message_id", msgID)
	span.SetAttributes(attribute.String("message_id", msgID))

	msg := &pb.ScannerToGatewayMessage{
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
		logger.Add("message_routing_key", pParams.Key)
		span.SetAttributes(attribute.String("message_routing_key", pParams.Key))
	}

	if len(pParams.Headers) > 0 {
		if msg.Headers == nil {
			msg.Headers = make(map[string]string)
		}

		maps.Copy(msg.Headers, pParams.Headers)
		logger.Add("message_headers_count", len(pParams.Headers))
		span.SetAttributes(attribute.Int("message_headers_count", len(pParams.Headers)))
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

	isCritical := reliability.IsCriticalEvent(event.Type)
	logger.Add("message_is_critical", isCritical)
	span.SetAttributes(attribute.Bool("message_is_critical", isCritical))

	var ackChan <-chan error
	if isCritical {
		ackChan = b.ackTracker.TrackMessage(msgID)
		logger.Debug(ctx, "Created acknowledgment channel for critical message",
			"message_id", msgID,
			"event_type", string(event.Type))
	}

	if err := b.stream.Send(msg); err != nil {
		if isCritical {
			b.ackTracker.StopTracking(msgID)
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

	go func() {
		const defaultAckTimeout = 30 * time.Second

		childCtx, childSpan := b.tracer.Start(ctx, "WaitForAcknowledgment",
			trace.WithAttributes(
				attribute.String("message_id", msgID),
				attribute.String("event_type", string(event.Type)),
			),
		)
		defer childSpan.End()

		ackErr := b.ackTracker.WaitForAcknowledgment(childCtx, msgID, ackChan, defaultAckTimeout)
		if ackErr != nil {
			childSpan.RecordError(ackErr)
			childSpan.SetStatus(codes.Error, ackErr.Error())
			b.logger.Error(childCtx, "Acknowledgment failed",
				"message_id", msgID,
				"event_type", string(event.Type),
				"error", ackErr)
			return
		}

		childSpan.AddEvent("message_acknowledged_successfully")
		childSpan.SetStatus(codes.Ok, "acknowledgment successful")
		b.logger.Debug(childCtx, "Message acknowledged successfully",
			"message_id", msgID,
			"event_type", string(event.Type))
	}()

	span.AddEvent("message_sent_awaiting_acknowledgment")
	span.SetStatus(codes.Ok, "message sent, acknowledgment being processed asynchronously")
	logger.Debug(ctx, "Message sent, waiting for acknowledgment in background")

	return nil
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

	if b.state.isClosed() {
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

	// Register handler for each event type
	for _, evtType := range eventTypes {
		b.handlerRegistry.registerHandler(evtType, handler)
		logger.Debug(ctx, "Subscribed to event type", "event_type", evtType)
		span.AddEvent("subscribed_to_event_type")
		span.SetAttributes(attribute.String("event_type", string(evtType)))
	}

	span.SetStatus(codes.Ok, "Successfully subscribed to events")
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

	for !b.state.isClosed() {
		ctx, span := b.tracer.Start(ctx, "EventBus.receiveLoop.recv")
		msg, err := b.stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) || b.state.isClosed() {
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
func (b *EventBus) processGatewayMessage(msg *pb.GatewayToScannerMessage) {
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

		// Handle acknowledgments for critical messages.
		if eventType == protocol.EventTypeMessageAck {
			if ack, ok := protoPayload.(*pb.MessageAcknowledgment); ok {
				b.processAcknowledgment(callbackCtx, ack)
				span.AddEvent("acknowledgment_processed")
				span.SetStatus(codes.Ok, "acknowledgment processed successfully")
				return nil
			}
		}

		// Get handlers for this event type using handlerRegistry
		handlers, exists := b.handlerRegistry.getHandlers(eventType)
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

				ackMsg := &pb.ScannerToGatewayMessage{
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

	span.SetAttributes(attribute.String("event_type", string(eventType)))
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

// processAcknowledgment handles acknowledgment messages received from the gateway.
// For critical events, this will resolve the waiting acknowledgment channel,
// allowing the original publisher to continue execution.
//
// The method:
// 1. Looks up the acknowledgment channel for the original message ID
// 2. If found, sends the result (success or error) to the channel
// 3. Logs the outcome for observability
//
// This completes the "critical event acknowledgment" pattern where publishers
// of important events wait for confirmation of successful processing.
func (b *EventBus) processAcknowledgment(ctx context.Context, ack *pb.MessageAcknowledgment) {
	logger := b.logger.With("original_message_id", ack.GetOriginalMessageId())
	ctx, span := b.tracer.Start(ctx, "EventBus.processAcknowledgment",
		trace.WithAttributes(
			attribute.String("original_message_id", ack.GetOriginalMessageId()),
		),
	)
	defer span.End()

	originalMsgID := ack.GetOriginalMessageId()
	span.SetAttributes(attribute.String("original_message_id", originalMsgID))

	var ackErr error
	if !ack.GetSuccess() {
		errMsg := ack.GetErrorMessage()
		ackErr = fmt.Errorf("message processing failed: %s", errMsg)
		span.RecordError(ackErr)
		span.SetStatus(codes.Error, ackErr.Error())
		span.AddEvent("negative_acknowledgment_received")
		logger.Error(ctx, "Received negative acknowledgment", "error_message", errMsg)
	} else {
		span.AddEvent("positive_acknowledgment_received")
		span.SetStatus(codes.Ok, "positive acknowledgment received")
		logger.Debug(ctx, "Received positive acknowledgment")
	}

	if !b.ackTracker.ResolveAcknowledgment(ctx, originalMsgID, ackErr) {
		// This could happen if the acknowledgment arrived after a timeout
		// or for a non-critical message that doesn't require acknowledgment.
		span.SetStatus(codes.Ok, "no acknowledgment channel found")
		span.RecordError(fmt.Errorf("no acknowledgment channel found for message ID: %s", originalMsgID))
		logger.Debug(ctx, "Received acknowledgment for unknown or expired message ID")
		return
	}

	span.AddEvent("acknowledgment_resolved")
}

// Close gracefully shuts down the event bus and releases associated resources.
// It cancels any pending operations, closes the connection, and ensures that
// the receive loop is terminated before returning.
func (b *EventBus) Close() error {
	if b.state.isClosed() {
		return nil
	}

	b.state.setClosed()
	b.cancelFunc()

	b.ackTracker.CleanupAll(b.ctx, errors.New("event bus closed"))

	// Wait for receiver goroutine to exit.
	select {
	case <-b.receiverDone:
		// Receiver has exited.
	case <-time.After(5 * time.Second):
		// Timed out waiting for receiver to exit.
	}

	return b.stream.CloseSend()
}
