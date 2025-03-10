// Package gateway implements the scanner gateway service that facilitates communication
// between on-premise scanners and the central control system.
//
// gRPC Bidirectional Streaming Architecture:
// ------------------------------------------
// This service uses gRPC bidirectional streaming to maintain persistent connections
// between scanners and the gateway. Unlike traditional request-response patterns, this
// approach establishes a single long-lived connection that allows both sides to send
// messages at any time, enabling real-time event-driven communication.
//
// Connection Lifecycle:
// 1. Initial Connection: A scanner calls ConnectScanner() once to establish the stream
// 2. Registration: The scanner immediately sends a registration message through this stream
// 3. Continuous Communication: After registration, both sides can freely send messages:
//   - Gateway side: handleScannerMessages() continuously receives messages
//   - Scanner side: A dedicated receiveLoop() continuously processes incoming messages
//
// This pattern effectively creates a virtual event bus over gRPC, allowing scanners
// to communicate with the central system regardless of network topology, avoiding
// the need for direct Kafka access from on-premise environments while maintaining
// the event-driven architecture.
//
// Connection Types:
//   - Regular Connection (ConnectScanner): For scanner-specific events and commands
//   - Broadcast Connection (SubscribeToBroadcasts): For broadcast job control events
//     system-wide notifications that need to reach all scanners simultaneously
//
// Reliability Model & Acknowledgments:
// -----------------------------------
// This service implements an asymmetric reliability pattern to balance throughput and reliability:
//
// 1. Gateway → Scanner (Commands):
//   - All messages in this direction are critical commands (StartTask, PauseTask, etc.)
//   - All commands require acknowledgment from scanners to confirm receipt and processing
//   - Commands are sent with unique message IDs that scanners must include in their acks
//   - If a scanner fails to acknowledge, the command may be lost or not executed
//
// 2. Scanner → Gateway (Events):
//   - Messages in this direction have varying levels of criticality
//   - High-frequency, non-critical events (heartbeats, metrics) use fire-and-forget pattern
//   - Critical events (task completion, terminal status updates) require acknowledgment
//   - The EventBus implementation determines message criticality based on event type
//
// Kafka Comparison and Limitations:
// --------------------------------
// This gRPC-based approach serves as a drop-in replacement for a Kafka-based event bus,
// but with some important differences:
//
// - Unlike Kafka, there is no persistent log or replay capability
// - Message delivery depends on active connections rather than durable storage
// - No consumer group semantics or message offset tracking for resuming consumption
// - Application-level acknowledgments provide reliability but without Kafka's durability
//
// TODO: Consider enhancing reliability with local storage buffers to handle temporary
// disconnections and ensure critical messages are never lost, more closely mimicking
// Kafka's durability guarantees.
package gateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	protoCodes "google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/domain/rules"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	grpcbus "github.com/ahrav/gitleaks-armada/internal/infra/eventbus/grpc"
	"github.com/ahrav/gitleaks-armada/internal/infra/eventbus/reliability"
	"github.com/ahrav/gitleaks-armada/internal/infra/eventbus/serialization"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
	"github.com/ahrav/gitleaks-armada/pkg/common/timeutil"
	"github.com/ahrav/gitleaks-armada/pkg/common/uuid"
	pb "github.com/ahrav/gitleaks-armada/proto"
)

// GatewayMetrics interface defines metrics collected by the gateway service.
type GatewayMetrics interface {
	// Connection metrics.
	IncConnectedScanners(ctx context.Context)
	DecConnectedScanners(ctx context.Context)
	SetConnectedScanners(ctx context.Context, count int)

	// Message metrics.
	IncMessagesReceived(ctx context.Context, messageType string)
	IncMessagesSent(ctx context.Context, messageType string)
	IncTranslationErrors(ctx context.Context, direction string)
	IncAuthErrors(ctx context.Context)

	// Domain events metrics from scanner sources.
	IncScannerRegistrations(ctx context.Context)
	IncScannerHeartbeats(ctx context.Context)
	IncScanResults(ctx context.Context)
	IncTaskProgress(ctx context.Context)
}

// GatewayServiceOption is a functional option for configuring the gateway service.
type GatewayServiceOption func(*Service)

// WithAuthKey sets the authentication key for the gateway service.
// When set, all connecting scanners must provide this key for authentication.
// If not set, authentication is disabled.
func WithAuthKey(key string) GatewayServiceOption { return func(g *Service) { g.authKey = key } }

// Service implements the ScannerGatewayService gRPC service.
// It manages bidirectional communication with scanners, translates between
// protocol messages and domain events, and maintains scanner connection state.
//
// The Service acts as a translation layer between two distinct communication patterns:
// 1. gRPC bidirectional streams (for scanner communication)
// 2. Event-driven architecture using the domain event publisher/subscriber model (for internal system communication)
//
// In this dual role, it's responsible for:
//   - Converting domain events to gRPC messages and vice versa
//   - Ensuring reliable delivery of critical messages through acknowledgment tracking
//   - Managing connection state and scanner lifecycle (registration, heartbeats, disconnection)
//   - Enforcing the asymmetric reliability model where commands require acknowledgment
//     and events may use fire-and-forget depending on criticality
type Service struct {
	pb.UnimplementedScannerGatewayServiceServer

	eventPublisher events.DomainEventPublisher

	// Active scanner connections and broadcast connections

	// scanners tracks all primary scanner connections established via ConnectScanner.
	// These connections handle scanner-specific commands and events, enabling
	// direct communication with individual scanners for tasks and status updates.
	// The registry maintains the mapping between scanner IDs and their connection state.
	scanners *ScannerRegistry

	// broadcastScanners tracks connections established via SubscribeToBroadcasts.
	// These connections are dedicated to system-wide events, and job control commands
	// that need to reach all scanners, enabling efficient distribution of broadcast
	// messages without interrupting the primary command channels.
	broadcastScanners *ScannerRegistry

	// Manages event subscriptions and acknowledgment tracking.
	ackTracker AckTracker

	// Handlers for different types of event subscriptions.
	regSubscriptionHandler       EventSubscriptionHandler
	broadcastSubscriptionHandler EventSubscriptionHandler

	// Authentication settings.
	// TODO: This will likely get ripped out of here and put into an interceptor.
	authKey string // If empty, authentication is disabled

	timeProvider timeutil.Provider

	// Observability.
	logger  *logger.Logger
	metrics GatewayMetrics
	tracer  trace.Tracer
}

// NewService creates a new instance of the gateway service.
// It requires both a regular event bus for scanner-specific events and a
// broadcast event bus for events that should be sent to all scanners.
func NewService(
	eventPublisher events.DomainEventPublisher,
	regSubscriptionHandler EventSubscriptionHandler,
	broadcastSubscriptionHandler EventSubscriptionHandler,
	logger *logger.Logger,
	metrics GatewayMetrics,
	tracer trace.Tracer,
	options ...GatewayServiceOption,
) *Service {
	s := &Service{
		eventPublisher: eventPublisher,

		// Event subscription handlers.
		ackTracker:                   NewAcknowledgmentTracker(logger),
		regSubscriptionHandler:       regSubscriptionHandler,
		broadcastSubscriptionHandler: broadcastSubscriptionHandler,

		// Registry of connected scanners.
		scanners:          NewScannerRegistry(metrics),
		broadcastScanners: NewScannerRegistry(metrics),

		// Observability.
		logger:  logger.With("component", "gateway_service"),
		metrics: metrics,
		tracer:  tracer,

		// Time provider.
		timeProvider: timeutil.Default(),
	}

	for _, opt := range options {
		opt(s)
	}

	return s
}

// ConnectScanner handles a bidirectional gRPC stream connection from a scanner.
// The first message must be a ScannerRegistrationRequest to establish the connection.
// All subsequent messages are handled via streaming with acknowledgments for critical messages.
func (s *Service) ConnectScanner(stream pb.ScannerGatewayService_SubscribeToBroadcastsServer) error {
	logger := logger.NewLoggerContext(s.logger.With("component", "gateway.ConnectScanner"))
	ctx, span := s.tracer.Start(stream.Context(), "gateway.ConnectScanner")
	defer span.End()

	initMsg, err := stream.Recv()
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "Failed to receive initial message")
		logger.Error(ctx, "Failed to receive initial message", "error", err)
		return status.Errorf(protoCodes.Internal, "Failed to receive initial message: %v", err)
	}

	// Wait for the first message which **must** be a "ScannerRegistrationRequest".
	msgID := initMsg.GetMessageId()
	if msgID == "" {
		span.RecordError(errors.New("message ID is empty"))
		span.SetStatus(codes.Error, "Message ID is empty")
		logger.Error(ctx, "Message ID is empty")
		return status.Errorf(protoCodes.InvalidArgument, "Message ID is empty")
	}
	logger.Add("message_id", msgID)
	span.SetAttributes(attribute.String("message_id", msgID))

	regRequest := initMsg.GetRegistration()
	if regRequest == nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "First message must be a registration request")
		logger.Error(ctx, "First message must be a registration request")
		return status.Errorf(protoCodes.InvalidArgument, "First message must be a registration request")
	}

	scannerID := regRequest.ScannerName
	if scannerID == "" {
		// TODO: Revist this and maybe return an error. Not sure why we would
		// want to generate a new UUID if the scanner didn't provide a name.
		logger.Warn(ctx, "Scanner name is empty, generating UUID")
		scannerID = uuid.New().String()
		span.AddEvent("scanner_name_empty")
	}
	span.SetAttributes(attribute.String("scanner_id", scannerID))
	logger.Add("scanner_id", scannerID)
	logger.Info(ctx, "Scanner connected")

	// TODO: Move all this auth nonsense into an interceptor.
	if s.authKey != "" && initMsg.GetAuthToken() != s.authKey {
		logger.Warn(ctx, "Scanner authentication failed")
		s.metrics.IncAuthErrors(ctx)
		span.RecordError(errors.New("authentication failed"))
		span.SetStatus(codes.Error, "Authentication failed")
		return status.Errorf(protoCodes.Unauthenticated, "Invalid authentication token")
	}

	logger.Add(
		"scanner_name", regRequest.ScannerName,
		"version", regRequest.Version,
		"hostname", regRequest.Hostname,
		"group", regRequest.GroupName,
		"capabilities", regRequest.Capabilities,
	)
	span.SetAttributes(
		attribute.String("scanner_name", scannerID),
		attribute.String("version", regRequest.Version),
		attribute.String("hostname", regRequest.Hostname),
		attribute.String("group", regRequest.GroupName),
	)

	conn := NewScannerConnection(
		scannerID,
		stream,
		regRequest.Capabilities,
		regRequest.Version,
		s.timeProvider,
		s.logger,
		s.tracer,
	)

	s.scanners.Register(ctx, scannerID, conn)
	logger.Info(ctx, "Scanner registered")
	span.AddEvent("scanner_registered")

	if err := s.sendRegistrationResponse(ctx, conn, scannerID, msgID); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		s.scanners.Unregister(ctx, scannerID)
		return fmt.Errorf("failed to send registration response: %w", err)
	}
	logger.Info(ctx, "Registration response sent")
	span.AddEvent("registration_response_sent")

	if err := s.subscribeToEvents(ctx, scannerID); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		s.scanners.Unregister(ctx, scannerID)
		return fmt.Errorf("failed to subscribe to events: %w", err)
	}
	logger.Info(ctx, "Subscribed to events")
	span.AddEvent("subscribed_to_events")

	if err = s.handleScannerMessages(ctx, conn); err != nil {
		s.scanners.Unregister(ctx, scannerID)

		span.SetStatus(codes.Error, err.Error())
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	s.scanners.Unregister(ctx, scannerID)
	s.ackTracker.CleanupAll(ctx, fmt.Errorf("scanner disconnected: %s", scannerID))
	s.logger.Info(ctx, "Scanner connection closed and resources cleaned up")

	return nil
}

// processIncomingScannerMessage handles a message from a scanner and sends acknowledgment for critical messages.
func (s *Service) processIncomingScannerMessage(
	ctx context.Context,
	conn *ScannerConnection,
	msg *pb.ScannerToGatewayMessage,
) error {
	ctx, span := s.tracer.Start(ctx, "gateway.processIncomingScannerMessage",
		trace.WithAttributes(
			attribute.String("scanner_id", conn.ScannerID),
			attribute.String("message_id", msg.MessageId),
		),
	)
	defer span.End()

	logger := s.logger.With(
		"component", "gateway.processIncomingScannerMessage",
		"scanner_id", conn.ScannerID,
		"message_id", msg.MessageId,
	)

	conn.UpdateActivity(s.timeProvider.Now())
	// messageType := msg.MessageId // Simplified for now

	// s.metrics.IncMessagesReceived(ctx, messageType)

	eventType, payload, err := grpcbus.ExtractScannerMessageInfo(ctx, msg)
	if err != nil {
		logger.Error(ctx, "Failed to extract message info", "error", err)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("failed to extract message info: %w", err)
	}

	// Handle acknowledgement messages earlier to short-circuit the processing.
	if eventType == grpcbus.EventTypeMessageAck {
		span.AddEvent("message_ack_received")
		if ack, ok := payload.(*pb.MessageAcknowledgment); ok {
			s.processAcknowledgment(ctx, ack)
			span.AddEvent("message_ack_processed")
			return nil
		}
	}

	routingKey := msg.GetRoutingKey()
	isCritical := reliability.IsCriticalEvent(eventType)
	span.SetAttributes(attribute.Bool("is_critical", isCritical))
	logger.Debug(ctx, "Processing scanner message",
		"event_type", string(eventType),
		"is_critical", isCritical,
		"routing_key", routingKey,
	)

	var options []events.PublishOption
	if routingKey != "" {
		options = append(options, events.WithKey(routingKey))
	}

	var (
		domainEvent events.DomainEvent
		evtType     events.EventType
	)

	switch eventType {
	case scanning.EventTypeScannerHeartbeat:
		span.AddEvent("scanner_heartbeat_received")
		s.metrics.IncScannerHeartbeats(ctx)

	case scanning.EventTypeTaskProgressed:
		span.AddEvent("task_progressed_received")
		s.metrics.IncTaskProgress(ctx)
		if event, ok := payload.(scanning.TaskProgressedEvent); ok {
			domainEvent = event
			evtType = scanning.EventTypeTaskProgressed
		}

	case scanning.EventTypeTaskCompleted:
		span.AddEvent("task_completed_received")
		if result, ok := payload.(scanning.TaskCompletedEvent); ok {
			domainEvent = result
			evtType = scanning.EventTypeTaskCompleted
		}

	case scanning.EventTypeTaskFailed:
		span.AddEvent("task_failed_received")
		if result, ok := payload.(scanning.TaskFailedEvent); ok {
			s.metrics.IncScanResults(ctx)
			domainEvent = result
			evtType = scanning.EventTypeTaskFailed
		}

	default:
		span.AddEvent("unknown_event_type")
		evtType = eventType
	}

	processingErr := s.publishDomainEvent(ctx, evtType, domainEvent, options...)
	if processingErr != nil {
		span.RecordError(processingErr)
		span.SetStatus(codes.Error, processingErr.Error())
		logger.Error(ctx, "Failed to publish domain event", "error", processingErr)
	} else {
		span.AddEvent("domain_event_published")
	}

	if isCritical {
		ackErr := s.sendMessageAcknowledgment(ctx, conn, msg.MessageId, processingErr)
		if ackErr != nil {
			logger.Error(ctx, "Failed to send message acknowledgment", "error", ackErr)
			span.RecordError(ackErr)
			// We don't return the ack error as it's secondary to the processing error
		}
	}

	return processingErr
}

// processAcknowledgment handles acknowledgment messages from scanners.
// It resolves the waiting acknowledgment channel for the original message.
func (s *Service) processAcknowledgment(ctx context.Context, ack *pb.MessageAcknowledgment) {
	logger := s.logger.With(
		"component", "gateway.processAcknowledgment",
		"original_message_id", ack.GetOriginalMessageId(),
	)
	span := trace.SpanFromContext(ctx)
	span.SetAttributes(
		attribute.String("original_message_id", ack.GetOriginalMessageId()),
		attribute.Bool("success", ack.GetSuccess()),
	)
	defer span.End()

	// Process the acknowledgment using the subscription manager
	var ackErr error
	if !ack.GetSuccess() {
		ackErr = fmt.Errorf("%s", ack.GetErrorMessage())
	}
	if !s.ackTracker.ResolveAcknowledgment(ctx, ack.GetOriginalMessageId(), ackErr) {
		// This could happen if the acknowledgment arrived after a timeout
		// or if the message didn't require an acknowledgment
		span.AddEvent("unknown_message_id")
		logger.Debug(ctx, "Received acknowledgment for unknown or expired message ID")
		return
	}
	span.AddEvent("acknowledgment_resolved")
}

// sendMessageAcknowledgment sends an acknowledgment for a critical message.
// TODO: REtry?
// Maybe retry with an interceptor, not sure if that's possible with streaming RPCs.
func (s *Service) sendMessageAcknowledgment(
	ctx context.Context,
	conn *ScannerConnection,
	messageID string,
	processingErr error,
) error {
	isSuccessful := processingErr == nil
	logger := s.logger.With(
		"component", "gateway.sendMessageAcknowledgment",
		"message_id", messageID,
		"success", isSuccessful,
	)
	ctx, span := s.tracer.Start(ctx, "gateway.sendMessageAcknowledgment",
		trace.WithAttributes(
			attribute.String("message_id", messageID),
			attribute.Bool("success", isSuccessful),
		),
	)
	defer span.End()

	ack := &pb.MessageAcknowledgment{OriginalMessageId: messageID, Success: isSuccessful, ScannerId: conn.ScannerID}

	if !isSuccessful {
		logger.Warn(ctx, "Failed to process message, sending negative acknowledgment", "error", processingErr)
		span.AddEvent("sending_negative_acknowledgment")
		ack.ErrorMessage = processingErr.Error()
	}

	msg := &pb.GatewayToScannerMessage{
		MessageId: uuid.New().String(),
		Timestamp: s.timeProvider.Now().UnixNano(),
		Payload:   &pb.GatewayToScannerMessage_Ack{Ack: ack},
	}

	// Send the acknowledgment back to the scanner.
	// Acknowledgments don't need to be tracked as they don't require acknowledgments themselves.
	if err := conn.SendMessage(ctx, msg); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "Failed to send acknowledgment")
		return fmt.Errorf("failed to send acknowledgment: %w", err)
	}
	span.AddEvent("acknowledgment_message_sent")
	logger.Debug(ctx, "Sent acknowledgment message")
	s.metrics.IncMessagesSent(ctx, "ack")

	return nil
}

// publishDomainEvent publishes a domain event to the event publisher.
// The payload should already implement the events.DomainEvent interface.
func (s *Service) publishDomainEvent(
	ctx context.Context,
	eventType events.EventType,
	payload any,
	opts ...events.PublishOption,
) error {
	ctx, span := s.tracer.Start(ctx, "gateway.publishDomainEvent",
		trace.WithAttributes(
			attribute.String("event_type", string(eventType)),
		),
	)
	defer span.End()

	domainEvent, ok := payload.(events.DomainEvent)
	if !ok {
		span.RecordError(fmt.Errorf("payload does not implement the DomainEvent interface: %T", payload))
		span.SetStatus(codes.Error, fmt.Sprintf("payload does not implement the DomainEvent interface: %T", payload))
		return fmt.Errorf("payload does not implement the DomainEvent interface: %T", payload)
	}

	if domainEvent.EventType() != eventType {
		span.RecordError(fmt.Errorf("event type mismatch: expected %s, got %s", eventType, domainEvent.EventType()))
		span.SetStatus(codes.Error, fmt.Sprintf("event type mismatch: expected %s, got %s", eventType, domainEvent.EventType()))
		return fmt.Errorf("event type mismatch: expected %s, got %s", eventType, domainEvent.EventType())
	}

	if err := s.eventPublisher.PublishDomainEvent(ctx, domainEvent, opts...); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("failed to publish domain event: %w", err)
	}
	span.AddEvent("domain_event_published")

	return nil
}

// subscribeToEvents subscribes to events that should be forwarded to the scanner.
//
// This method implements the gateway→scanner direction of the reliability model:
// - All messages sent from gateway to scanner are treated as critical commands
// - Each command requires explicit acknowledgment from the scanner
// - If a scanner fails to acknowledge, the command is considered failed
//
// This approach differs from a Kafka consumer model in several important ways:
// - No persistent log storage that can be replayed if a scanner disconnects
// - No offset tracking to resume consumption from a known point after reconnection
// - Reliability depends entirely on application-level acknowledgments
//
// TODO: Consider implementing local buffering of commands with retry mechanisms
// to better handle disconnections and provide stronger delivery guarantees.
func (s *Service) subscribeToEvents(ctx context.Context, scannerID string) error {
	logger := s.logger.With("operation", "subscribeToEvents", "scanner_id", scannerID)
	ctx, span := s.tracer.Start(
		ctx,
		"gateway.subscribeToEvents",
		trace.WithAttributes(attribute.String("scanner_id", scannerID)),
	)
	defer span.End()

	conn, exists := s.scanners.Get(scannerID)
	if !exists {
		err := fmt.Errorf("scanner not found: %s", scannerID)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		logger.Error(ctx, "Scanner not found", "error", err)
		return err
	}

	// We are only interested in the non-broadcast events that need to be routed
	// from the controller -> scanner through this gateway.
	eventTypes := []events.EventType{
		// Core task processing events.
		scanning.EventTypeTaskCreated,
		scanning.EventTypeTaskResume,
		scanning.EventTypeTaskPaused,

		// Rule-related events.
		rules.EventTypeRulesRequested,

		// System events.
		grpcbus.EventTypeSystemNotification,
	}

	logger.Info(ctx, "Setting up event subscriptions for scanner",
		"event_types", fmt.Sprintf("%v", eventTypes))

	// Use the regular subscription handler to set up the event subscriptions
	err := s.regSubscriptionHandler.Subscribe(
		ctx,
		scannerID,
		conn.Stream,
		eventTypes,
		s.convertToScannerMessage,
	)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		logger.Error(ctx, "Failed to subscribe to events", "error", err)
		return err
	}

	span.SetStatus(codes.Ok, "Successfully subscribed to events")
	logger.Info(ctx, "Successfully subscribed to events for scanner")
	return nil
}

// handleScannerMessages processes incoming messages from a connected scanner.
// It maintains the connection and routes messages to appropriate handlers,
// updating activity timestamps and handling disconnections gracefully.
func (s *Service) handleScannerMessages(ctx context.Context, conn *ScannerConnection) error {
	logger := s.logger.With("operation", "handleScannerMessages", "scanner_id", conn.ScannerID)

	for {
		ctx, span := s.tracer.Start(ctx, "gateway.handleScannerMessages",
			trace.WithAttributes(
				attribute.String("scanner_id", conn.ScannerID),
				attribute.String("scanner_version", conn.Version),
				attribute.String("last_activity_ts", conn.LastActivity.Format(time.RFC3339Nano)),
			),
		)

		if ctx.Err() != nil {
			span.SetStatus(codes.Error, "Context cancelled")
			span.RecordError(ctx.Err())
			span.End()
			return ctx.Err()
		}

		// Consume messages from the scanner.
		msg, err := conn.ReceiveMessage(ctx)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "Error receiving message from scanner")
			span.End()
			s.scanners.Unregister(ctx, conn.ScannerID)
			return fmt.Errorf("error receiving message from scanner: %w", err)
		}
		span.AddEvent("message_received_from_scanner",
			trace.WithAttributes(
				attribute.String("message_id", msg.GetMessageId()),
			),
		)

		conn.UpdateActivity(s.timeProvider.Now())

		if err := s.processIncomingScannerMessage(ctx, conn, msg); err != nil {
			// Continue processing messages unless it's a critical error.
			if status.Code(err) == protoCodes.Internal {
				span.RecordError(err)
				span.SetStatus(codes.Error, "Error processing message from scanner")
				span.End()
				s.scanners.Unregister(ctx, conn.ScannerID)
				return err
			}
			span.RecordError(err)
			span.SetStatus(codes.Error, "Non-critical error processing message from scanner")
			logger.Warn(ctx, "Non-critical error processing message from scanner", "error", err)
		}
		span.End()
	}
}

// convertToScannerMessage converts a domain event to a scanner message.
//
// This method is a key part of the gateway→scanner reliability model:
//   - It generates a unique message ID for each outgoing message
//   - This ID allows scanners to acknowledge receipt and processing
//   - All messages sent via this method are considered critical commands
//     that require acknowledgment from scanners
//
// The message ID tracking is critical for the acknowledgment system,
// as it creates a correlation between outgoing commands and their acknowledgments,
// similar to how Kafka maintains message offsets but implemented at the application level.
func (s *Service) convertToScannerMessage(
	ctx context.Context,
	evt events.EventEnvelope,
) (*pb.GatewayToScannerMessage, error) {
	span := trace.SpanFromContext(ctx)
	defer span.End()

	// Create the base message.
	msg := &pb.GatewayToScannerMessage{
		MessageId: uuid.New().String(),
		Timestamp: s.timeProvider.Now().UnixNano(),
	}

	protoPayload, err := serialization.DomainEventToProto(evt.Type, evt.Payload)
	if err != nil {
		span.RecordError(err)
		s.metrics.IncTranslationErrors(ctx, "outgoing")
		return nil, fmt.Errorf("failed to convert domain event to proto: %w", err)
	}

	if err := grpcbus.SetGatewayToScannerPayload(msg, evt.Type, protoPayload); err != nil {
		span.RecordError(err)
		s.metrics.IncTranslationErrors(ctx, "outgoing")
		return nil, fmt.Errorf("failed to set gateway message payload: %w", err)
	}
	span.AddEvent("conversion_complete")

	return msg, nil
}

// sendRegistrationResponse sends a registration response to a scanner.
func (s *Service) sendRegistrationResponse(
	ctx context.Context,
	conn *ScannerConnection,
	scannerID string,
	messageID string,
) error {
	logger := s.logger.With("operation", "sendRegistrationResponse",
		"scanner_id", scannerID,
		"message_id", messageID,
		"message_type", "registration_response",
	)
	ctx, span := s.tracer.Start(ctx, "gateway.send_registration_response",
		trace.WithAttributes(
			attribute.String("scanner_id", scannerID),
			attribute.String("message_id", messageID),
			attribute.String("message_type", "registration_response"),
		),
	)
	defer span.End()

	resp := &pb.GatewayToScannerMessage{
		MessageId: messageID,
		Timestamp: s.timeProvider.Now().UnixNano(),
		Payload: &pb.GatewayToScannerMessage_Ack{
			Ack: &pb.MessageAcknowledgment{OriginalMessageId: messageID, Success: true},
		},
	}

	if err := conn.SendMessage(ctx, resp); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "Failed to send registration response")
		return fmt.Errorf("failed to send registration response: %w", err)
	}
	span.AddEvent("registration response sent successfully")
	span.SetStatus(codes.Ok, "successfully sent registration response")
	s.metrics.IncMessagesSent(ctx, "registration_response")
	logger.Info(ctx, "Registration response sent successfully")

	return nil
}

// SubscribeToBroadcasts handles connections for broadcast events that should be delivered to all scanners.
// This separate stream is unidirectional (gateway to scanner) and allows efficient
// distribution of system-wide events like job control commands and notifications.
func (s *Service) SubscribeToBroadcasts(stream pb.ScannerGatewayService_SubscribeToBroadcastsServer) error {
	logger := logger.NewLoggerContext(s.logger.With("method", "SubscribeToBroadcasts"))
	ctx, span := s.tracer.Start(stream.Context(), "gateway.SubscribeToBroadcasts")
	defer span.End()

	initMsg, err := stream.Recv()
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "Failed to receive initial message")
		return status.Errorf(protoCodes.Internal, "Failed to receive initial message: %v", err)
	}

	scannerID := initMsg.GetScannerId()
	if scannerID == "" {
		span.SetStatus(codes.Error, "Scanner ID is required")
		span.RecordError(fmt.Errorf("scanner ID is required"))
		return status.Errorf(protoCodes.InvalidArgument, "Scanner ID is required")
	}

	logger.Add("scanner_id", scannerID)
	span.SetAttributes(attribute.String("scanner_id", scannerID))
	logger.Info(ctx, "Scanner requesting broadcast subscription")

	// Verify scanner is already registered via regular connection.
	// TODO: Is there a scenario in which a scanner doesn't need the regular connection?
	// In which case, we would also need a Registration event for this.
	_, regularExists := s.scanners.Get(scannerID)
	if !regularExists {
		span.SetStatus(codes.Error, "Scanner not registered via primary connection")
		logger.Error(ctx, "Scanner not registered via primary connection")
		return status.Errorf(protoCodes.FailedPrecondition,
			"Scanner must be registered via primary connection before subscribing to broadcasts")
	}

	existingBroadcastConn, broadcastExists := s.broadcastScanners.Get(scannerID)
	if broadcastExists {
		logger.Warn(ctx, "Scanner reconnecting broadcast stream while existing connection is active",
			"existing_connection_time", existingBroadcastConn.Connected)

		// Remove existing broadcast connection.
		s.broadcastScanners.Unregister(ctx, scannerID)
	}

	// Create the broadcast connection record.
	broadcastConn := &ScannerConnection{
		ScannerID:    scannerID,
		Stream:       stream,
		Connected:    s.timeProvider.Now(),
		LastActivity: s.timeProvider.Now(),
	}

	s.broadcastScanners.Register(ctx, scannerID, broadcastConn)
	broadcastCount := s.broadcastScanners.Count()

	logger.Info(ctx, "Broadcast connection established",
		"broadcast_scanners_count", broadcastCount)

	if err := s.subscribeToBroadcastEvents(ctx, scannerID, broadcastConn); err != nil {
		logger.Error(ctx, "Failed to subscribe to broadcast events", "error", err)
		span.RecordError(err)
		span.SetStatus(codes.Error, "Failed to subscribe to broadcast events")

		s.broadcastScanners.Unregister(ctx, scannerID)
		return status.Error(protoCodes.Internal, "Failed to set up broadcast event subscription")
	}
	span.AddEvent("broadcast_event_subscription_established")

	// Continue receiving messages from the scanner to keep the connection alive
	// and handle any messages that need to be processed (like acknowledgments).
	// This will block until the scanner disconnects, or an error occurs.
	if err := s.handleBroadcastMessages(ctx, broadcastConn); err != nil {
		logger.Error(ctx, "Failed to handle broadcast messages", "error", err)
		span.RecordError(err)
		span.SetStatus(codes.Error, "Failed to handle broadcast messages")
	}

	s.broadcastScanners.Unregister(ctx, scannerID)
	s.ackTracker.CleanupAll(ctx, fmt.Errorf("broadcast scanner disconnected: %s", scannerID))
	logger.Info(ctx, "Scanner broadcast connection closed and resources cleaned up")

	return err
}

// subscribeToBroadcastEvents subscribes to broadcast events that should be distributed
// to all scanners, such as job control commands (pause, cancel) and system notifications.
func (s *Service) subscribeToBroadcastEvents(
	ctx context.Context,
	scannerID string,
	conn *ScannerConnection,
) error {
	logger := s.logger.With("method", "subscribeToBroadcastEvents", "scanner_id", scannerID)
	ctx, span := s.tracer.Start(ctx, "gateway.subscribeToBroadcastEvents",
		trace.WithAttributes(
			attribute.String("scanner_id", scannerID),
		),
	)
	defer span.End()

	// Define broadcast event types - system-wide events that all scanners should receive.
	// These generally include job control events and system notifications.
	broadcastEventTypes := []events.EventType{
		scanning.EventTypeJobPaused,
		scanning.EventTypeJobCancelled,
		grpcbus.EventTypeSystemNotification,
	}

	logger.Info(ctx, "Setting up broadcast event subscriptions for scanner",
		"event_types", fmt.Sprintf("%v", broadcastEventTypes))

	// Use the broadcast subscription handler to set up the event subscriptions
	err := s.broadcastSubscriptionHandler.Subscribe(
		ctx,
		scannerID,
		conn.Stream,
		broadcastEventTypes,
		s.convertToScannerMessage,
	)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		logger.Error(ctx, "Failed to subscribe to broadcast events", "error", err)
		return err
	}

	span.SetStatus(codes.Ok, "Successfully subscribed to broadcast events")
	logger.Info(ctx, "Successfully subscribed to broadcast events")
	return nil
}

// handleBroadcastMessages processes incoming messages on the broadcast stream.
func (s *Service) handleBroadcastMessages(ctx context.Context, conn *ScannerConnection) error {
	logger := s.logger.With("method", "handleBroadcastMessages", "scanner_id", conn.ScannerID)

	for {
		select {
		case <-ctx.Done():
			logger.Info(ctx, "Context cancelled, closing broadcast stream")
			return ctx.Err()
		default:
			// Continue processing.
		}

		msg, err := conn.ReceiveMessage(ctx)
		if err != nil {
			if errors.Is(err, io.EOF) {
				logger.Info(ctx, "Scanner disconnected from broadcast stream")
				return nil
			}
			logger.Error(ctx, "Error receiving message from scanner", "error", err)
			// TODO: Should we continue instead? maybe after we add retry we can return an error.
			return err
		}

		// Process the message (primarily for acknowledgments).
		if err := s.processBroadcastMessage(ctx, conn, msg); err != nil {
			logger.Error(ctx, "Error processing broadcast message from scanner", "error", err)
			// Continue rather than failing the entire connection.
		}
	}
}

// processBroadcastMessage handles messages received on broadcast connections.
//
// Unlike regular scanner connections, broadcast connections are optimized for
// one-way (gateway to scanner) communication of system-wide events. The only
// expected message type from scanner to gateway on this connection are
// acknowledgments of received broadcast messages.
//
// This asymmetric design enables efficient handling of broadcast events without
// interfering with scanner-specific command channels, while still maintaining
// delivery guarantees for critical broadcasts.
//
// This approach differs from a Kafka consumer model where consumer groups and
// failed message processing would be retried automatically based on consumer offset commits.
func (s *Service) processBroadcastMessage(
	ctx context.Context,
	conn *ScannerConnection,
	msg *pb.ScannerToGatewayMessage,
) error {
	conn.UpdateActivity(s.timeProvider.Now())

	if ack := msg.GetAck(); ack != nil {
		ctx, span := s.tracer.Start(ctx, "gateway.processBroadcastAcknowledgment",
			trace.WithAttributes(
				attribute.String("original_message_id", ack.GetOriginalMessageId()),
				attribute.Bool("success", ack.GetSuccess()),
			),
		)
		defer span.End()

		originalMsgID := ack.GetOriginalMessageId()

		var ackErr error
		if !ack.GetSuccess() {
			ackErr = fmt.Errorf("scanner reported error: %s", ack.GetErrorMessage())
			span.RecordError(ackErr)
			span.SetStatus(codes.Error, "Scanner reported error processing broadcast message")
		} else {
			span.SetStatus(codes.Ok, "Scanner successfully processed broadcast message")
		}

		// Use the subscription manager to process the acknowledgment
		resolved := s.ackTracker.ResolveAcknowledgment(ctx, originalMsgID, ackErr)
		if !resolved {
			// This can happen if acknowledgment arrived after timeout.
			span.AddEvent("acknowledgment_for_expired_message")
			s.logger.Warn(ctx, "Received broadcast acknowledgment for unknown or expired message ID",
				"scanner_id", conn.ScannerID,
				"original_message_id", originalMsgID)
		} else {
			span.AddEvent("broadcast_acknowledgment_resolved")
			if ackErr != nil {
				s.logger.Error(ctx, "Processed broadcast acknowledgment with error",
					"scanner_id", conn.ScannerID,
					"original_message_id", originalMsgID,
					"error", ackErr)
			} else {
				s.logger.Debug(ctx, "Processed broadcast acknowledgment successfully",
					"scanner_id", conn.ScannerID,
					"original_message_id", originalMsgID)
			}
		}

		s.metrics.IncMessagesReceived(ctx, "broadcast_acknowledgment")
		return nil
	}

	// Any other message types on broadcast stream are unexpected.
	s.metrics.IncMessagesReceived(ctx, "unexpected_broadcast")
	s.logger.Warn(ctx, "Unexpected message type on broadcast stream",
		"scanner_id", conn.ScannerID, "message_id", msg.GetMessageId())
	return nil
}
