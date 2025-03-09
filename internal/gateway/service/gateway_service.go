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
	"sync"
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

// GatewayMetrics defines the metrics interface for the gateway service.
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
func WithAuthKey(key string) GatewayServiceOption {
	return func(g *Service) { g.authKey = key }
}

// acknowledgmentTracker manages pending acknowledgments for outgoing messages.
// It provides thread-safe operations for tracking and resolving acknowledgments.
// TODO: We can add metrics around timings of acks.
type acknowledgmentTracker struct {
	mu      sync.RWMutex
	pending map[string]chan error
}

// newAcknowledgmentTracker creates a new acknowledgment tracker.
func newAcknowledgmentTracker() *acknowledgmentTracker {
	return &acknowledgmentTracker{pending: make(map[string]chan error)}
}

// trackMessage starts tracking a message that requires acknowledgment.
// It returns a channel that will receive the acknowledgment result.
func (t *acknowledgmentTracker) trackMessage(messageID string) chan error {
	ackChan := make(chan error, 1)

	t.mu.Lock()
	t.pending[messageID] = ackChan
	t.mu.Unlock()

	return ackChan
}

// resolveAcknowledgment resolves the acknowledgment for a message.
// It sends the error (or nil for success) to the waiting channel if one exists.
// Returns true if the message was being tracked, false otherwise.
func (t *acknowledgmentTracker) resolveAcknowledgment(ctx context.Context, messageID string, err error) bool {
	span := trace.SpanFromContext(ctx)
	span.SetAttributes(
		attribute.String("message_id", messageID),
		attribute.Bool("success", err == nil),
	)

	t.mu.RLock()
	ackChan, exists := t.pending[messageID]
	t.mu.RUnlock()
	if !exists {
		span.AddEvent("unknown_message_id")
		return false
	}

	ackChan <- err

	t.mu.Lock()
	delete(t.pending, messageID)
	t.mu.Unlock()
	span.AddEvent("resolved_acknowledgment")

	return true
}

// stopTracking stops tracking a message without resolving its acknowledgment.
// This is useful for timeouts or when cleaning up.
func (t *acknowledgmentTracker) stopTracking(messageID string) {
	t.mu.Lock()
	delete(t.pending, messageID)
	t.mu.Unlock()
}

// scannerRegistry manages the collection of connected scanners.
// It provides thread-safe operations for registering, accessing, and removing scanners.
type scannerRegistry struct {
	mu       sync.RWMutex
	scanners map[string]*scannerConnection
	metrics  GatewayMetrics
}

// newScannerRegistry creates a new scanner registry.
func newScannerRegistry(metrics GatewayMetrics) *scannerRegistry {
	return &scannerRegistry{scanners: make(map[string]*scannerConnection), metrics: metrics}
}

// register adds a scanner connection to the registry.
// If a scanner with the same ID already exists, it will be replaced.
// This call always succeeds.
func (r *scannerRegistry) register(ctx context.Context, scannerID string, conn *scannerConnection) {
	span := trace.SpanFromContext(ctx)
	span.SetAttributes(attribute.String("scanner_id", scannerID))
	span.AddEvent("registering_scanner")

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.scanners[scannerID]; exists {
		span.AddEvent("scanner_already_registered")
	}
	r.scanners[scannerID] = conn
	span.AddEvent("scanner_registered")

	r.metrics.IncConnectedScanners(ctx)
	r.metrics.SetConnectedScanners(ctx, len(r.scanners))
}

// unregister removes a scanner connection from the registry.
// Returns true if the scanner was found and removed, false otherwise.
func (r *scannerRegistry) unregister(ctx context.Context, scannerID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	span := trace.SpanFromContext(ctx)
	span.SetAttributes(attribute.String("scanner_id", scannerID))
	span.AddEvent("unregistering_scanner")

	if _, exists := r.scanners[scannerID]; !exists {
		span.AddEvent("scanner_not_found")
		return false
	}
	delete(r.scanners, scannerID)
	span.AddEvent("scanner_unregistered")

	r.metrics.DecConnectedScanners(ctx)
	r.metrics.SetConnectedScanners(ctx, len(r.scanners))

	return true
}

// get retrieves a scanner connection by ID.
// Returns the connection and true if found, nil and false otherwise.
func (r *scannerRegistry) get(scannerID string) (*scannerConnection, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	conn, exists := r.scanners[scannerID]
	return conn, exists
}

// count returns the number of registered scanners.
func (r *scannerRegistry) count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.scanners)
}

// forEach executes a function for each registered scanner.
// The registry is locked for reading during the iteration.
func (r *scannerRegistry) forEach(f func(scannerID string, conn *scannerConnection)) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for id, conn := range r.scanners {
		f(id, conn)
	}
}

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

	// Core dependencies.
	eventPublisher events.DomainEventPublisher
	eventBus       events.EventBus // For regular scanner-specific events
	broadcastBus   events.EventBus // For broadcast events to all scanners

	// Active scanner connections and broadcast connections

	// scanners tracks all primary scanner connections established via ConnectScanner.
	// These connections handle scanner-specific commands and events, enabling
	// direct communication with individual scanners for tasks and status updates.
	// The registry maintains the mapping between scanner IDs and their connection state.
	scanners *scannerRegistry

	// broadcastScanners tracks connections established via SubscribeToBroadcasts.
	// These connections are dedicated to system-wide events, and job control commands
	// that need to reach all scanners, enabling efficient distribution of broadcast
	// messages without interrupting the primary command channels.
	broadcastScanners *scannerRegistry

	// Track outgoing messages that require acknowledgment.
	// Critical for reliability and ensuring scanners process important commands.
	ackTracker *acknowledgmentTracker

	// Authentication settings.
	// TODO: This will likely get ripped out of here and put into an interceptor.
	authKey string // If empty, authentication is disabled

	timeProvider timeutil.Provider

	// Observability.
	logger  *logger.Logger
	metrics GatewayMetrics
	tracer  trace.Tracer
}

// scannerConnection tracks the state of a connected scanner.
type scannerConnection struct {
	id           string                                        // Scanner ID
	stream       pb.ScannerGatewayService_ConnectScannerServer // gRPC stream
	connected    time.Time                                     // When the scanner connected
	lastActivity time.Time                                     // Last time we received a message
	capabilities []string                                      // Scanner capabilities
	version      string                                        // Scanner version
}

// NewService creates a new instance of the gateway service.
// It requires both a regular event bus for scanner-specific events and a
// broadcast event bus for events that should go to all scanners.
// The service translates between domain events and gRPC protocol messages,
// maintaining bidirectional communication with connected scanners.
func NewService(
	eventPublisher events.DomainEventPublisher,
	eventBus events.EventBus,
	broadcastBus events.EventBus,
	logger *logger.Logger,
	metrics GatewayMetrics,
	tracer trace.Tracer,
	options ...GatewayServiceOption,
) *Service {
	svc := &Service{
		eventPublisher:    eventPublisher,
		eventBus:          eventBus,
		broadcastBus:      broadcastBus,
		scanners:          newScannerRegistry(metrics),
		broadcastScanners: newScannerRegistry(metrics),
		ackTracker:        newAcknowledgmentTracker(),
		timeProvider:      timeutil.Default(),
		logger:            logger,
		metrics:           metrics,
		tracer:            tracer,
	}

	for _, opt := range options {
		opt(svc)
	}

	return svc
}

// ConnectScanner handles a bidirectional gRPC stream connection from a scanner.
// The first message must be a ScannerRegistrationRequest to establish the connection.
// All subsequent messages are handled via streaming with acknowledgments for critical messages.
func (s *Service) ConnectScanner(stream pb.ScannerGatewayService_ConnectScannerServer) error {
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

	conn := &scannerConnection{
		id:           scannerID,
		stream:       stream,
		connected:    s.timeProvider.Now(),
		lastActivity: s.timeProvider.Now(),
		capabilities: regRequest.Capabilities,
		version:      regRequest.Version,
	}

	s.scanners.register(ctx, scannerID, conn)
	logger.Info(ctx, "Scanner registered")
	span.AddEvent("scanner_registered")

	if err := s.sendRegistrationResponse(ctx, stream, scannerID, msgID); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		s.scanners.unregister(ctx, scannerID)
		return fmt.Errorf("failed to send registration response: %w", err)
	}
	logger.Info(ctx, "Registration response sent")
	span.AddEvent("registration_response_sent")

	if err := s.subscribeToEvents(ctx, scannerID); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		s.scanners.unregister(ctx, scannerID)
		return fmt.Errorf("failed to subscribe to events: %w", err)
	}
	logger.Info(ctx, "Subscribed to events")
	span.AddEvent("subscribed_to_events")

	if err = s.handleScannerMessages(ctx, conn); err != nil {
		s.scanners.unregister(ctx, scannerID)

		span.SetStatus(codes.Error, err.Error())
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	logger.Info(ctx, "Scanner connection closed")
	return nil
}

// processIncomingScannerMessage handles a message from a scanner and sends acknowledgment for critical messages.
func (s *Service) processIncomingScannerMessage(
	ctx context.Context,
	conn *scannerConnection,
	msg *pb.ScannerToGatewayMessage,
) error {
	ctx, span := s.tracer.Start(ctx, "gateway.processIncomingScannerMessage",
		trace.WithAttributes(
			attribute.String("scanner_id", conn.id),
			attribute.String("message_id", msg.MessageId),
		),
	)
	defer span.End()

	logger := s.logger.With(
		"component", "gateway.processIncomingScannerMessage",
		"scanner_id", conn.id,
		"message_id", msg.MessageId,
	)

	conn.lastActivity = s.timeProvider.Now()
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
		ackErr := s.sendMessageAcknowledgment(ctx, conn, msg.MessageId, processingErr == nil, processingErr)
		if ackErr != nil {
			logger.Error(ctx, "Failed to send message acknowledgment", "error", ackErr)
			span.RecordError(ackErr)
			// We don't return the ack error as it's secondary to the processing error
		}
	}

	return processingErr
}

// processAcknowledgment handles acknowledgment messages received from scanners.
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

	originalMsgID := ack.GetOriginalMessageId()

	var err error
	if !ack.GetSuccess() {
		errMsg := ack.GetErrorMessage()
		err = fmt.Errorf("message processing failed: %s", errMsg)
		span.AddEvent("negative_acknowledgment_received")
		logger.Error(ctx, "Received negative acknowledgment", "error_message", errMsg)
	} else {
		span.AddEvent("positive_acknowledgment_received")
		logger.Debug(ctx, "Received positive acknowledgment")
	}

	if !s.ackTracker.resolveAcknowledgment(ctx, originalMsgID, err) {
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
	conn *scannerConnection,
	messageID string,
	success bool,
	processingErr error,
) error {
	logger := s.logger.With(
		"component", "gateway.sendMessageAcknowledgment",
		"message_id", messageID,
		"success", success,
	)
	ctx, span := s.tracer.Start(ctx, "gateway.sendMessageAcknowledgment",
		trace.WithAttributes(
			attribute.String("message_id", messageID),
			attribute.Bool("success", success),
		),
	)
	defer span.End()

	ack := &pb.MessageAcknowledgment{OriginalMessageId: messageID, Success: success, ScannerId: conn.id}

	if !success && processingErr != nil {
		logger.Warn(ctx, "Failed to process message, sending negative acknowledgment", "error", processingErr)
		span.AddEvent("sending_negative_acknowledgment")
		ack.ErrorMessage = processingErr.Error()
	}

	gatewayMsg := &pb.GatewayToScannerMessage{MessageId: messageID}
	if err := grpcbus.SetGatewayToScannerPayload(gatewayMsg, grpcbus.EventTypeMessageAck, ack); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("failed to set acknowledgment payload: %w", err)
	}

	if err := conn.stream.Send(gatewayMsg); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
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

	conn, exists := s.scanners.get(scannerID)
	if !exists {
		span.SetStatus(codes.Error, "Scanner not found")
		span.RecordError(fmt.Errorf("scanner not found: %s", scannerID))
		return fmt.Errorf("scanner not found: %s", scannerID)
	}

	// We are only interested in the non-broadcast events that need to be routed
	// from the controller -> scanner through this gateway.
	eventTypes := []events.EventType{
		scanning.EventTypeTaskCreated,
		scanning.EventTypeTaskResume,
		rules.EventTypeRulesRequested,
		// We'll want to listen for system notifications too
		grpcbus.EventTypeSystemNotification,
	}

	// Handler for gateway→scanner commands.
	// This handler converts domain events to gateway messages and sends them to scanners.
	// Unlike the scanner→gateway direction which uses criticality-based reliability,
	// all commands from gateway to scanner are treated as critical and must be acknowledged.
	handler := func(ctx context.Context, evt events.EventEnvelope, ack events.AckFunc) error {
		ctx, span := s.tracer.Start(ctx, "gateway.subscribeToEvents.handler",
			trace.WithAttributes(
				attribute.String("event_type", string(evt.Type)),
			),
		)
		defer span.End()

		// Convert domain event to scanner message.
		msg, err := s.convertToScannerMessage(ctx, evt)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "Failed to convert domain event to scanner message")
			logger.Error(ctx, "Failed to convert domain event to scanner message",
				"event_type", evt.Type,
				"error", err)
			s.metrics.IncTranslationErrors(ctx, "outgoing")
			ack(err)
			return nil // Continue processing other events
		}
		span.AddEvent("domain_message_converted_to_scanner_message")

		// All messages from gateway to scanner are critical commands requiring acknowledgment.
		ackChan := s.ackTracker.trackMessage(msg.MessageId)

		// Send the message to the scanner.
		if err := conn.stream.Send(msg); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "Failed to send message to scanner")
			logger.Error(ctx, "Failed to send message to scanner",
				"event_type", evt.Type,
				"error", err)

			// Clean up the acknowledgment tracking
			s.ackTracker.stopTracking(msg.MessageId)

			ack(err)
			return nil // Continue processing other events
		}

		span.AddEvent("message_sent_to_scanner")
		s.metrics.IncMessagesSent(ctx, string(evt.Type))
		logger.Debug(ctx, "Sent message to scanner", "event_type", evt.Type)

		// Wait for acknowledgment with timeout
		const defaultAckTimeout = 30 * time.Second
		timeoutCtx, cancel := context.WithTimeout(ctx, defaultAckTimeout)
		defer cancel()

		select {
		case err := <-ackChan:
			// No need to clean up as resolveAcknowledgment already did this

			if err != nil {
				span.RecordError(err)
				span.SetStatus(codes.Error, "Scanner acknowledged with error")
				logger.Error(ctx, "Scanner acknowledged message with error",
					"event_type", evt.Type,
					"error", err)
				ack(err)
				return nil
			}

			span.SetStatus(codes.Ok, "Command acknowledged successfully")
			logger.Debug(ctx, "Scanner acknowledged command successfully", "event_type", evt.Type)
			ack(nil)
			return nil

		case <-timeoutCtx.Done():
			// The acknowledgment timed out
			s.ackTracker.stopTracking(msg.MessageId)

			err := fmt.Errorf("acknowledgment timeout for message: %s", msg.MessageId)
			span.RecordError(err)
			span.SetStatus(codes.Error, "Acknowledgment timeout")
			logger.Error(ctx, "Acknowledgment timeout for command",
				"event_type", evt.Type,
				"message_id", msg.MessageId)
			ack(err)
			return nil
		}
	}

	return s.eventBus.Subscribe(ctx, eventTypes, handler)
}

// handleScannerMessages processes incoming messages from a connected scanner.
// It maintains the connection and routes messages to appropriate handlers,
// updating activity timestamps and handling disconnections gracefully.
func (s *Service) handleScannerMessages(ctx context.Context, conn *scannerConnection) error {
	logger := s.logger.With("operation", "handleScannerMessages", "scanner_id", conn.id)

	for {
		ctx, span := s.tracer.Start(ctx, "gateway.handleScannerMessages",
			trace.WithAttributes(
				attribute.String("scanner_id", conn.id),
				attribute.String("scanner_version", conn.version),
				attribute.String("last_activity_ts", conn.lastActivity.Format(time.RFC3339Nano)),
			),
		)

		if ctx.Err() != nil {
			span.SetStatus(codes.Error, "Context cancelled")
			span.RecordError(ctx.Err())
			span.End()
			return ctx.Err()
		}

		// Consume messages from the scanner.
		msg, err := conn.stream.Recv()
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "Error receiving message from scanner")
			span.End()
			s.scanners.unregister(ctx, conn.id)
			return fmt.Errorf("error receiving message from scanner: %w", err)
		}
		span.AddEvent("message_received_from_scanner",
			trace.WithAttributes(
				attribute.String("message_id", msg.GetMessageId()),
			),
		)

		conn.lastActivity = s.timeProvider.Now()

		if err := s.processIncomingScannerMessage(ctx, conn, msg); err != nil {
			// Continue processing messages unless it's a critical error.
			if status.Code(err) == protoCodes.Internal {
				span.RecordError(err)
				span.SetStatus(codes.Error, "Error processing message from scanner")
				span.End()
				s.scanners.unregister(ctx, conn.id)
				return err
			}
			span.RecordError(err)
			span.SetStatus(codes.Error, "Non-critical error processing message from scanner")
			logger.Warn(ctx, "Non-critical error processing message from scanner", "error", err)
		}
		span.End()
	}
}

// Helper to track metrics based on message type
func (g *Service) trackMessageMetrics(ctx context.Context, messageType string) {
	g.metrics.IncMessagesReceived(ctx, messageType)

	// Track additional metrics based on the message type
	switch messageType {
	case "heartbeat":
		g.metrics.IncScannerHeartbeats(ctx)
	case "scanner_registered":
		g.metrics.IncScannerRegistrations(ctx)
	case "scan_result":
		g.metrics.IncScanResults(ctx)
	case "task_progressed":
		g.metrics.IncTaskProgress(ctx)
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
	stream pb.ScannerGatewayService_ConnectScannerServer,
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

	if err := stream.Send(resp); err != nil {
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

// getMessageType extracts the message type from a GatewayToScannerMessage for logging and metrics.
func getMessageType(msg *pb.GatewayToScannerMessage) string {
	switch {
	case msg.GetTaskCreated() != nil:
		return "task_created"
	case msg.GetTaskResume() != nil:
		return "task_resume"
	case msg.GetJobPaused() != nil:
		return "job_paused"
	case msg.GetJobCancelled() != nil:
		return "job_cancelled"
	case msg.GetNotification() != nil:
		return "notification"
	// case msg.GetRegistrationResponse() != nil:
	// 	return "registration_response"
	default:
		return "unknown"
	}
}

// SubscribeToBroadcasts handles connections for broadcast events that should be delivered to all scanners.
// This separate stream is unidirectional (gateway to scanner) and allows efficient
// distribution of system-wide events like job control commands and notifications.
func (s *Service) SubscribeToBroadcasts(stream pb.ScannerGatewayService_SubscribeToBroadcastsServer) error {
	logger := s.logger.With("method", "SubscribeToBroadcasts")
	ctx, span := s.tracer.Start(stream.Context(), "gateway.SubscribeToBroadcasts")
	defer span.End()

	// Receive the initial message
	initMsg, err := stream.Recv()
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "Failed to receive initial message")
		return status.Errorf(protoCodes.Internal, "Failed to receive initial message: %v", err)
	}

	// Get scanner ID from the message
	var scannerID string
	if reg := initMsg.GetScannerRegistered(); reg != nil {
		scannerID = reg.GetScannerName()
	} else {
		scannerID = initMsg.GetScannerId()
	}

	if scannerID == "" {
		span.SetStatus(codes.Error, "Scanner ID is required")
		return status.Errorf(protoCodes.InvalidArgument, "Scanner ID is required")
	}

	logger = logger.With("scanner_id", scannerID)
	span.SetAttributes(attribute.String("scanner_id", scannerID))
	logger.Info(ctx, "Scanner requesting broadcast subscription")

	// Verify scanner is already registered via regular connection
	_, regularExists := s.scanners.get(scannerID)
	if !regularExists {
		span.SetStatus(codes.Error, "Scanner not registered via primary connection")
		logger.Error(ctx, "Scanner not registered via primary connection")
		return status.Errorf(protoCodes.FailedPrecondition,
			"Scanner must be registered via primary connection before subscribing to broadcasts")
	}

	// Check if scanner already has a broadcast connection
	existingBroadcastConn, broadcastExists := s.broadcastScanners.get(scannerID)
	if broadcastExists {
		logger.Warn(ctx, "Scanner reconnecting broadcast stream while existing connection is active",
			"existing_connection_time", existingBroadcastConn.connected)

		// Remove existing broadcast connection
		s.broadcastScanners.unregister(ctx, scannerID)
	}

	// Create the broadcast connection record
	broadcastConn := &scannerConnection{
		id:           scannerID,
		stream:       stream,
		connected:    s.timeProvider.Now(),
		lastActivity: s.timeProvider.Now(),
	}

	// Store the broadcast connection
	s.broadcastScanners.register(ctx, scannerID, broadcastConn)
	broadcastCount := s.broadcastScanners.count()

	logger.Info(ctx, "Broadcast connection established",
		"broadcast_scanners_count", broadcastCount)

	// Subscribe to broadcast events
	if err := s.subscribeToBroadcastEvents(ctx, scannerID, stream); err != nil {
		logger.Error(ctx, "Failed to subscribe to broadcast events", "error", err)
		span.RecordError(err)
		span.SetStatus(codes.Error, "Failed to subscribe to broadcast events")

		// Remove the broadcast connection
		s.broadcastScanners.unregister(ctx, scannerID)

		return status.Error(protoCodes.Internal, "Failed to set up broadcast event subscription")
	}

	// Continue receiving messages from the scanner to keep the connection alive
	// and handle any messages that need to be processed (like acknowledgments)
	err = s.handleBroadcastMessages(ctx, broadcastConn, stream)

	// Clean up broadcast connection on exit
	s.broadcastScanners.unregister(ctx, scannerID)

	return err
}

// subscribeToBroadcastEvents sets up subscriptions for broadcast events.
// It creates event handlers that convert domain events to protocol messages
// and distribute them to connected scanners through the broadcast channel.
func (s *Service) subscribeToBroadcastEvents(
	ctx context.Context,
	scannerID string,
	stream pb.ScannerGatewayService_ConnectScannerServer,
) error {
	logger := s.logger.With("method", "subscribeToBroadcastEvents", "scanner_id", scannerID)

	// Define broadcast event types - system-wide events that all scanners should receive.
	// These generally include job control events and system notifications.
	broadcastEventTypes := []events.EventType{
		scanning.EventTypeJobPausing,
		scanning.EventTypeJobPaused,
		scanning.EventTypeJobResuming,
		scanning.EventTypeJobCancelling,
		scanning.EventTypeJobCancelled,
		grpcbus.EventTypeSystemNotification,
	}

	// Set up handler for broadcast events
	handler := func(ctx context.Context, evt events.EventEnvelope, ack events.AckFunc) error {
		// Convert domain event to gateway message
		gatewayMsg, err := s.convertToScannerMessage(ctx, evt)
		if err != nil {
			logger.Error(ctx, "Failed to convert domain event to gateway message",
				"event_type", evt.Type, "error", err)
			s.metrics.IncTranslationErrors(ctx, "domain_to_gateway")
			if ack != nil {
				ack(err) // Acknowledge with error
			}
			return nil // Skip this event but continue processing others
		}

		// Send the broadcast message to this scanner
		if err := stream.Send(gatewayMsg); err != nil {
			logger.Error(ctx, "Failed to send broadcast event to scanner",
				"event_type", evt.Type, "error", err)
			if ack != nil {
				ack(err) // Acknowledge with error
			}
			return err
		}

		// Track metrics
		s.metrics.IncMessagesSent(ctx, getMessageType(gatewayMsg))

		// Acknowledge successful processing
		if ack != nil {
			ack(nil)
		}

		return nil
	}

	// Subscribe to broadcast events via the broadcast event bus
	// This ensures we're listening to the dedicated broadcast topics
	return s.broadcastBus.Subscribe(ctx, broadcastEventTypes, handler)
}

// handleBroadcastMessages processes incoming messages on the broadcast stream.
func (s *Service) handleBroadcastMessages(
	ctx context.Context,
	conn *scannerConnection,
	stream pb.ScannerGatewayService_ConnectScannerServer,
) error {
	logger := s.logger.With("method", "handleBroadcastMessages", "scanner_id", conn.id)

	for {
		// Check if context is done
		select {
		case <-ctx.Done():
			logger.Info(ctx, "Context cancelled, closing broadcast stream")
			return ctx.Err()
		default:
			// Continue processing
		}

		// Receive message from scanner
		msg, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				logger.Info(ctx, "Scanner disconnected from broadcast stream")
				return nil
			}
			logger.Error(ctx, "Error receiving message from scanner", "error", err)
			return err
		}

		// Process the message (primarily for acknowledgments)
		if err := s.processBroadcastMessage(ctx, conn, msg); err != nil {
			logger.Error(ctx, "Error processing broadcast message from scanner", "error", err)
			// Continue rather than failing the entire connection
		}
	}
}

// processBroadcastMessage handles messages from scanners on the broadcast stream.
// This is mainly for acknowledgments and specific broadcast-related events.
//
// In the broadcast stream, we only expect to receive acknowledgments from scanners.
// These acknowledgments confirm receipt and processing of broadcast commands sent by the gateway.
// Unlike Kafka which tracks consumer offsets automatically, our system relies on
// these explicit application-level acknowledgments to confirm message delivery.
//
// The absence of more robust handling of acknowledgments (like retries or tracking)
// is a limitation compared to Kafka's persistence model. In a Kafka-based system,
// failed message processing would be retried automatically based on consumer offset commits.
func (s *Service) processBroadcastMessage(
	ctx context.Context,
	conn *scannerConnection,
	msg *pb.ScannerToGatewayMessage,
) error {
	// Update last activity timestamp
	conn.lastActivity = time.Now()

	// For broadcast, we only expect acknowledgments
	if ack := msg.GetAck(); ack != nil {
		// Process acknowledgment
		s.metrics.IncMessagesReceived(ctx, "acknowledgment")
		// No further action needed for acknowledgments
		return nil
	}

	// Any other message types on broadcast stream are unexpected
	s.metrics.IncMessagesReceived(ctx, "unexpected_broadcast")
	s.logger.Warn(ctx, "Unexpected message type on broadcast stream",
		"scanner_id", conn.id, "message_id", msg.GetMessageId())
	return nil
}
