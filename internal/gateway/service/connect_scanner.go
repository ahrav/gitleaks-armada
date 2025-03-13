// Package gateway implements the scanner gateway service.
package gateway

import (
	"context"
	"errors"
	"fmt"
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
	"github.com/ahrav/gitleaks-armada/internal/infra/messaging/connections"
	"github.com/ahrav/gitleaks-armada/internal/infra/messaging/protocol"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
	"github.com/ahrav/gitleaks-armada/pkg/common/uuid"
	pb "github.com/ahrav/gitleaks-armada/proto"
)

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

	conn := connections.NewScannerConnection(
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
func (s *Service) handleScannerMessages(ctx context.Context, conn *connections.ScannerConnection) error {
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

// sendRegistrationResponse sends a registration response to a scanner.
func (s *Service) sendRegistrationResponse(
	ctx context.Context,
	conn *connections.ScannerConnection,
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

// processIncomingScannerMessage handles a message from a scanner and sends acknowledgment for critical messages.
func (s *Service) processIncomingScannerMessage(
	ctx context.Context,
	conn *connections.ScannerConnection,
	msg *pb.ScannerToGatewayMessage,
) error {
	ctx, span := s.tracer.Start(ctx, "gateway.processIncomingScannerMessage",
		trace.WithAttributes(
			attribute.String("scanner_id", conn.ScannerID),
			attribute.String("message_id", msg.GetMessageId()),
		),
	)
	defer span.End()

	msgID := msg.GetMessageId()
	logger := logger.NewLoggerContext(s.logger.With(
		"component", "gateway.processIncomingScannerMessage",
		"scanner_id", conn.ScannerID,
		"message_id", msgID,
	))

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
	if eventType == protocol.EventTypeMessageAck {
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
	case scanning.EventTypeScannerRegistered:
		span.AddEvent("scanner_registered_received")
		if event, ok := payload.(scanning.ScannerRegisteredEvent); ok {
			domainEvent = event
			evtType = scanning.EventTypeScannerRegistered
		}

	case scanning.EventTypeScannerHeartbeat:
		span.AddEvent("scanner_heartbeat_received")
		if event, ok := payload.(scanning.ScannerHeartbeatEvent); ok {
			domainEvent = event
			evtType = scanning.EventTypeScannerHeartbeat
		}
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

	case rules.EventTypeRulesUpdated:
		span.AddEvent("rules_updated_received")
		if event, ok := payload.(rules.RuleUpdatedEvent); ok {
			domainEvent = event
			evtType = rules.EventTypeRulesUpdated
		}

	default:
		err := fmt.Errorf("unknown event type: %s", eventType)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	logger.Add("event_type", string(evtType))

	processingErr := s.publishDomainEvent(ctx, evtType, domainEvent, options...)
	if processingErr != nil {
		span.RecordError(processingErr)
		span.SetStatus(codes.Error, processingErr.Error())
		logger.Error(ctx, "Failed to publish domain event", "error", processingErr)
	} else {
		span.AddEvent("domain_event_published")
	}

	if isCritical {
		ackErr := s.sendMessageAcknowledgment(ctx, conn, msgID, processingErr)
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
		errMsg := ack.GetErrorMessage()
		ackErr = fmt.Errorf("message processing failed: %s", errMsg)
		span.RecordError(ackErr)
		span.SetStatus(codes.Error, ackErr.Error())
		logger.Error(ctx, "Message processing failed", "error", ackErr)
	} else {
		span.AddEvent("positive_acknowledgment_received")
		span.SetStatus(codes.Ok, "positive acknowledgment received")
		logger.Debug(ctx, "Received positive acknowledgment")
	}

	if !s.ackTracker.ResolveAcknowledgment(ctx, ack.GetOriginalMessageId(), ackErr) {
		// This could happen if the acknowledgment arrived after a timeout
		// or if the message didn't require an acknowledgment
		span.SetStatus(codes.Error, "unknown or expired message ID")
		span.RecordError(fmt.Errorf("no acknowledgment channel found for message ID: %s", ack.GetOriginalMessageId()))
		logger.Debug(ctx, "Received acknowledgment for unknown or expired message ID")
		return
	}

	span.AddEvent("acknowledgment_resolved")
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

// sendMessageAcknowledgment sends an acknowledgment for a critical message.
// TODO: REtry?
// Maybe retry with an interceptor, not sure if that's possible with streaming RPCs.
func (s *Service) sendMessageAcknowledgment(
	ctx context.Context,
	conn *connections.ScannerConnection,
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
