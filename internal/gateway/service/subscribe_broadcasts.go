// Package gateway implements the scanner gateway service.
package gateway

import (
	"context"
	"errors"
	"fmt"
	"io"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	protoCodes "google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/internal/infra/messaging/connections"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
	"github.com/ahrav/gitleaks-armada/pkg/common/uuid"
	pb "github.com/ahrav/gitleaks-armada/proto"
)

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
	broadcastConn := connections.NewScannerConnection(
		scannerID,
		stream,
		nil,
		"",
		s.timeProvider,
		s.logger,
		s.tracer,
	)

	// Send acknowledgment for the initial message
	messageID := initMsg.GetMessageId()
	if err := s.sendBroadcastAcknowledgment(ctx, broadcastConn, messageID); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "Failed to send broadcast acknowledgment")
		logger.Error(ctx, "Failed to send broadcast acknowledgment", "error", err)
		return status.Errorf(protoCodes.Internal, "Failed to send broadcast acknowledgment: %v", err)
	}
	span.AddEvent("broadcast_acknowledgment_sent")
	logger.Info(ctx, "Broadcast acknowledgment sent")

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

// sendBroadcastAcknowledgment sends an acknowledgment for a broadcast message.
func (s *Service) sendBroadcastAcknowledgment(
	ctx context.Context,
	conn *connections.ScannerConnection,
	messageID string,
) error {
	logger := s.logger.With("operation", "sendBroadcastAcknowledgment", "message_id", messageID)
	ctx, span := s.tracer.Start(ctx, "gateway.sendBroadcastAcknowledgment",
		trace.WithAttributes(
			attribute.String("message_id", messageID),
		),
	)
	defer span.End()

	ack := &pb.MessageAcknowledgment{OriginalMessageId: messageID, Success: true, ScannerId: conn.ScannerID}
	msg := &pb.GatewayToScannerMessage{
		MessageId: uuid.New().String(),
		Timestamp: s.timeProvider.Now().UnixNano(),
		Payload:   &pb.GatewayToScannerMessage_Ack{Ack: ack},
	}

	if err := conn.SendMessage(ctx, msg); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "Failed to send broadcast acknowledgment")
		return fmt.Errorf("failed to send broadcast acknowledgment: %w", err)
	}
	span.AddEvent("broadcast_acknowledgment_message_sent")
	logger.Debug(ctx, "Sent broadcast acknowledgment message")
	s.metrics.IncMessagesSent(ctx, "broadcast_acknowledgment")

	return nil
}

// subscribeToBroadcastEvents subscribes to broadcast events that should be distributed
// to all scanners, such as job control commands (pause, cancel) and system notifications.
func (s *Service) subscribeToBroadcastEvents(
	ctx context.Context,
	scannerID string,
	conn *connections.ScannerConnection,
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
func (s *Service) handleBroadcastMessages(ctx context.Context, conn *connections.ScannerConnection) error {
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
	conn *connections.ScannerConnection,
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
