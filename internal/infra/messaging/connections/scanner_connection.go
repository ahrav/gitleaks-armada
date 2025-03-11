package connections

import (
	"context"
	"slices"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/infra/messaging/protocol"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
	"github.com/ahrav/gitleaks-armada/pkg/common/timeutil"
)

// ScannerConnection tracks the state of a connected scanner and provides
// methods for interacting with the scanner through its gRPC stream.
// It encapsulates the connection details and provides a clean API for
// sending/receiving messages and managing the connection lifecycle.
type ScannerConnection struct {
	ScannerID    string               // Scanner ID
	Stream       GatewayScannerStream // gRPC stream
	Connected    time.Time            // When the scanner connected
	LastActivity time.Time            // Last time we received a message
	Capabilities []string             // Scanner capabilities
	Version      string               // Scanner version

	timeProvider timeutil.Provider
	logger       *logger.Logger
	tracer       trace.Tracer
}

// NewScannerConnection creates a new scanner connection with the provided details.
func NewScannerConnection(
	id string,
	stream GatewayScannerStream,
	capabilities []string,
	version string,
	timeProvider timeutil.Provider,
	logger *logger.Logger,
	tracer trace.Tracer,
) *ScannerConnection {
	now := timeProvider.Now()
	return &ScannerConnection{
		ScannerID:    id,
		Stream:       stream,
		Connected:    now,
		LastActivity: now,
		Capabilities: capabilities,
		Version:      version,
		timeProvider: timeProvider,
		logger:       logger.With("component", "scanner_connection"),
		tracer:       tracer,
	}
}

// SendMessage sends a message to the scanner and handles any errors.
func (c *ScannerConnection) SendMessage(ctx context.Context, msg *protocol.GatewayToScannerMessage) error {
	ctx, span := c.tracer.Start(ctx, "gateway.ScannerConnection.SendMessage")
	defer span.End()

	span.SetAttributes(
		attribute.String("scanner_id", c.ScannerID),
		attribute.String("message_id", msg.GetMessageId()),
	)

	err := c.Stream.Send(msg)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "Failed to send message")
		c.logger.Error(ctx, "Failed to send message", "error", err)
	}
	span.AddEvent("Message sent")
	span.SetStatus(codes.Ok, "Message sent")

	return err
}

// ReceiveMessage receives a message from the scanner.
func (c *ScannerConnection) ReceiveMessage(ctx context.Context) (*protocol.ScannerToGatewayMessage, error) {
	ctx, span := c.tracer.Start(ctx, "gateway.ScannerConnection.ReceiveMessage")
	defer span.End()

	span.SetAttributes(attribute.String("scanner_id", c.ScannerID))

	msg, err := c.Stream.Recv()
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "Failed to receive message")
		c.logger.Error(ctx, "Failed to receive message", "error", err)
		return nil, err
	}
	span.AddEvent("Message received")
	span.SetStatus(codes.Ok, "Message received")

	return msg, nil
}

// UpdateActivity updates the last activity timestamp for this connection.
func (c *ScannerConnection) UpdateActivity(t time.Time) { c.LastActivity = t }

// HasCapability checks if the scanner has a specific capability.
func (c *ScannerConnection) HasCapability(capability string) bool {
	return slices.Contains(c.Capabilities, capability)
}

// CreateAcknowledgment creates a message acknowledgment response for this scanner.
func (c *ScannerConnection) CreateAcknowledgment(messageID string, success bool, errorMessage string) *protocol.MessageAck {
	return &protocol.MessageAck{
		OriginalMessageId: messageID,
		Success:           success,
		ErrorMessage:      errorMessage,
		ScannerId:         c.ScannerID,
	}
}
