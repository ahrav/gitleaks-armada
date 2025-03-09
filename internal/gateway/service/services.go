package gateway

import (
	"context"
	"time"

	"google.golang.org/grpc"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	grpcbus "github.com/ahrav/gitleaks-armada/internal/infra/eventbus/grpc"
)

// ScannerStream represents a gRPC stream connection to a scanner.
// It abstracts the transport layer allowing the gateway to send messages
// to scanners without directly depending on gRPC implementation details.
type ScannerStream interface {
	// Send sends a message to the scanner over the stream.
	Send(*grpcbus.GatewayToScannerMessage) error

	// Context returns the context associated with this stream.
	Context() context.Context
}

// MessageConverter transforms domain events into messages that can be sent to scanners.
// This adapter function allows the gateway to translate between its internal event-driven
// architecture and the protobuf-based communication protocol used with scanners.
type MessageConverter func(ctx context.Context, evt events.EventEnvelope) (*grpcbus.GatewayToScannerMessage, error)

// AckTracker manages the acknowledgment lifecycle for messages sent to scanners.
// It represents a critical component in the gateway's reliability model, ensuring
// that commands and events are successfully delivered to and processed by scanners
// in distributed environments.
//
// This interface provides methods to:
// - Track outgoing messages and their acknowledgment status
// - Resolve acknowledgments when they arrive from scanners
// - Handle timeout scenarios for unacknowledged messages
// - Clean up tracking resources when connections terminate
type AckTracker interface {
	// TrackMessage begins tracking a message by its ID and returns a channel
	// that will receive an error if acknowledgment fails, or nil on success.
	TrackMessage(messageID string) <-chan error

	// ResolveAcknowledgment handles an incoming acknowledgment for a tracked message.
	// Returns true if the message was being tracked and now resolved, false otherwise.
	ResolveAcknowledgment(ctx context.Context, messageID string, err error) bool

	// StopTracking removes tracking for a specific message, typically when
	// the message is no longer relevant (e.g., on scanner disconnect).
	StopTracking(messageID string)

	// CleanupAll resolves all pending messages with the provided error.
	// Used during shutdown or when a scanner connection is terminated.
	CleanupAll(ctx context.Context, err error)

	// WaitForAcknowledgment blocks until an acknowledgment is received for the
	// message or until the timeout is reached. Returns an error if acknowledgment
	// fails or times out, nil on successful acknowledgment.
	WaitForAcknowledgment(
		ctx context.Context,
		messageID string,
		ackCh <-chan error,
		timeout time.Duration,
	) error
}

// EventSubscriptionHandler manages event subscriptions and delivers events to scanners.
// It implements the bridge between the system's event-driven architecture and the
// gRPC streaming model used to communicate with on-premise scanners.
//
// This interface abstracts the mechanics of event bus subscriptions and delivery,
// allowing higher-level components to focus on subscription coordination without
// dealing with low-level event processing details.
type EventSubscriptionHandler interface {
	// Subscribe creates a subscription for the specified scanner to receive events
	// of the given types. Events are converted to scanner-specific messages and sent
	// through the provided stream. Returns an error if the subscription fails or when
	// the stream is closed.
	Subscribe(
		ctx context.Context,
		scannerID string,
		stream ScannerStream,
		eventTypes []events.EventType,
		converter MessageConverter,
	) error
}

// GatewayScannerStream represents the bidirectional stream between the gateway and a scanner.
// From the gateway's perspective, this interface provides the correct message direction:
// - Gateway sends GatewayToScannerMessage TO the scanner (gateway → scanner)
// - Gateway receives ScannerToGatewayMessage FROM the scanner (scanner → gateway)
//
// This interface is implemented by the gRPC bidirectional stream clients:
// - pb.ScannerGatewayService_ConnectScannerClient
// - pb.ScannerGatewayService_SubscribeToBroadcastsClient
type GatewayScannerStream interface {
	// Send sends a GatewayToScannerMessage from the gateway to the scanner.
	Send(message *grpcbus.GatewayToScannerMessage) error

	// Recv receives a ScannerToGatewayMessage from the scanner to the gateway.
	Recv() (*grpcbus.ScannerToGatewayMessage, error)

	// Embed the ServerStream interface to get all other required methods.
	grpc.ServerStream
}
