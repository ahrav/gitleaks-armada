package subscription

import (
	"context"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/infra/messaging/protocol"
)

// ScannerStream represents a gRPC stream connection to a scanner.
// It abstracts the transport layer allowing the gateway to send messages
// to scanners without directly depending on gRPC implementation details.
type ScannerStream interface {
	// Send sends a message to the scanner over the stream.
	Send(*protocol.GatewayToScannerMessage) error

	// Context returns the context associated with this stream.
	Context() context.Context
}

// MessageConverter transforms domain events into messages that can be sent to scanners.
// This adapter function allows the gateway to translate between its internal event-driven
// architecture and the protobuf-based communication protocol used with scanners.
type MessageConverter func(ctx context.Context, evt events.EventEnvelope) (*protocol.GatewayToScannerMessage, error)

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
