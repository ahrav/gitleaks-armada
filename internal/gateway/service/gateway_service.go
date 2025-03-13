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

	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/infra/messaging/acktracking"
	"github.com/ahrav/gitleaks-armada/internal/infra/messaging/registry"
	"github.com/ahrav/gitleaks-armada/internal/infra/messaging/subscription"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
	"github.com/ahrav/gitleaks-armada/pkg/common/timeutil"
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
	scanners *registry.ScannerRegistry

	// broadcastScanners tracks connections established via SubscribeToBroadcasts.
	// These connections are dedicated to system-wide events, and job control commands
	// that need to reach all scanners, enabling efficient distribution of broadcast
	// messages without interrupting the primary command channels.
	broadcastScanners *registry.ScannerRegistry

	// Manages event subscriptions and acknowledgment tracking.
	ackTracker acktracking.AckTracker

	// Handlers for different types of event subscriptions.
	regSubscriptionHandler       subscription.EventSubscriptionHandler
	broadcastSubscriptionHandler subscription.EventSubscriptionHandler

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
	regSubscriptionHandler subscription.EventSubscriptionHandler,
	broadcastSubscriptionHandler subscription.EventSubscriptionHandler,
	logger *logger.Logger,
	metrics GatewayMetrics,
	tracer trace.Tracer,
	options ...GatewayServiceOption,
) *Service {
	s := &Service{
		eventPublisher: eventPublisher,

		// Event subscription handlers.
		ackTracker:                   acktracking.NewTracker(logger),
		regSubscriptionHandler:       regSubscriptionHandler,
		broadcastSubscriptionHandler: broadcastSubscriptionHandler,

		// Registry of connected scanners.
		scanners:          registry.NewScannerRegistry(metrics),
		broadcastScanners: registry.NewScannerRegistry(metrics),

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
