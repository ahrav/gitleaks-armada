package gateway

import (
	"context"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	pb "github.com/ahrav/gitleaks-armada/proto"
)

type AckTracker interface {
	TrackMessage(messageID string) <-chan error
	ResolveAcknowledgment(ctx context.Context, messageID string, err error) bool
	StopTracking(messageID string)
	CleanupAll(ctx context.Context, err error)
}

type EventSubscriptionHandler interface {
	Subscribe(ctx context.Context, scannerID string, stream ScannerStream, eventTypes []events.EventType, converter MessageConverter) error
}

type EventSubscriptionManager interface {
	SubscribeToRegularEvents(ctx context.Context, scannerID string, stream ScannerStream, eventTypes []events.EventType) error
	SubscribeToBroadcastEvents(ctx context.Context, scannerID string, stream ScannerStream, eventTypes []events.EventType) error
	ProcessAcknowledgment(ctx context.Context, ack *pb.MessageAcknowledgment) bool
	CleanupTracking(ctx context.Context, scannerID string)
}
