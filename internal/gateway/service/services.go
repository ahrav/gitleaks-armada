package gateway

import (
	"context"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
)

type AckTracker interface {
	TrackMessage(messageID string) <-chan error
	ResolveAcknowledgment(ctx context.Context, messageID string, err error) bool
	StopTracking(messageID string)
	CleanupAll(ctx context.Context, err error)
}

type EventSubscriptionHandler interface {
	Subscribe(
		ctx context.Context,
		scannerID string,
		stream ScannerStream,
		eventTypes []events.EventType,
		converter MessageConverter,
	) error
}
