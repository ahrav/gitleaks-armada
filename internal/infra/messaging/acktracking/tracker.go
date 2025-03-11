package acktracking

import (
	"context"
	"time"
)

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
