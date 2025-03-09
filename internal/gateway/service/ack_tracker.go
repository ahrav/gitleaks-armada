package gateway

import (
	"context"
	"sync"
	"time"

	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

// AcknowledgmentTracker handles tracking and resolution of message acknowledgments.
//
// Purpose and Role in the Gateway Architecture:
// ---------------------------------------------
// The AcknowledgmentTracker is a component of the gateway service's reliability model.
// Without a persistent message broker like Kafka, this tracker provides application-level
// guarantees that important commands and events are successfully delivered and processed.
//
// In a distributed system where scanners may be located in various network environments,
// ensuring command delivery is essential. This tracker implements the acknowledgment
// half of the reliability contract:
//
// 1. Messages that require acknowledgment are tracked with unique IDs.
// 2. The sender awaits confirmation via channels specific to each message.
// 3. When acknowledgments arrive, they're matched to the original messages.
// 4. Timeouts ensure the system doesn't wait indefinitely for lost acknowledgments.
//
// This approach creates a "at-least-once delivery" semantic similar to what message
// brokers provide, but implemented at the application level over gRPC streams.
//
// Unlike traditional request-response patterns, this tracker allows async acknowledgment
// of messages sent over bidirectional streams, where the acknowledgment may arrive
// much later than when the original message was sent.
// TODO: Add metrics to track number, duration, rate, errors, etc.
// TODO: Make this more reliable, maybe some sort of persistence?
type AcknowledgmentTracker struct {
	mu      sync.RWMutex
	pending map[string]chan error
	logger  *logger.Logger
}

// NewAcknowledgmentTracker creates a new tracker for message acknowledgments.
func NewAcknowledgmentTracker(logger *logger.Logger) *AcknowledgmentTracker {
	return &AcknowledgmentTracker{pending: make(map[string]chan error), logger: logger}
}

// TrackMessage starts tracking a message that requires acknowledgment and
// returns a channel that will receive an error or nil when the message is acknowledged.
//
// When sending a command to a scanner that requires confirmation of processing,
// call this method to begin tracking the message and obtain a channel. When an
// acknowledgment is received, the result will be sent to this channel.
//
// The returned channel is buffered with size 1 to prevent blocking when resolving
// acknowledgments.
func (t *AcknowledgmentTracker) TrackMessage(messageID string) <-chan error {
	t.mu.Lock()
	defer t.mu.Unlock()

	ch := make(chan error, 1)
	t.pending[messageID] = ch
	return ch
}

// ResolveAcknowledgment resolves a pending acknowledgment for a message.
// Returns true if the acknowledgment was successfully resolved, false otherwise.
//
// When an acknowledgment message is received from a scanner, call this method
// to match it with the original message and notify the waiting goroutine.
// The error parameter indicates whether the scanner successfully processed the
// message (nil) or encountered an error (non-nil).
//
// This method is the core of the reliability contract, as it closes the feedback
// loop between command issuance and confirmation of processing.
func (t *AcknowledgmentTracker) ResolveAcknowledgment(ctx context.Context, messageID string, err error) bool {
	t.mu.RLock()
	ch, exists := t.pending[messageID]
	t.mu.RUnlock()

	if !exists {
		t.logger.Debug(ctx, "No pending acknowledgment found for message",
			"message_id", messageID)
		return false
	}

	select {
	case ch <- err:
		// Successfully sent acknowledgment.
	default:
		// Channel already closed or buffer full.
		t.logger.Warn(ctx, "Failed to send acknowledgment to channel",
			"message_id", messageID,
			"error", err)
		return false
	}

	t.StopTracking(messageID)
	return true
}

// StopTracking stops tracking a message.
//
// This is typically called after an acknowledgment has been resolved,
// or when giving up on receiving an acknowledgment (such as after a timeout).
// It prevents memory leaks by cleaning up channels for messages that will
// never receive an acknowledgment.
func (t *AcknowledgmentTracker) StopTracking(messageID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.pending, messageID)
}

// CleanupAll resolves all pending acknowledgments with the given error.
//
// This is typically used during:
// 1. Service shutdown - to prevent goroutines from waiting indefinitely.
// 2. When a scanner connection is closed - to fail all pending commands.
// 3. During error recovery scenarios - to clear the tracking state.
//
// It ensures that all waiting goroutines are unblocked with a meaningful error,
// rather than being left to timeout individually.
func (t *AcknowledgmentTracker) CleanupAll(ctx context.Context, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	count := len(t.pending)
	if count == 0 {
		return
	}

	t.logger.Info(ctx, "Cleaning up pending acknowledgments",
		"count", count,
		"error", err)

	for messageID, ch := range t.pending {
		select {
		case ch <- err:
			// Successfully sent error.
		default:
			// Channel already closed or buffer full.
		}
		delete(t.pending, messageID)
	}
}

// WaitForAcknowledgment waits for an acknowledgment to be received for the given message,
// or until the context is canceled or the timeout is reached.
//
// This method implements the timeout semantics of the acknowledgment system.
// Since network issues, scanner failures, or processing delays could prevent
// an acknowledgment from ever arriving, this method ensures the system won't
// wait forever.
//
// The timeout duration should be chosen based on:
// 1. Expected processing time for the command.
// 2. Network conditions between gateway and scanners.
// 3. Criticality of timely command execution.
func (t *AcknowledgmentTracker) WaitForAcknowledgment(
	ctx context.Context,
	messageID string,
	ackCh <-chan error,
	timeout time.Duration,
) error {
	span := trace.SpanFromContext(ctx)
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	select {
	case err := <-ackCh:
		span.AddEvent("ack_received")
		return err
	case <-timeoutCtx.Done():
		span.AddEvent("timeout_waiting_for_ack")
		t.logger.Warn(ctx, "Timed out waiting for acknowledgment")
		// Clean up the channel since we're no longer waiting.
		t.StopTracking(messageID)
		return timeoutCtx.Err()
	case <-ctx.Done():
		span.AddEvent("context_canceled_while_waiting_for_ack")
		t.logger.Warn(ctx, "Context canceled while waiting for acknowledgment", "message_id", messageID)
		// Clean up the channel since we're no longer waiting.
		t.StopTracking(messageID)
		return ctx.Err()
	}
}
