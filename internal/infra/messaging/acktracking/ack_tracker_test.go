package acktracking_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/ahrav/gitleaks-armada/internal/infra/messaging/acktracking"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

func TestNewAcknowledgmentTracker(t *testing.T) {
	log := logger.Noop()
	tracker := acktracking.NewTracker(log)
	assert.NotNil(t, tracker, "Expected non-nil tracker")
}

// TestTrackMessageReceivesNilAck verifies that once a message is tracked,
// resolving with nil will unblock the channel with a nil error.
func TestTrackMessageReceivesNilAck(t *testing.T) {
	log := logger.Noop()
	tracker := acktracking.NewTracker(log)

	messageID := "test-track-nil"
	ackCh := tracker.TrackMessage(messageID)

	ok := tracker.ResolveAcknowledgment(context.Background(), messageID, nil)
	assert.True(t, ok, "ResolveAcknowledgment should return true for a tracked message")

	// The channel should receive nil.
	err := <-ackCh
	assert.Nil(t, err, "expected nil error from acknowledgment channel")
}

// TestTrackMessageReceivesErrorAck verifies that once a message is tracked,
// resolving with a non-nil error will unblock the channel with that error.
func TestTrackMessageReceivesErrorAck(t *testing.T) {
	log := logger.Noop()
	tracker := acktracking.NewTracker(log)

	messageID := "test-track-error"
	ackCh := tracker.TrackMessage(messageID)

	resolveErr := errors.New("some ack error")
	ok := tracker.ResolveAcknowledgment(context.Background(), messageID, resolveErr)
	assert.True(t, ok, "ResolveAcknowledgment should return true for a tracked message")

	// The channel should receive the same error.
	err := <-ackCh
	assert.EqualError(t, err, resolveErr.Error(), "expected the channel to receive the resolved error")
}

// TestResolveAcknowledgmentUnknown verifies that resolving a non-existent
// message returns false.
func TestResolveAcknowledgmentUnknown(t *testing.T) {
	log := logger.Noop()
	tracker := acktracking.NewTracker(log)

	messageID := "unknown-id"
	ok := tracker.ResolveAcknowledgment(context.Background(), messageID, nil)
	assert.False(t, ok, "expected ResolveAcknowledgment to return false for unknown message")
}

// TestStopTracking verifies that once we stop tracking a message,
// any subsequent acknowledgment attempts fail.
func TestStopTracking(t *testing.T) {
	log := logger.Noop()
	tracker := acktracking.NewTracker(log)

	messageID := "test-stop-tracking"
	ackCh := tracker.TrackMessage(messageID)

	tracker.StopTracking(messageID)

	// Trying to resolve after stop tracking should fail.
	ok := tracker.ResolveAcknowledgment(context.Background(), messageID, nil)
	assert.False(t, ok, "expected ResolveAcknowledgment to return false after stop tracking")

	// The channel should not receive any new messages.
	select {
	case ackErr := <-ackCh:
		t.Fatalf("expected no ack to be sent on the channel, got %v", ackErr)
	default:
		// No message received, which is correct.
	}
}

// TestCleanupAll verifies that calling CleanupAll sends the provided error
// to all pending channels.
func TestCleanupAll(t *testing.T) {
	log := logger.Noop()
	tracker := acktracking.NewTracker(log)

	msg1 := "test-cleanup-1"
	msg2 := "test-cleanup-2"
	ch1 := tracker.TrackMessage(msg1)
	ch2 := tracker.TrackMessage(msg2)

	cleanupErr := errors.New("cleanup error")
	tracker.CleanupAll(context.Background(), cleanupErr)

	// Both channels should receive the cleanupErr.
	err1 := <-ch1
	err2 := <-ch2

	assert.EqualError(t, err1, cleanupErr.Error(), "channel 1 should receive the cleanup error")
	assert.EqualError(t, err2, cleanupErr.Error(), "channel 2 should receive the cleanup error")
}

// TestWaitForAcknowledgmentReturnsNil checks that WaitForAcknowledgment
// returns nil if the message was resolved with a nil error.
func TestWaitForAcknowledgmentReturnsNil(t *testing.T) {
	log := logger.Noop()
	tracker := acktracking.NewTracker(log)

	ctx := context.Background()
	msgID := "test-wait-success"
	ackCh := tracker.TrackMessage(msgID)

	go func() {
		tracker.ResolveAcknowledgment(ctx, msgID, nil)
	}()

	err := tracker.WaitForAcknowledgment(ctx, msgID, ackCh, time.Second)
	assert.Nil(t, err, "expected WaitForAcknowledgment to return nil after successful acknowledgment")
}

// TestWaitForAcknowledgmentReturnsError checks that WaitForAcknowledgment
// returns the same error that was resolved.
func TestWaitForAcknowledgmentReturnsError(t *testing.T) {
	log := logger.Noop()
	tracker := acktracking.NewTracker(log)

	ctx := context.Background()
	msgID := "test-wait-error"
	ackCh := tracker.TrackMessage(msgID)

	resolveErr := errors.New("processing failed")
	go func() {
		tracker.ResolveAcknowledgment(ctx, msgID, resolveErr)
	}()

	err := tracker.WaitForAcknowledgment(ctx, msgID, ackCh, time.Second)
	assert.EqualError(t, err, resolveErr.Error(), "expected WaitForAcknowledgment to return the same error")
}

// TestWaitForAcknowledgmentTimesOut verifies that WaitForAcknowledgment
// returns an error when the timeout is reached without acknowledgment.
func TestWaitForAcknowledgmentTimesOut(t *testing.T) {
	synctest.Run(func() {
		log := logger.Noop()
		tracker := acktracking.NewTracker(log)

		ctx := context.Background()
		msgID := "test-wait-timeout"
		ackCh := tracker.TrackMessage(msgID)

		const testTimeout = 2 * time.Millisecond
		start := time.Now()
		err := tracker.WaitForAcknowledgment(ctx, msgID, ackCh, testTimeout)
		elapsed := time.Since(start)

		assert.Error(t, err, "expected a timeout error, got nil")
		// Just ensure it took at least the test timeout.
		assert.GreaterOrEqual(t, elapsed.Milliseconds(), testTimeout.Milliseconds(), "should wait the full timeout before returning")
	})
}

// TestWaitForAcknowledgmentContextCancel ensures that if the parent context is canceled,
// WaitForAcknowledgment returns immediately with that error instead of waiting for the timeout.
func TestWaitForAcknowledgmentContextCancel(t *testing.T) {
	log := logger.Noop()
	tracker := acktracking.NewTracker(log)

	msgID := "test-wait-context-cancel"
	ackCh := tracker.TrackMessage(msgID)

	// Cancel the context before any resolution.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := tracker.WaitForAcknowledgment(ctx, msgID, ackCh, 500*time.Millisecond)
	assert.Error(t, err, "expected context canceled error, got nil")
	// Implementation might return context.Canceled or a generic error; assert that it's not nil.
}

// TestConcurrentResolvesNoDataRace ensures no data race or unexpected behavior
// occurs when multiple goroutines call ResolveAcknowledgment for the same message.
func TestConcurrentResolvesNoDataRace(t *testing.T) {
	log := logger.Noop()
	tracker := acktracking.NewTracker(log)

	msgID := "test-concurrent"
	ackCh := tracker.TrackMessage(msgID)

	var wg sync.WaitGroup
	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tracker.ResolveAcknowledgment(context.Background(), msgID, nil)
		}()
	}
	wg.Wait()

	// We only expect one successful write to the channel. The rest may fail or be moot.
	ackErr := <-ackCh
	assert.Nil(t, ackErr, "expected the channel to receive a nil error from one of the resolves")
}

// TestDoubleResolveAcknowledgment verifies that once a message is resolved,
// any subsequent attempts to resolve it will fail.
func TestDoubleResolveAcknowledgment(t *testing.T) {
	log := logger.Noop()
	tracker := acktracking.NewTracker(log)
	ctx := context.Background()

	messageID := "test-message-8"
	ch := tracker.TrackMessage(messageID)

	// First resolution should succeed.
	success1 := tracker.ResolveAcknowledgment(ctx, messageID, nil)
	assert.True(t, success1, "First resolution should succeed")

	select {
	case err := <-ch:
		assert.NoError(t, err, "Expected nil error on acknowledgment")
	default:
		assert.Fail(t, "Timed out waiting for first acknowledgment")
	}

	// Second resolution should fail as the message is no longer tracked.
	success2 := tracker.ResolveAcknowledgment(ctx, messageID, nil)
	assert.False(t, success2, "Second resolution should fail")
}

// TestStopTrackingNonExistentMessage verifies that stopping tracking for a
// non-existent message does not panic.
func TestStopTrackingNonExistentMessage(t *testing.T) {
	log := logger.Noop()
	tracker := acktracking.NewTracker(log)

	// Should not panic when stopping tracking for a non-existent message.
	assert.NotPanics(t, func() {
		tracker.StopTracking("non-existent-message")
	})
}

// TestCleanupAllWithNoMessages verifies that CleanupAll does not panic when
// there are no pending messages.
func TestCleanupAllWithNoMessages(t *testing.T) {
	log := logger.Noop()
	tracker := acktracking.NewTracker(log)
	ctx := context.Background()

	// Should not panic when cleaning up with no pending messages.
	assert.NotPanics(t, func() {
		tracker.CleanupAll(ctx, errors.New("test error"))
	})
}
