package subscription_test

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/infra/messaging/acktracking"
	"github.com/ahrav/gitleaks-armada/internal/infra/messaging/subscription"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
	"github.com/ahrav/gitleaks-armada/pkg/common/timeutil"
	"github.com/ahrav/gitleaks-armada/proto"
)

// --- Mocks and test doubles ---

// MockEventBus implements events.EventBus for testing.
type MockEventBus struct {
	SubscribeFunc func(ctx context.Context, eventTypes []events.EventType, handler events.HandlerFunc) error
	PublishFunc   func(ctx context.Context, event events.EventEnvelope, opts ...events.PublishOption) error
	CloseFunc     func() error
}

func (m *MockEventBus) Subscribe(ctx context.Context, eventTypes []events.EventType, handler events.HandlerFunc) error {
	return m.SubscribeFunc(ctx, eventTypes, handler)
}
func (m *MockEventBus) Publish(ctx context.Context, event events.EventEnvelope, opts ...events.PublishOption) error {
	return m.PublishFunc(ctx, event, opts...)
}
func (m *MockEventBus) Close() error {
	return m.CloseFunc()
}

// MockScannerStream implements the ScannerStream interface.
type MockScannerStream struct {
	SendFunc    func(*proto.GatewayToScannerMessage) error
	ContextFunc func() context.Context
}

func (m *MockScannerStream) Send(msg *proto.GatewayToScannerMessage) error { return m.SendFunc(msg) }
func (m *MockScannerStream) Context() context.Context                      { return m.ContextFunc() }

// MockConverter simulates message conversion.
type MockConverter struct {
	ConvertFunc func(ctx context.Context, evt events.EventEnvelope) (*proto.GatewayToScannerMessage, error)
}

func (mc *MockConverter) Convert(ctx context.Context, evt events.EventEnvelope) (*proto.GatewayToScannerMessage, error) {
	return mc.ConvertFunc(ctx, evt)
}

// We also need to test the ack logic. Usually, EventBus's Subscribe passes a handler with
// signature:  func(ctx context.Context, envelope events.EventEnvelope, ack events.AckFunc) error
// We'll create a test scenario that simulates firing these handlers.

func TestEventSubscriptionHandlerSubscribeSuccess(t *testing.T) {
	synctest.Run(func() {
		tracer := noop.NewTracerProvider().Tracer("test")

		// This mock event bus will just store the handlers for invocation later.
		handlers := make(map[events.EventType]events.HandlerFunc)
		mockBus := &MockEventBus{
			SubscribeFunc: func(ctx context.Context, eventTypes []events.EventType, handler events.HandlerFunc) error {
				// For simplicity, we just store the last eventType => handler.
				for _, et := range eventTypes {
					handlers[et] = handler
				}
				return nil
			},
			PublishFunc: func(context.Context, events.EventEnvelope, ...events.PublishOption) error { return nil },
			CloseFunc:   func() error { return nil },
		}

		mockLogger := logger.Noop()
		ackTracker := acktracking.NewTracker(mockLogger)

		// Create the subscription handler under test.
		subHandler := subscription.NewEventSubscriptionHandler(
			mockBus,
			ackTracker,
			20*time.Millisecond, // ackTimeout
			timeutil.Default(),
			mockLogger,
			tracer,
		)

		ctx := context.Background()
		const (
			testEventA = "TestEventA"
			testEventB = "TestEventB"
		)
		eventTypes := []events.EventType{testEventA, testEventB}

		// We'll need a mock scanner stream to pass along to Subscribe.
		scannerStream := &MockScannerStream{
			SendFunc:    func(*proto.GatewayToScannerMessage) error { return nil },
			ContextFunc: func() context.Context { return ctx },
		}

		converter := func(ctx context.Context, e events.EventEnvelope) (*proto.GatewayToScannerMessage, error) {
			return &proto.GatewayToScannerMessage{MessageId: "generated-message-id"}, nil
		}

		err := subHandler.Subscribe(ctx, "scanner-123", scannerStream, eventTypes, converter)
		assert.NoError(t, err, "Subscribe should succeed")
		// Verify that mockBus.SubscribeFunc was called for each event type.
		assert.Equal(t, 2, len(handlers), "expected two event handlers to be registered")

		// Prepare to simulate a "scanner ack" in the background so
		// WaitForAcknowledgment doesn't time out.
		go func() {
			ackTracker.ResolveAcknowledgment(context.Background(), "generated-message-id", nil)
		}()

		// Simulate an event being received by the bus. We want to see if the
		// subscription handler attempts to convert and send the message properly.
		envelope := events.EventEnvelope{Key: "ev-1", Type: testEventA}

		ackCalled := make(chan error, 1)
		ackFunc := func(err error) { ackCalled <- err }

		// Now call the stored handler for "TestEventA".
		handlerA := handlers[testEventA]
		err = handlerA(context.Background(), envelope, ackFunc)
		assert.NoError(t, err, "handler function should succeed when sending and waiting for ack")

		// Verify that the ack function was called.
		synctest.Wait()
		err = <-ackCalled
		assert.NoError(t, err, "ack function should be called to signal the event was processed")
	})
}

func TestEventSubscriptionHandlerSubscribeFailureOnBusSubscribe(t *testing.T) {
	// Provide a SubscribeFunc that returns an error.
	mockBus := &MockEventBus{
		SubscribeFunc: func(ctx context.Context, et []events.EventType, h events.HandlerFunc) error {
			return errors.New("subscription failed")
		},
		PublishFunc: func(context.Context, events.EventEnvelope, ...events.PublishOption) error { return nil },
		CloseFunc:   func() error { return nil },
	}

	mockLogger := logger.Noop()
	ackTracker := acktracking.NewTracker(mockLogger)
	tracer := noop.NewTracerProvider().Tracer("test")

	subHandler := subscription.NewEventSubscriptionHandler(
		mockBus,
		ackTracker,
		20*time.Millisecond,
		timeutil.Default(),
		mockLogger,
		tracer,
	)

	ctx := context.Background()
	eventTypes := []events.EventType{"TestEventA"}
	scannerStream := &MockScannerStream{
		SendFunc:    func(*proto.GatewayToScannerMessage) error { return nil },
		ContextFunc: func() context.Context { return ctx },
	}

	converter := func(context.Context, events.EventEnvelope) (*proto.GatewayToScannerMessage, error) {
		return &proto.GatewayToScannerMessage{}, nil
	}

	err := subHandler.Subscribe(ctx, "scanner-ABC", scannerStream, eventTypes, converter)
	assert.Error(t, err, "expected error due to subscription failure")
	assert.Contains(t, err.Error(), "subscription failed", "error message should reference the underlying cause")
}

// Tests that if the converter fails, the event is acked with error and the subscription
// handler returns an error from its handler function.
func TestEventSubscriptionHandlerSubscribeConverterError(t *testing.T) {
	synctest.Run(func() {
		// We'll store the event handler to invoke it directly.
		var eventHandler events.HandlerFunc
		mockBus := &MockEventBus{
			SubscribeFunc: func(ctx context.Context, et []events.EventType, h events.HandlerFunc) error {
				eventHandler = h
				return nil
			},
			PublishFunc: func(context.Context, events.EventEnvelope, ...events.PublishOption) error { return nil },
			CloseFunc:   func() error { return nil },
		}

		mockLogger := logger.Noop()
		ackTracker := acktracking.NewTracker(mockLogger)
		tracer := noop.NewTracerProvider().Tracer("test")

		subHandler := subscription.NewEventSubscriptionHandler(
			mockBus,
			ackTracker,
			20*time.Millisecond,
			timeutil.Default(),
			mockLogger,
			tracer,
		)

		ctx := context.Background()
		err := subHandler.Subscribe(
			ctx,
			"scanner-XYZ",
			&MockScannerStream{},
			[]events.EventType{"TestEvent"},
			func(_ context.Context, _ events.EventEnvelope) (*proto.GatewayToScannerMessage, error) {
				return nil, errors.New("converter exploded")
			},
		)
		assert.NoError(t, err, "subscribe itself should succeed since bus doesn't fail")

		// Now simulate an event from the bus.
		envelope := events.EventEnvelope{Type: "TestEvent"}
		ackCalled := make(chan error, 1)
		ackFunc := func(err error) { ackCalled <- err } // we expect an error

		handleErr := eventHandler(context.Background(), envelope, ackFunc)
		assert.Error(t, handleErr, "expected an error from the event handler because the converter failed")

		synctest.Wait()
		err = <-ackCalled
		assert.Error(t, err, "the ack function should be called with the converter error")
	})
}

// If stream.Send fails, we expect the subscription handler to ack with error,
// and stop tracking. We simulate that scenario here.
func TestEventSubscriptionHandlerSubscribeSendFails(t *testing.T) {
	synctest.Run(func() {
		var eventHandler events.HandlerFunc
		mockBus := &MockEventBus{
			SubscribeFunc: func(ctx context.Context, et []events.EventType, h events.HandlerFunc) error {
				eventHandler = h
				return nil
			},
			PublishFunc: func(context.Context, events.EventEnvelope, ...events.PublishOption) error { return nil },
			CloseFunc:   func() error { return nil },
		}

		mockLogger := logger.Noop()
		ackTracker := acktracking.NewTracker(mockLogger)
		tracer := noop.NewTracerProvider().Tracer("test")

		subHandler := subscription.NewEventSubscriptionHandler(
			mockBus,
			ackTracker,
			20*time.Millisecond,
			timeutil.Default(),
			mockLogger,
			tracer,
		)

		ctx := context.Background()
		scannerStream := &MockScannerStream{
			SendFunc:    func(*proto.GatewayToScannerMessage) error { return errors.New("network failure") },
			ContextFunc: func() context.Context { return ctx },
		}

		converter := func(_ context.Context, _ events.EventEnvelope) (*proto.GatewayToScannerMessage, error) {
			return &proto.GatewayToScannerMessage{MessageId: "msg-1"}, nil
		}

		err := subHandler.Subscribe(ctx, "scanner-ABC", scannerStream, []events.EventType{"FailEvent"}, converter)
		assert.NoError(t, err, "subscription should succeed for the bus")

		// Now simulate receiving an event.
		ackCalled := make(chan error, 1)
		ackFunc := func(e error) { ackCalled <- e } // we expect a "network failure" error

		envelope := events.EventEnvelope{Type: "FailEvent"}
		handleErr := eventHandler(context.Background(), envelope, ackFunc)
		assert.Error(t, handleErr, "handler should fail because Send failed")
		assert.Contains(t, handleErr.Error(), "network failure")

		synctest.Wait()
		err = <-ackCalled
		assert.Error(t, err, "ack should have been called with the error")
	})
}

// If we send the message successfully but the ack never arrives, WaitForAcknowledgment
// will time out. We verify that the handler returns an error in that scenario.
func TestEventSubscriptionHandlerSubscribeAckTimeout(t *testing.T) {
	synctest.Run(func() {
		var eventHandler events.HandlerFunc
		mockBus := &MockEventBus{
			SubscribeFunc: func(ctx context.Context, et []events.EventType, h events.HandlerFunc) error {
				eventHandler = h
				return nil
			},
			PublishFunc: func(context.Context, events.EventEnvelope, ...events.PublishOption) error { return nil },
			CloseFunc:   func() error { return nil },
		}

		mockLogger := logger.Noop()
		ackTracker := acktracking.NewTracker(mockLogger)
		tracer := noop.NewTracerProvider().Tracer("test")

		// We set a short ackTimeout.
		subHandler := subscription.NewEventSubscriptionHandler(
			mockBus,
			ackTracker,
			5*time.Millisecond, // short for test
			timeutil.Default(),
			mockLogger,
			tracer,
		)

		ctx := context.Background()
		scannerStream := &MockScannerStream{
			SendFunc:    func(*proto.GatewayToScannerMessage) error { return nil },
			ContextFunc: func() context.Context { return ctx },
		}

		converter := func(_ context.Context, _ events.EventEnvelope) (*proto.GatewayToScannerMessage, error) {
			return &proto.GatewayToScannerMessage{MessageId: "msg-timeout"}, nil
		}

		err := subHandler.Subscribe(ctx, "scanner-timeout", scannerStream, []events.EventType{"TimeoutEvent"}, converter)
		assert.NoError(t, err, "subscribe should not fail")

		// In order to simulate the ack never arriving, we will purposefully not call
		// "ackTracker.ResolveAcknowledgment" in the background.

		ackCalled := make(chan error, 1)
		ackFunc := func(e error) { ackCalled <- e } // we expect a timeout error

		envelope := events.EventEnvelope{Type: "TimeoutEvent"}
		handleErr := eventHandler(context.Background(), envelope, ackFunc)
		assert.NoError(t, handleErr, "handler should succeed")

		synctest.Wait()
		handleErr = <-ackCalled
		// Because the ack never arrives, WaitForAcknowledgment should time out
		assert.Error(t, handleErr)
		assert.Contains(t, handleErr.Error(), "context deadline exceeded", "expected a timeout error")
	})
}
