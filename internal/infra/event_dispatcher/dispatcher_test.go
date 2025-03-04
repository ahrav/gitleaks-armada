package eventdispatcher

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

// mockEventHandler is a test implementation of the EventHandler interface
type mockEventHandler struct {
	mu              sync.Mutex
	supportedEvents []events.EventType
	handleFunc      func(ctx context.Context, evt events.EventEnvelope) error
	callCount       int
}

func (m *mockEventHandler) SupportedEvents() []events.EventType { return m.supportedEvents }

func (m *mockEventHandler) HandleEvent(ctx context.Context, evt events.EventEnvelope, ack events.AckFunc) error {
	m.mu.Lock()
	m.callCount++
	m.mu.Unlock()

	err := m.handleFunc(ctx, evt)
	// Only acknowledge if no error.
	if err == nil {
		ack(nil)
	}
	return err
}

func newTestEventHandler(eventTypes []events.EventType, handlerFn func(ctx context.Context, evt events.EventEnvelope) error) *mockEventHandler {
	return &mockEventHandler{supportedEvents: eventTypes, handleFunc: handlerFn}
}

func newTestDispatcher() *Dispatcher {
	mockTracer := noop.NewTracerProvider().Tracer("")
	mockLogger := logger.Noop()
	return New("test-controller", mockTracer, mockLogger)
}

func createTestAckFunc() events.AckFunc {
	return func(err error) {}
}

// TestEventRouting tests that events are routed to the correct handlers.
func TestEventRouting(t *testing.T) {
	ctx := context.Background()
	d := newTestDispatcher()

	eventType1 := events.EventType("test.event1")
	eventType2 := events.EventType("test.event2")

	handler1 := newTestEventHandler(
		[]events.EventType{eventType1},
		func(ctx context.Context, evt events.EventEnvelope) error {
			return nil
		},
	)

	handler2 := newTestEventHandler(
		[]events.EventType{eventType2},
		func(ctx context.Context, evt events.EventEnvelope) error {
			return nil
		},
	)

	require.NoError(t, d.RegisterHandler(ctx, handler1))
	require.NoError(t, d.RegisterHandler(ctx, handler2))

	evt1 := events.EventEnvelope{Type: eventType1}
	evt2 := events.EventEnvelope{Type: eventType2}

	require.NoError(t, d.Dispatch(ctx, evt1, createTestAckFunc()))
	require.NoError(t, d.Dispatch(ctx, evt2, createTestAckFunc()))

	assert.Equal(t, 1, handler1.callCount)
	assert.Equal(t, 1, handler2.callCount)
}

// TestHandlerErrors tests error handling behavior.
func TestHandlerErrors(t *testing.T) {
	ctx := context.Background()
	d := newTestDispatcher()

	eventType := events.EventType("test.event")
	expectedErr := errors.New("handler error")

	handler := newTestEventHandler(
		[]events.EventType{eventType},
		func(ctx context.Context, evt events.EventEnvelope) error { return expectedErr },
	)
	require.NoError(t, d.RegisterHandler(ctx, handler))

	evt := events.EventEnvelope{Type: eventType}
	err := d.Dispatch(ctx, evt, createTestAckFunc())

	require.Error(t, err)
	assert.Contains(t, err.Error(), expectedErr.Error())
}

// TestMissingHandler tests behavior when no handler exists.
func TestMissingHandler(t *testing.T) {
	ctx := context.Background()
	d := newTestDispatcher()

	eventType := events.EventType("test.event")
	evt := events.EventEnvelope{Type: eventType}

	err := d.Dispatch(ctx, evt, createTestAckFunc())

	require.Error(t, err)
	assert.IsType(t, &HandlerNotFoundError{}, err)
}

// TestHandlerRegistrationConflict tests behavior when registering duplicate handlers.
func TestHandlerRegistrationConflict(t *testing.T) {
	ctx := context.Background()
	d := newTestDispatcher()

	eventType := events.EventType("test.event")

	handler1 := newTestEventHandler(
		[]events.EventType{eventType},
		func(ctx context.Context, evt events.EventEnvelope) error { return nil },
	)

	handler2 := newTestEventHandler(
		[]events.EventType{eventType},
		func(ctx context.Context, evt events.EventEnvelope) error { return nil },
	)

	require.NoError(t, d.RegisterHandler(ctx, handler1))

	// Register second handler (should fail).
	err := d.RegisterHandler(ctx, handler2)
	require.Error(t, err)
	assert.IsType(t, &HandlerAlreadyRegisteredError{}, err)
}

// TestConcurrentDispatch tests behavior with concurrent dispatches.
func TestConcurrentDispatch(t *testing.T) {
	ctx := context.Background()
	d := newTestDispatcher()

	eventType := events.EventType("test.event")

	var counter int
	var mu sync.Mutex

	handler := newTestEventHandler(
		[]events.EventType{eventType},
		func(ctx context.Context, evt events.EventEnvelope) error {
			mu.Lock()
			counter++
			mu.Unlock()
			return nil
		},
	)

	require.NoError(t, d.RegisterHandler(ctx, handler))

	// Dispatch concurrently.
	evt := events.EventEnvelope{Type: eventType}
	var wg sync.WaitGroup
	numGoroutines := 10

	for range numGoroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = d.Dispatch(ctx, evt, createTestAckFunc())
		}()
	}
	wg.Wait()

	assert.Equal(t, numGoroutines, handler.callCount)
}
