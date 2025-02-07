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

func TestRegisterHandler(t *testing.T) {
	ctx := context.Background()
	log := logger.Noop()
	tracer := noop.NewTracerProvider().Tracer("test")
	d := New("test", tracer, log)

	eventType := events.EventType("test.event")
	handler := func(ctx context.Context, evt events.EventEnvelope, ack events.AckFunc) error {
		return nil
	}

	d.RegisterHandler(ctx, eventType, handler)

	d.mu.RLock()
	registeredHandler, exists := d.handlers[eventType]
	d.mu.RUnlock()

	assert.True(t, exists)
	assert.NotNil(t, registeredHandler)
}

func TestRegisterHandlerReplaceExisting(t *testing.T) {
	ctx := context.Background()
	log := logger.Noop()
	tracer := noop.NewTracerProvider().Tracer("test")
	d := New("test", tracer, log)

	eventType := events.EventType("test.event")
	var handler1Called bool
	handler1 := func(ctx context.Context, evt events.EventEnvelope, ack events.AckFunc) error {
		handler1Called = true
		return nil
	}
	var handler2Called bool
	handler2 := func(ctx context.Context, evt events.EventEnvelope, ack events.AckFunc) error {
		handler2Called = true
		return nil
	}

	d.RegisterHandler(ctx, eventType, handler1)
	d.RegisterHandler(ctx, eventType, handler2)

	// Dispatch an event.
	evt := events.EventEnvelope{
		Type: eventType,
		Metadata: events.EventMetadata{
			Partition: 1,
			Offset:    100,
		},
	}

	err := d.Dispatch(ctx, evt, func(err error) {
		require.NoError(t, err)
	})

	require.NoError(t, err)
	assert.False(t, handler1Called, "handler1 should not have been called")
	assert.True(t, handler2Called, "handler2 should have been called")
}

func TestDispatchSuccess(t *testing.T) {
	ctx := context.Background()
	log := logger.Noop()
	tracer := noop.NewTracerProvider().Tracer("test")
	d := New("test", tracer, log)

	eventType := events.EventType("test.success")
	handlerCalled := false

	handler := func(ctx context.Context, evt events.EventEnvelope, ack events.AckFunc) error {
		handlerCalled = true
		return nil
	}

	d.RegisterHandler(ctx, eventType, handler)

	evt := events.EventEnvelope{
		Type: eventType,
		Metadata: events.EventMetadata{
			Partition: 1,
			Offset:    100,
		},
	}

	err := d.Dispatch(ctx, evt, func(err error) {
		require.NoError(t, err)
	})
	require.NoError(t, err)
	assert.True(t, handlerCalled)
}

func TestDispatchHandlerNotFound(t *testing.T) {
	ctx := context.Background()
	log := logger.Noop()
	tracer := noop.NewTracerProvider().Tracer("test")
	d := New("test", tracer, log)

	evt := events.EventEnvelope{
		Type: events.EventType("unregistered.event"),
		Metadata: events.EventMetadata{
			Partition: 1,
			Offset:    100,
		},
	}

	err := d.Dispatch(ctx, evt, func(err error) {
		require.Error(t, err)
	})
	require.Error(t, err)

	var handlerNotFoundErr *HandlerNotFoundError
	assert.ErrorAs(t, err, &handlerNotFoundErr)
	assert.Equal(t, evt.Type, handlerNotFoundErr.EventType)
	assert.Equal(t, evt.Metadata.Partition, handlerNotFoundErr.Partition)
	assert.Equal(t, evt.Metadata.Offset, handlerNotFoundErr.Offset)
}

func TestDispatchHandlerError(t *testing.T) {
	ctx := context.Background()
	log := logger.Noop()
	tracer := noop.NewTracerProvider().Tracer("test")
	d := New("test", tracer, log)

	eventType := events.EventType("test.error")
	expectedErr := errors.New("handler error")

	handler := func(ctx context.Context, evt events.EventEnvelope, ack events.AckFunc) error {
		return expectedErr
	}

	d.RegisterHandler(ctx, eventType, handler)

	evt := events.EventEnvelope{
		Type: eventType,
		Metadata: events.EventMetadata{
			Partition: 1,
			Offset:    100,
		},
	}

	err := d.Dispatch(ctx, evt, func(err error) {
		require.Error(t, err)
		assert.ErrorContains(t, err, expectedErr.Error())
	})
	require.Error(t, err)
}

func TestDispatchConcurrent(t *testing.T) {
	ctx := context.Background()
	log := logger.Noop()
	tracer := noop.NewTracerProvider().Tracer("test")
	d := New("test", tracer, log)

	eventType := events.EventType("test.concurrent")
	var callCount int
	var mu sync.Mutex

	handler := func(ctx context.Context, evt events.EventEnvelope, ack events.AckFunc) error {
		mu.Lock()
		callCount++
		mu.Unlock()
		return nil
	}

	d.RegisterHandler(ctx, eventType, handler)

	evt := events.EventEnvelope{
		Type: eventType,
		Metadata: events.EventMetadata{
			Partition: 1,
			Offset:    100,
		},
	}

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := d.Dispatch(ctx, evt, func(err error) {
				assert.NoError(t, err)
			})
			require.NoError(t, err)
		}()
	}
	wg.Wait()

	assert.Equal(t, 10, callCount)
}
