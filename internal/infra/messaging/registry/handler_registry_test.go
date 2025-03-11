package registry_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/infra/messaging/registry"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

func TestNewHandlerRegistry(t *testing.T) {
	log := logger.Noop()
	tr := noop.NewTracerProvider().Tracer("test")

	reg := registry.NewHandlerRegistry(log, tr)
	assert.NotNil(t, reg, "Expected a non-nil registry")
}

func TestRegisterHandlerSingle(t *testing.T) {
	log := logger.Noop()
	tr := noop.NewTracerProvider().Tracer("test")

	reg := registry.NewHandlerRegistry(log, tr)

	var handled bool
	handler := func(ctx context.Context, env events.EventEnvelope, ack events.AckFunc) error {
		handled = true
		return nil
	}

	eventType := events.EventType("TestEvent")
	reg.RegisterHandler(context.Background(), eventType, handler)

	handlers, found := reg.GetHandlers(context.Background(), eventType)
	assert.True(t, found, "Expected to find handlers for TestEvent")
	assert.Len(t, handlers, 1, "Expected exactly one handler")

	_ = handlers[0](context.Background(), events.EventEnvelope{}, func(err error) {})
	assert.True(t, handled, "Expected the test handler to be invoked")
}

func TestRegisterHandlerMultiple(t *testing.T) {
	log := logger.Noop()
	tr := noop.NewTracerProvider().Tracer("test")

	reg := registry.NewHandlerRegistry(log, tr)

	handlerA := func(ctx context.Context, env events.EventEnvelope, ack events.AckFunc) error { return nil }
	handlerB := func(ctx context.Context, env events.EventEnvelope, ack events.AckFunc) error { return nil }
	handlerC := func(ctx context.Context, env events.EventEnvelope, ack events.AckFunc) error { return nil }

	eventType := events.EventType("MultiEvent")

	// Register multiple handlers for the same event type.
	reg.RegisterHandler(context.Background(), eventType, handlerA)
	reg.RegisterHandler(context.Background(), eventType, handlerB)
	reg.RegisterHandler(context.Background(), eventType, handlerC)

	handlers, found := reg.GetHandlers(context.Background(), eventType)
	assert.True(t, found)
	assert.Len(t, handlers, 3, "Should have three handlers registered for MultiEvent")
}

func TestGetHandlersNotFound(t *testing.T) {
	log := logger.Noop()
	tr := noop.NewTracerProvider().Tracer("test")

	reg := registry.NewHandlerRegistry(log, tr)

	// We haven't registered anything. We expect an empty result.
	handlers, found := reg.GetHandlers(context.Background(), events.EventType("UnregisteredEvent"))
	assert.False(t, found, "Expected found=false for an unregistered event type")
	assert.Nil(t, handlers, "Expected nil slice for unregistered event type")
}
