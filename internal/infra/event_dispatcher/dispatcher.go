package eventdispatcher

import (
	"context"
	"fmt"
	"sync"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
)

// Dispatcher manages event handlers and dispatches events to their registered handler.
// Following a simple event routing pattern, it ensures each event type has exactly one
// handler responsible for processing events of that type.
//
// Typical usage:
//
//	dispatcher := eventdispatcher.NewEventDispatcher(myTracer)
//
//	// Register handlers for different event types
//	dispatcher.RegisterHandler(events.EventTypeXYZ, handler1)
//	dispatcher.RegisterHandler(events.EventTypeABC, handler2)
//
//	// Dispatch events
//	err := dispatcher.Dispatch(ctx, someEnvelope)
type Dispatcher struct {
	mu       sync.RWMutex
	handlers map[events.EventType]events.HandlerFunc
	tracer   trace.Tracer
}

// New constructs a new EventDispatcher that uses the provided tracer
// for instrumentation. The dispatcher starts with an empty registry; handlers must
// be registered before dispatching any events.
func New(tracer trace.Tracer) *Dispatcher {
	return &Dispatcher{
		handlers: make(map[events.EventType]events.HandlerFunc),
		tracer:   tracer,
	}
}

// RegisterHandler associates a handler with a specific event type.
// If a handler is already registered for the event type, it will be replaced.
//
// This method is safe to call concurrently.
//
// Example usage:
//
//	dispatcher.RegisterHandler(events.EventTypeXYZ, handler1)
func (d *Dispatcher) RegisterHandler(eventType events.EventType, handler events.HandlerFunc) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.handlers[eventType] = handler
}

// Dispatch attempts to dispatch the provided event envelope to its registered handler.
// It creates a new trace span and executes the handler. If the handler returns an error,
// dispatch stops and returns that error.
//
// If no handler is found for the event type, an error is returned.
//
// Typical callsite usage:
//
//	err := dispatcher.Dispatch(ctx, envelope)
//	if err != nil {
//	    // handle or log error
//	}
func (d *Dispatcher) Dispatch(ctx context.Context, evt events.EventEnvelope, ack events.AckFunc) error {
	ctx, span := d.tracer.Start(ctx, "event_dispatcher.handle_event",
		trace.WithAttributes(
			attribute.String("event_type", string(evt.Type)),
		))
	defer span.End()

	d.mu.RLock()
	handler, exists := d.handlers[evt.Type]
	d.mu.RUnlock()

	if !exists {
		err := fmt.Errorf("no handler registered for event type: %s", evt.Type)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	if err := handler(ctx, evt, ack); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	span.SetStatus(codes.Ok, "event dispatched successfully")
	return nil
}
