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

// Dispatcher manages an event-handler registry and handles event dispatching.
// It creates a trace span for each dispatched event, looks up the corresponding
// handler, and invokes it. If no handler is found or the handler encounters an error,
// the dispatcher records the error on the span and returns it to the caller.
//
// Typical usage:
//
//	dispatcher := eventdispatcher.NewEventDispatcher(myTracer)
//	dispatcher.RegisterHandler(events.EventTypeXYZ, myHandlerFunc)
//	...
//	err := dispatcher.Dispatch(ctx, someEnvelope)
type Dispatcher struct {
	mu       sync.RWMutex
	handlers map[events.EventType]events.HandlerFunc
	tracer   trace.Tracer
}

// New constructs a new EventDispatcher that uses the provided tracer
// for instrumentation. The dispatcher starts with an empty registry; handlers must
// be registered before Dispatching any events.
func New(tracer trace.Tracer) *Dispatcher {
	return &Dispatcher{
		handlers: make(map[events.EventType]events.HandlerFunc),
		tracer:   tracer,
	}
}

// RegisterHandler associates the specified eventType with the given eventHandler function.
// If a handler is already registered for this event type, it will be overwritten.
//
// This method is safe to call concurrently.
func (d *Dispatcher) RegisterHandler(eventType events.EventType, handler events.HandlerFunc) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.handlers[eventType] = handler
}

// Dispatch attempts to dispatch the provided event envelope to a matching handler.
// It creates a new trace span (named "event_dispatcher.handle_event"), looks up the
// appropriate handler from the registry, and invokes it.
//
// If no handler is found for the event type or if the handler returns an error, the
// dispatcher records the error in the span and returns it to the caller.
//
// Typical callsite usage:
//
//	err := dispatcher.Dispatch(ctx, envelope)
//	if err != nil {
//	    // handle or log error
//	}
func (d *Dispatcher) Dispatch(ctx context.Context, evt events.EventEnvelope, ack events.AckFunc) error {
	// Start a tracing span that includes the event type as an attribute.
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

	span.AddEvent("handler_found")

	if err := handler(ctx, evt, ack); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	ack(nil)

	span.SetStatus(codes.Ok, "event dispatched successfully")
	return nil
}
