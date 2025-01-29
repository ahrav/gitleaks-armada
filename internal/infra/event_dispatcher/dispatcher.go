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

// Dispatcher manages event handlers and dispatches events to all registered handlers
// for a given event type. Following the publisher/subscriber pattern, it allows multiple
// handlers to process the same event type independently, enabling different components
// to react to the same event for different purposes.
//
// Typical usage:
//
//	dispatcher := eventdispatcher.NewEventDispatcher(myTracer)
//
//	// Register handlers for different event types
//	dispatcher.RegisterHandlers(events.EventTypeXYZ, handler1, handler2)
//	dispatcher.RegisterHandlers(events.EventTypeABC, handler3)
//
//	// Dispatch events
//	err := dispatcher.Dispatch(ctx, someEnvelope)
type Dispatcher struct {
	mu       sync.RWMutex
	handlers map[events.EventType][]events.HandlerFunc
	tracer   trace.Tracer
}

// New constructs a new EventDispatcher that uses the provided tracer
// for instrumentation. The dispatcher starts with an empty registry; handlers must
// be registered before dispatching any events.
func New(tracer trace.Tracer) *Dispatcher {
	return &Dispatcher{
		handlers: make(map[events.EventType][]events.HandlerFunc),
		tracer:   tracer,
	}
}

// RegisterHandlers associates one or more handlers with a specific event type.
// Following the publisher/subscriber pattern, multiple handlers can process the
// same event type independently, enabling different components to react to the
// same event for different purposes.
//
// This method is safe to call concurrently.
//
// Example usage:
//
//	// Single handler
//	dispatcher.RegisterHandlers(events.EventTypeXYZ, handler1)
//
//	// Multiple handlers
//	dispatcher.RegisterHandlers(events.EventTypeXYZ,
//	    handler1,
//	    handler2,
//	    handler3,
//	)
func (d *Dispatcher) RegisterHandlers(eventType events.EventType, handlers ...events.HandlerFunc) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.handlers[eventType] = append(d.handlers[eventType], handlers...)
}

// Dispatch attempts to dispatch the provided event envelope to all registered handlers
// for its event type. It creates a new trace span and executes each handler sequentially.
// If any handler returns an error, dispatch stops and returns that error.
//
// This aligns with typical event processing patterns where each handler (consumer)
// needs to successfully process the event before moving to the next one.
//
// If no handlers are found for the event type, an error is returned.
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
	handlers, exists := d.handlers[evt.Type]
	d.mu.RUnlock()

	if !exists || len(handlers) == 0 {
		err := fmt.Errorf("no handlers registered for event type: %s", evt.Type)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	span.AddEvent("handlers_found", trace.WithAttributes(
		attribute.Int("handler_count", len(handlers)),
	))

	// Execute all handlers for this event type
	for _, handler := range handlers {
		if err := handler(ctx, evt, ack); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return err
		}
	}
	ack(nil)

	span.SetStatus(codes.Ok, "event dispatched successfully")
	return nil
}
