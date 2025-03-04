package eventdispatcher

import (
	"context"
	"fmt"
	"sync"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

// Dispatcher manages event handlers and dispatches events to their registered handler.
// Following a simple event routing pattern, it ensures each event type has exactly one
// handler responsible for processing events of that type.
//
// Typical usage:
//
//	dispatcher := eventdispatcher.New(controllerID, tracer, logger)
//
//	// Register handlers for different event types
//	dispatcher.RegisterHandler(ctx, handler1)
//	dispatcher.RegisterHandler(ctx, handler2)
//
//	// Dispatch events
//	err := dispatcher.Dispatch(ctx, someEnvelope)
type Dispatcher struct {
	controllerID string

	mu       sync.RWMutex
	handlers map[events.EventType]events.EventHandler

	logger *logger.Logger
	tracer trace.Tracer
}

// New constructs a new EventDispatcher that uses the provided tracer
// for instrumentation. The dispatcher starts with an empty registry; handlers must
// be registered before dispatching any events.
func New(controllerID string, tracer trace.Tracer, logger *logger.Logger) *Dispatcher {
	logger = logger.With("component", "event_dispatcher")
	return &Dispatcher{
		controllerID: controllerID,
		handlers:     make(map[events.EventType]events.EventHandler),
		tracer:       tracer,
		logger:       logger,
	}
}

// HandlerAlreadyRegisteredError is an error type that indicates a handler was already registered for an event type.
type HandlerAlreadyRegisteredError struct {
	EventType events.EventType
	Handler   events.EventHandler
}

func (e *HandlerAlreadyRegisteredError) Error() string {
	return fmt.Sprintf("handler already registered for event type: %s", e.EventType)
}

// RegisterHandler associates a handler with a specific event type.
// If a handler is already registered for the event type, it will be replaced.
//
// This method is safe to call concurrently.
//
// Example usage:
//
//	dispatcher.RegisterHandler(ctx, handler1)
func (d *Dispatcher) RegisterHandler(ctx context.Context, handler events.EventHandler) error {
	logger := d.logger.With("operation", "register_handler")
	_, span := d.tracer.Start(ctx, "event_dispatcher.register_handler",
		trace.WithAttributes(
			attribute.String("controller_id", d.controllerID),
			attribute.String("handler_type", fmt.Sprintf("%T", handler)),
		),
	)
	defer span.End()

	d.mu.Lock()
	defer d.mu.Unlock()

	for _, evtType := range handler.SupportedEvents() {
		if existing, exists := d.handlers[evtType]; exists {
			span.RecordError(&HandlerAlreadyRegisteredError{
				EventType: evtType,
				Handler:   existing,
			})
			span.SetStatus(codes.Error, "handler already registered")
			return &HandlerAlreadyRegisteredError{EventType: evtType, Handler: existing}
		}
		d.handlers[evtType] = handler
	}

	logger.Debug(ctx, "handler registered")
	span.AddEvent("handler_registered")
	span.SetStatus(codes.Ok, "handler registered")
	return nil
}

// HandlerNotFoundError is an error type that indicates a handler was not found for an event type.
type HandlerNotFoundError struct {
	EventType events.EventType
	Partition int32
	Offset    int64
}

func (e *HandlerNotFoundError) Error() string {
	return fmt.Sprintf("no handler registered for event type: %s (partition: %d, offset: %d)",
		e.EventType, e.Partition, e.Offset)
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
	logger := logger.NewLoggerContext(d.logger.With("operation", "dispatch",
		"event_type", evt.Type,
		"partition", evt.Metadata.Partition,
		"offset", evt.Metadata.Offset,
	))
	ctx, span := d.tracer.Start(ctx, "event_dispatcher.handle_event",
		trace.WithAttributes(
			attribute.String("controller_id", d.controllerID),
			attribute.String("event_type", string(evt.Type)),
			attribute.Int("partition", int(evt.Metadata.Partition)),
			attribute.Int64("offset", evt.Metadata.Offset),
		))
	defer span.End()

	d.mu.RLock()
	handler, exists := d.handlers[evt.Type]
	d.mu.RUnlock()
	if !exists {
		err := &HandlerNotFoundError{
			EventType: evt.Type,
			Partition: evt.Metadata.Partition,
			Offset:    evt.Metadata.Offset,
		}
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	logger.Add("handler_type", fmt.Sprintf("%T", handler))

	if err := handler.HandleEvent(ctx, evt, ack); err != nil {
		span.RecordError(err)
		return fmt.Errorf("handler %T failed to process event %s: %w",
			handler, evt.Type, err)
	}

	span.SetStatus(codes.Ok, "event dispatched successfully")
	logger.Debug(ctx, "event dispatched successfully")
	return nil
}
