// Package registry provides components for managing event handlers
// in an event-driven architecture. It enables registration and lookup
// of handlers for different event types, facilitating the routing
// of events to their appropriate handlers.
package registry

import (
	"context"
	"sync"

	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

// HandlerRegistry provides thread-safe registration and retrieval
// of event handlers. It maps event types to their handler functions,
// allowing the event bus to route events to the appropriate handlers.
type HandlerRegistry struct {
	mu       sync.RWMutex
	handlers map[events.EventType][]events.HandlerFunc

	logger *logger.Logger
	tracer trace.Tracer
}

// NewHandlerRegistry creates a new HandlerRegistry with the given logger and tracer.
func NewHandlerRegistry(logger *logger.Logger, tracer trace.Tracer) *HandlerRegistry {
	return &HandlerRegistry{
		handlers: make(map[events.EventType][]events.HandlerFunc),
		logger:   logger.With("component", "handler_registry"),
		tracer:   tracer,
	}
}

// RegisterHandler adds a handler function for the specified event type.
// Multiple handlers can be registered for the same event type.
func (r *HandlerRegistry) RegisterHandler(ctx context.Context, eventType events.EventType, handler events.HandlerFunc) {
	ctx, span := r.tracer.Start(ctx, "registry.register_handler")
	defer span.End()

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.handlers[eventType]; !exists {
		r.handlers[eventType] = []events.HandlerFunc{}
	}

	r.handlers[eventType] = append(r.handlers[eventType], handler)

	span.AddEvent("handler_registered")
	span.SetStatus(codes.Ok, "handler registered")
	r.logger.Debug(ctx, "Handler registered for event type", "event_type", string(eventType))
}

// GetHandlers retrieves all handler functions for a specific event type.
// Returns the handlers and a boolean indicating if any handlers were found.
func (r *HandlerRegistry) GetHandlers(ctx context.Context, eventType events.EventType) ([]events.HandlerFunc, bool) {
	ctx, span := r.tracer.Start(ctx, "registry.get_handlers")
	defer span.End()

	r.mu.RLock()
	defer r.mu.RUnlock()

	handlers, exists := r.handlers[eventType]
	if !exists || len(handlers) == 0 {
		span.SetStatus(codes.Error, "no handlers found")
		r.logger.Debug(ctx, "No handlers found for event type", "event_type", string(eventType))
		return nil, false
	}

	span.SetStatus(codes.Ok, "handlers found")
	r.logger.Debug(ctx, "Found handlers for event type",
		"event_type", string(eventType),
		"handler_count", len(handlers))
	return handlers, true
}
