package otel

import (
	"context"

	"go.opentelemetry.io/otel/trace"
)

// GetTraceID returns the trace id from the current span context.
func GetTraceID(ctx context.Context) string {
	if span := trace.SpanFromContext(ctx); span.SpanContext().IsValid() {
		return span.SpanContext().TraceID().String()
	}
	return "00000000000000000000000000000000"
}
