package postgres

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// executeAndTrace is a helper function that wraps database operations with OpenTelemetry tracing.
// It creates a new span with the given name and attributes, executes the provided operation,
// and handles error recording and span cleanup.
//
// Returns an error if the operation fails, nil otherwise.
// Any errors are recorded on the span before being returned.
func executeAndTrace(
	ctx context.Context,
	tracer trace.Tracer,
	spanName string,
	attributes []attribute.KeyValue,
	operation func(ctx context.Context) error,
) error {
	ctx, span := tracer.Start(ctx, spanName, trace.WithAttributes(attributes...))
	defer span.End()

	err := operation(ctx)
	if err != nil {
		span.RecordError(err)
		return err
	}
	return nil
}
