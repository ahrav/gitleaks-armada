// Package otel provides otel support.
package otel

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.4.0"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

// Config defines the information needed to init tracing.
type Config struct {
	ServiceName        string
	Host               string
	ExcludedRoutes     map[string]struct{}
	Probability        float64
	ResourceAttributes map[string]string
}

// InitTracing configures open telemetry to be used with the service.
func InitTracing(log *logger.Logger, cfg Config) (trace.TracerProvider, func(ctx context.Context), error) {
	exporter, err := otlptrace.New(
		context.Background(),
		otlptracegrpc.NewClient(
			otlptracegrpc.WithInsecure(), // This should be configurable
			otlptracegrpc.WithEndpoint(cfg.Host),
		),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("creating new exporter: %w", err)
	}

	var traceProvider trace.TracerProvider
	teardown := func(ctx context.Context) {}

	switch cfg.Host {
	case "":
		log.Info(context.Background(), "OTEL", "tracer", "NOOP")
		traceProvider = noop.NewTracerProvider()

	default:
		log.Info(context.Background(), "OTEL", "tracer", cfg.Host)

		attrs := make([]attribute.KeyValue, 0, len(cfg.ResourceAttributes)+1)
		attrs = append(attrs, semconv.ServiceNameKey.String(cfg.ServiceName))
		for k, v := range cfg.ResourceAttributes {
			attrs = append(attrs, attribute.String(k, v))
		}

		tp := sdktrace.NewTracerProvider(
			sdktrace.WithSampler(newEndpointExcluder(cfg.ExcludedRoutes, cfg.Probability)),
			sdktrace.WithBatcher(exporter,
				sdktrace.WithMaxExportBatchSize(sdktrace.DefaultMaxExportBatchSize),
				sdktrace.WithBatchTimeout(sdktrace.DefaultScheduleDelay*time.Millisecond),
				sdktrace.WithMaxExportBatchSize(sdktrace.DefaultMaxExportBatchSize),
			),
			sdktrace.WithResource(
				resource.NewWithAttributes(
					semconv.SchemaURL,
					attrs...,
				),
			),
		)

		teardown = func(ctx context.Context) { tp.Shutdown(ctx) }

		traceProvider = tp
	}

	// We must set this provider as the global provider for things to work,
	// but we pass this provider around the program where needed to collect
	// our traces.
	otel.SetTracerProvider(traceProvider)

	// Extract incoming trace contexts and the headers we set in outgoing requests.
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	return traceProvider, teardown, nil
}

// AddSpan creates a new span with the given name and attributes
func AddSpan(ctx context.Context, tracer trace.Tracer, spanName string, keyValues ...attribute.KeyValue) (context.Context, trace.Span) {
	ctx, span := tracer.Start(ctx, spanName)
	for _, kv := range keyValues {
		span.SetAttributes(kv)
	}
	return ctx, span
}

// Helper function to convert map to attribute.KeyValue slice
func attributesFromMap(m map[string]string) []attribute.KeyValue {
	attrs := make([]attribute.KeyValue, 0, len(m))
	for k, v := range m {
		attrs = append(attrs, attribute.String(k, v))
	}
	return attrs
}
