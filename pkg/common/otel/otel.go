// Package otel provides otel support.
package otel

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.4.0"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

// Config defines the information needed to init tracing.
type Config struct {
	ServiceName        string
	ExporterEndpoint   string
	Host               string
	ExcludedRoutes     map[string]struct{}
	Probability        float64
	ResourceAttributes map[string]string
	InsecureExporter   bool
}

// InitTracing configures open telemetry to be used with the service.
func InitTelemetry(log *logger.Logger, cfg Config) (trace.TracerProvider, func(ctx context.Context), error) {
	// Create shared resource attributes
	attrs := make([]attribute.KeyValue, 0, len(cfg.ResourceAttributes)+1)
	attrs = append(attrs, semconv.ServiceNameKey.String(cfg.ServiceName))
	for k, v := range cfg.ResourceAttributes {
		attrs = append(attrs, attribute.String(k, v))
	}

	res := resource.NewWithAttributes(
		semconv.SchemaURL,
		attrs...,
	)

	// Initialize trace exporter.
	traceOpts := []otlptracegrpc.Option{
		otlptracegrpc.WithEndpoint(cfg.ExporterEndpoint),
		otlptracegrpc.WithInsecure(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	traceExporter, err := otlptracegrpc.New(
		ctx,
		traceOpts...,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("creating trace exporter: %w", err)
	}

	// Initialize metrics exporter.
	metricOpts := []otlpmetricgrpc.Option{
		otlpmetricgrpc.WithEndpoint(cfg.ExporterEndpoint),
		otlpmetricgrpc.WithInsecure(),
	}

	metricExporter, err := otlpmetricgrpc.New(
		ctx,
		metricOpts...,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("creating metric exporter: %w", err)
	}

	// Configure trace provider.
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(newEndpointExcluder(cfg.ExcludedRoutes, cfg.Probability)),
		sdktrace.WithBatcher(traceExporter,
			sdktrace.WithBatchTimeout(5*time.Second),
			sdktrace.WithMaxExportBatchSize(512),
			sdktrace.WithMaxQueueSize(2048),
		),
		sdktrace.WithResource(res),
	)

	// Configure metric provider.
	mp := metric.NewMeterProvider(
		metric.WithReader(metric.NewPeriodicReader(metricExporter)),
		metric.WithResource(res),
	)

	// Set global providers.
	otel.SetTracerProvider(tp)
	otel.SetMeterProvider(mp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	cleanup := func(ctx context.Context) {
		if err := tp.Shutdown(ctx); err != nil {
			log.Error(ctx, "shutting down tracer provider", "error", err)
		}
		if err := mp.Shutdown(ctx); err != nil {
			log.Error(ctx, "shutting down meter provider", "error", err)
		}
	}

	return tp, cleanup, nil
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
