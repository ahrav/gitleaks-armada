package otel

import (
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.4.0"
)

// NewMeterProvider creates a new meter provider with the given service name.
func NewMeterProvider(serviceName string) (metric.MeterProvider, error) {
	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(NewResource(serviceName)),
	)

	return mp, nil
}

// NewResource creates a new OpenTelemetry resource with service name.
func NewResource(serviceName string) *resource.Resource {
	return resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceNameKey.String(serviceName),
	)
}
