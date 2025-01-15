package otel

import (
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
)

// GetMeterProvider returns the global meter provider that was set up by InitTelemetry.
func GetMeterProvider() metric.MeterProvider { return otel.GetMeterProvider() }
