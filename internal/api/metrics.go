package api

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/ahrav/gitleaks-armada/internal/infra/eventbus/kafka"
)

const namespace = "api_gateway"

// APIMetrics defines metrics operations needed by the API gateway
type APIMetrics interface {
	// EventBus metrics
	kafka.EventBusMetrics

	// API metrics
	IncRequestsTotal(ctx context.Context, method, path string, status int)
	ObserveRequestDuration(ctx context.Context, method, path string, duration time.Duration)
	IncScanRequestsTotal(ctx context.Context)
	IncScanRequestErrors(ctx context.Context, reason string)
}

type apiMetrics struct {
	// Kafka metrics
	messagesPublished metric.Int64Counter
	messagesConsumed  metric.Int64Counter
	publishErrors     metric.Int64Counter
	consumeErrors     metric.Int64Counter

	// API metrics
	requestsTotal     metric.Int64Counter
	requestDuration   metric.Float64Histogram
	scanRequestsTotal metric.Int64Counter
	scanRequestErrors metric.Int64Counter
}

func NewAPIMetrics(mp metric.MeterProvider) (*apiMetrics, error) {
	meter := mp.Meter(namespace, metric.WithInstrumentationVersion("v0.1.0"))

	m := new(apiMetrics)
	var err error

	// Kafka metrics
	if m.messagesPublished, err = meter.Int64Counter(
		"messages_published_total",
		metric.WithDescription("Total number of messages published"),
	); err != nil {
		return nil, err
	}

	if m.messagesConsumed, err = meter.Int64Counter(
		"messages_consumed_total",
		metric.WithDescription("Total number of messages consumed"),
	); err != nil {
		return nil, err
	}

	if m.publishErrors, err = meter.Int64Counter(
		"publish_errors_total",
		metric.WithDescription("Total number of publish errors"),
	); err != nil {
		return nil, err
	}

	if m.consumeErrors, err = meter.Int64Counter(
		"consume_errors_total",
		metric.WithDescription("Total number of consume errors"),
	); err != nil {
		return nil, err
	}

	// API metrics
	if m.requestsTotal, err = meter.Int64Counter(
		"requests_total",
		metric.WithDescription("Total number of HTTP requests"),
	); err != nil {
		return nil, err
	}

	if m.requestDuration, err = meter.Float64Histogram(
		"request_duration_seconds",
		metric.WithDescription("HTTP request duration in seconds"),
	); err != nil {
		return nil, err
	}

	if m.scanRequestsTotal, err = meter.Int64Counter(
		"scan_requests_total",
		metric.WithDescription("Total number of scan requests"),
	); err != nil {
		return nil, err
	}

	if m.scanRequestErrors, err = meter.Int64Counter(
		"scan_request_errors_total",
		metric.WithDescription("Total number of scan request errors"),
	); err != nil {
		return nil, err
	}

	return m, nil
}

// EventBusMetrics implementation
func (m *apiMetrics) IncMessagePublished(ctx context.Context, topic string) {
	m.messagesPublished.Add(ctx, 1, metric.WithAttributes(attribute.String("topic", topic)))
}

func (m *apiMetrics) IncMessageConsumed(ctx context.Context, topic string) {
	m.messagesConsumed.Add(ctx, 1, metric.WithAttributes(attribute.String("topic", topic)))
}

func (m *apiMetrics) IncPublishError(ctx context.Context, topic string) {
	m.publishErrors.Add(ctx, 1, metric.WithAttributes(attribute.String("topic", topic)))
}

func (m *apiMetrics) IncConsumeError(ctx context.Context, topic string) {
	m.consumeErrors.Add(ctx, 1, metric.WithAttributes(attribute.String("topic", topic)))
}

// APIMetrics implementation
func (m *apiMetrics) IncRequestsTotal(ctx context.Context, method, path string, status int) {
	m.requestsTotal.Add(ctx, 1, metric.WithAttributes(
		attribute.String("method", method),
		attribute.String("path", path),
		attribute.Int("status", status),
	))
}

func (m *apiMetrics) ObserveRequestDuration(ctx context.Context, method, path string, duration time.Duration) {
	m.requestDuration.Record(ctx, duration.Seconds(), metric.WithAttributes(
		attribute.String("method", method),
		attribute.String("path", path),
	))
}

func (m *apiMetrics) IncScanRequestsTotal(ctx context.Context) {
	m.scanRequestsTotal.Add(ctx, 1)
}

func (m *apiMetrics) IncScanRequestErrors(ctx context.Context, reason string) {
	m.scanRequestErrors.Add(ctx, 1, metric.WithAttributes(
		attribute.String("reason", reason),
	))
}
