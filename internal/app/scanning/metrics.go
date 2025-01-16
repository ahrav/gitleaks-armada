package scanning

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
	"github.com/ahrav/gitleaks-armada/internal/infra/eventbus/kafka"
)

// ScannerMetrics defines metrics operations needed by the scanner.
type ScannerMetrics interface {
	// Messaging metrics
	kafka.BrokerMetrics

	// Task metrics
	IncTasksProcessed(ctx context.Context)
	IncTaskErrors(ctx context.Context)
	TrackTask(ctx context.Context, f func() error) error

	// Worker metrics
	SetActiveWorkers(ctx context.Context, count int)
	IncWorkerErrors(ctx context.Context)

	// Common scan metrics across all sources.
	ObserveScanDuration(ctx context.Context, sourceType shared.SourceType, duration time.Duration)
	ObserveScanSize(ctx context.Context, sourceType shared.SourceType, sizeBytes int64)
	ObserveScanFindings(ctx context.Context, sourceType shared.SourceType, count int)
	IncScanError(ctx context.Context, sourceType shared.SourceType)
}

// scannerMetrics implements ScannerMetrics
type scannerMetrics struct {
	// Messaging metrics
	messagesPublished metric.Int64Counter
	messagesConsumed  metric.Int64Counter
	publishErrors     metric.Int64Counter
	consumeErrors     metric.Int64Counter

	// Task metrics
	tasksProcessed  metric.Int64Counter
	taskErrors      metric.Int64Counter
	activeTasks     metric.Int64UpDownCounter
	taskProcessTime metric.Float64Histogram

	// Finding metrics
	lastFindingFoundTime metric.Float64ObservableGauge

	// Worker metrics
	activeWorkers metric.Int64UpDownCounter
	workerErrors  metric.Int64Counter

	// Common scan metrics across all sources.
	scanDuration metric.Float64Histogram
	scanSize     metric.Int64Histogram
	scanFindings metric.Int64Histogram
	scanError    metric.Int64Counter
}

const namespace = "scanner"

// NewScannerMetrics creates a new Scanner metrics instance.
func NewScannerMetrics(mp metric.MeterProvider) (*scannerMetrics, error) {
	meter := mp.Meter(namespace, metric.WithInstrumentationVersion("v0.1.0"))

	s := new(scannerMetrics)
	var err error

	// Initialize messaging metrics
	if s.messagesPublished, err = meter.Int64Counter(
		"messages_published_total",
		metric.WithDescription("Total number of messages published"),
	); err != nil {
		return nil, err
	}

	if s.messagesConsumed, err = meter.Int64Counter(
		"messages_consumed_total",
		metric.WithDescription("Total number of messages consumed"),
	); err != nil {
		return nil, err
	}

	if s.publishErrors, err = meter.Int64Counter(
		"publish_errors_total",
		metric.WithDescription("Total number of publish errors"),
	); err != nil {
		return nil, err
	}

	if s.consumeErrors, err = meter.Int64Counter(
		"consume_errors_total",
		metric.WithDescription("Total number of consume errors"),
	); err != nil {
		return nil, err
	}

	// Initialize task metrics
	if s.tasksProcessed, err = meter.Int64Counter(
		"tasks_processed_total",
		metric.WithDescription("Total number of tasks successfully processed"),
	); err != nil {
		return nil, err
	}

	if s.taskErrors, err = meter.Int64Counter(
		"task_errors_total",
		metric.WithDescription("Total number of task processing errors"),
	); err != nil {
		return nil, err
	}

	if s.activeTasks, err = meter.Int64UpDownCounter(
		"active_tasks",
		metric.WithDescription("Number of tasks currently being processed"),
	); err != nil {
		return nil, err
	}

	if s.taskProcessTime, err = meter.Float64Histogram(
		"task_process_duration_seconds",
		metric.WithDescription("Time taken to process each task"),
	); err != nil {
		return nil, err
	}

	// Initialize worker metrics
	if s.activeWorkers, err = meter.Int64UpDownCounter(
		"active_workers",
		metric.WithDescription("Number of active workers"),
	); err != nil {
		return nil, err
	}

	if s.workerErrors, err = meter.Int64Counter(
		"worker_errors_total",
		metric.WithDescription("Total number of worker errors"),
	); err != nil {
		return nil, err
	}

	// Initialize common scan metrics
	if s.scanDuration, err = meter.Float64Histogram(
		"scan_duration_milliseconds",
		metric.WithDescription("Time taken to scan sources in milliseconds"),
		metric.WithUnit("ms"),
	); err != nil {
		return nil, err
	}

	if s.scanSize, err = meter.Int64Histogram(
		"scan_size_bytes",
		metric.WithDescription("Size of sources scanned in bytes"),
		metric.WithUnit("bytes"),
	); err != nil {
		return nil, err
	}

	if s.scanFindings, err = meter.Int64Histogram(
		"scan_findings",
		metric.WithDescription("Number of findings discovered per source"),
		metric.WithUnit("findings"),
	); err != nil {
		return nil, err
	}

	if s.scanError, err = meter.Int64Counter(
		"scan_errors_total",
		metric.WithDescription("Total number of scan errors"),
	); err != nil {
		return nil, err
	}

	return s, nil
}

// Task metrics implementations
func (m *scannerMetrics) IncTasksProcessed(ctx context.Context) {
	m.tasksProcessed.Add(ctx, 1)
}

func (m *scannerMetrics) IncTaskErrors(ctx context.Context) {
	m.taskErrors.Add(ctx, 1)
}

func (m *scannerMetrics) TrackTask(ctx context.Context, f func() error) error {
	m.activeTasks.Add(ctx, 1)
	defer m.activeTasks.Add(ctx, -1)

	start := time.Now()
	err := f()
	m.taskProcessTime.Record(ctx, time.Since(start).Seconds())
	return err
}

// Worker metrics implementations
func (m *scannerMetrics) SetActiveWorkers(ctx context.Context, count int) {
	m.activeWorkers.Add(ctx, int64(count))
}

func (m *scannerMetrics) IncWorkerErrors(ctx context.Context) {
	m.workerErrors.Add(ctx, 1)
}

// Kafka BrokerMetrics implementations
func (m *scannerMetrics) IncMessagePublished(ctx context.Context, topic string) {
	m.messagesPublished.Add(ctx, 1, metric.WithAttributes(attribute.String("topic", topic)))
}

func (m *scannerMetrics) IncMessageConsumed(ctx context.Context, topic string) {
	m.messagesConsumed.Add(ctx, 1, metric.WithAttributes(attribute.String("topic", topic)))
}

func (m *scannerMetrics) IncPublishError(ctx context.Context, topic string) {
	m.publishErrors.Add(ctx, 1, metric.WithAttributes(attribute.String("topic", topic)))
}

func (m *scannerMetrics) IncConsumeError(ctx context.Context, topic string) {
	m.consumeErrors.Add(ctx, 1, metric.WithAttributes(attribute.String("topic", topic)))
}

// Common scan metrics implementations
func (m *scannerMetrics) ObserveScanDuration(ctx context.Context, sourceType shared.SourceType, duration time.Duration) {
	m.scanDuration.Record(ctx, float64(duration.Milliseconds()), metric.WithAttributes(
		attribute.String("source_type", string(sourceType)),
	))
}

func (m *scannerMetrics) ObserveScanSize(ctx context.Context, sourceType shared.SourceType, sizeBytes int64) {
	m.scanSize.Record(ctx, sizeBytes, metric.WithAttributes(
		attribute.String("source_type", string(sourceType)),
	))
}

func (m *scannerMetrics) ObserveScanFindings(ctx context.Context, sourceType shared.SourceType, count int) {
	m.scanFindings.Record(ctx, int64(count), metric.WithAttributes(
		attribute.String("source_type", string(sourceType)),
	))
}

func (m *scannerMetrics) IncScanError(ctx context.Context, sourceType shared.SourceType) {
	m.scanError.Add(ctx, 1, metric.WithAttributes(
		attribute.String("source_type", string(sourceType)),
	))
}
