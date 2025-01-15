package scanning

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

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

	// Repository metrics
	ObserveFindings(ctx context.Context, repoURI string, count int)
	ObserveRepoSize(ctx context.Context, repoURI string, sizeBytes int64)
	ObserveCloneTime(ctx context.Context, repoURI string, duration time.Duration)
	IncCloneError(ctx context.Context, repoURI string)
	ObserveScanTime(ctx context.Context, repoURI string, duration time.Duration)

	// URL scan metrics
	ObserveURLScanTime(ctx context.Context, url string, duration time.Duration)
	ObserveURLScanSize(ctx context.Context, url string, sizeBytes int64)
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
	findingsPerTask      metric.Float64Histogram
	lastFindingFoundTime metric.Float64ObservableGauge

	// Worker metrics
	activeWorkers metric.Int64UpDownCounter
	workerErrors  metric.Int64Counter

	// Repository scan metrics
	repoSize    metric.Int64Histogram
	cloneTime   metric.Float64Histogram
	cloneErrors metric.Int64Counter
	scanTime    metric.Float64Histogram

	// URL scan metrics
	urlScanTime metric.Float64Histogram
	urlScanSize metric.Int64Histogram
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

	// Initialize Git operations metrics
	if s.cloneTime, err = meter.Float64Histogram(
		"git_clone_duration_seconds",
		metric.WithDescription("Time taken to clone repositories"),
	); err != nil {
		return nil, err
	}

	if s.cloneErrors, err = meter.Int64Counter(
		"git_clone_errors_total",
		metric.WithDescription("Total number of repository clone errors"),
	); err != nil {
		return nil, err
	}

	// Initialize finding metrics
	if s.findingsPerTask, err = meter.Float64Histogram(
		"findings_per_task",
		metric.WithDescription("Number of findings discovered per task"),
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

	// Initialize repository metrics
	if s.repoSize, err = meter.Int64Histogram(
		"repository_size_bytes",
		metric.WithDescription("Size of cloned repositories in bytes"),
		metric.WithUnit("bytes"),
	); err != nil {
		return nil, err
	}

	if s.cloneTime, err = meter.Float64Histogram(
		"repository_clone_duration_seconds",
		metric.WithDescription("Time taken to clone repositories"),
		metric.WithUnit("s"),
	); err != nil {
		return nil, err
	}

	if s.cloneErrors, err = meter.Int64Counter(
		"repository_clone_errors_total",
		metric.WithDescription("Total number of repository clone errors"),
	); err != nil {
		return nil, err
	}

	if s.scanTime, err = meter.Float64Histogram(
		"repository_scan_duration_milliseconds",
		metric.WithDescription("Time taken to scan repositories in milliseconds"),
		metric.WithUnit("ms"),
	); err != nil {
		return nil, err
	}

	if s.urlScanTime, err = meter.Float64Histogram(
		"url_scan_duration_milliseconds",
		metric.WithDescription("Time taken to scan URLs in milliseconds"),
		metric.WithUnit("ms"),
	); err != nil {
		return nil, err
	}

	if s.urlScanSize, err = meter.Int64Histogram(
		"url_scan_size_bytes",
		metric.WithDescription("Size of URLs scanned in bytes"),
		metric.WithUnit("bytes"),
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

// Repository metrics implementations
func (m *scannerMetrics) ObserveRepoSize(ctx context.Context, repoURI string, sizeBytes int64) {
	m.repoSize.Record(ctx, sizeBytes, metric.WithAttributes(
		attribute.String("repository_uri", repoURI),
	))
}

func (m *scannerMetrics) ObserveCloneTime(ctx context.Context, repoURI string, duration time.Duration) {
	m.cloneTime.Record(ctx, duration.Seconds(), metric.WithAttributes(
		attribute.String("repository_uri", repoURI),
	))
}

func (m *scannerMetrics) IncCloneError(ctx context.Context, repoURI string) {
	m.cloneErrors.Add(ctx, 1, metric.WithAttributes(
		attribute.String("repository_uri", repoURI),
	))
}

func (m *scannerMetrics) ObserveFindings(ctx context.Context, repoURI string, count int) {
	m.findingsPerTask.Record(ctx, float64(count), metric.WithAttributes(
		attribute.String("repository_uri", repoURI),
	))
}

func (m *scannerMetrics) ObserveScanTime(ctx context.Context, repoURI string, duration time.Duration) {
	m.scanTime.Record(ctx, float64(duration.Milliseconds()), metric.WithAttributes(
		attribute.String("repository_uri", repoURI),
	))
}

func (m *scannerMetrics) ObserveURLScanTime(ctx context.Context, url string, duration time.Duration) {
	m.urlScanTime.Record(ctx, float64(duration.Milliseconds()), metric.WithAttributes(
		attribute.String("url", url),
	))
}

func (m *scannerMetrics) ObserveURLScanSize(ctx context.Context, url string, sizeBytes int64) {
	m.urlScanSize.Record(ctx, sizeBytes, metric.WithAttributes(
		attribute.String("url", url),
	))
}
