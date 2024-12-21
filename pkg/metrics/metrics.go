package metrics

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// ControllerMetrics defines metrics operations needed by the controller.
type ControllerMetrics interface {
	// Task metrics.
	IncTasksEnqueued()

	// Enumeration metrics.
	TrackEnumeration(f func() error) error
}

// ScannerMetrics defines metrics operations needed by the scanner.
type ScannerMetrics interface {
	// Task metrics.
	IncTasksDequeued()
	TrackTask(f func() error) error
}

// Metrics implements both ControllerMetrics and ScannerMetrics.
type Metrics struct {
	// Controller metrics.
	TasksEnqueued     prometheus.Counter
	EnumerationTime   prometheus.Histogram
	ActiveEnumeration prometheus.Gauge

	// Scanner metrics.
	TasksDequeued   prometheus.Counter
	ActiveTasks     prometheus.Gauge
	TaskProcessTime prometheus.Histogram
}

// Ensure Metrics implements both interfaces.
var _ ControllerMetrics = (*Metrics)(nil)
var _ ScannerMetrics = (*Metrics)(nil)

// Interface implementation methods.
func (m *Metrics) IncTasksEnqueued() { m.TasksEnqueued.Inc() }
func (m *Metrics) IncTasksDequeued() { m.TasksDequeued.Inc() }

// TrackEnumeration tracks the duration of a function and updates the metrics.
func (m *Metrics) TrackEnumeration(f func() error) error {
	m.ActiveEnumeration.Inc()
	defer m.ActiveEnumeration.Dec()

	start := time.Now()
	err := f()
	m.EnumerationTime.Observe(time.Since(start).Seconds())
	return err
}

// TrackTask tracks the duration of a function and updates the metrics.
func (m *Metrics) TrackTask(f func() error) error {
	m.ActiveTasks.Inc()
	defer m.ActiveTasks.Dec()

	start := time.Now()
	err := f()
	m.TaskProcessTime.Observe(time.Since(start).Seconds())
	return err
}

// New creates a new Metrics instance with registered metrics.
func New(namespace string) *Metrics {
	return &Metrics{
		// Controller metrics.
		TasksEnqueued: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "tasks_enqueued_total",
			Help:      "Total number of tasks published to Kafka",
		}),
		EnumerationTime: promauto.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "enumeration_duration_seconds",
			Help:      "Time taken to enumerate repositories",
			Buckets:   prometheus.ExponentialBuckets(1, 2, 16),
		}),
		ActiveEnumeration: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "active_enumeration",
			Help:      "Indicates if repository enumeration is in progress",
		}),

		// Scanner metrics.
		TasksDequeued: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "tasks_dequeued_total",
			Help:      "Total number of tasks consumed from Kafka",
		}),
		ActiveTasks: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "active_tasks",
			Help:      "Number of tasks currently being processed",
		}),
		TaskProcessTime: promauto.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "task_process_duration_seconds",
			Help:      "Time taken to process each task",
			Buckets:   prometheus.ExponentialBuckets(5, 2, 16),
		}),
	}
}

// StartServer starts the metrics HTTP server.
func StartServer(addr string) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	return http.ListenAndServe(addr, mux)
}
