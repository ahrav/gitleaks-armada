package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/ahrav/gitleaks-armada/internal/messaging/kafka"
)

// ScannerMetrics defines metrics operations needed by the scanner.
type ScannerMetrics interface {
	// Messaging metrics
	kafka.BrokerMetrics

	// Task metrics
	IncTasksProcessed()
	IncTaskErrors()
	TrackTask(f func() error) error

	// Git operations metrics
	ObserveCloneTime(duration time.Duration)
	IncCloneErrors()

	// Finding metrics
	ObserveFindings(count int)

	// Worker metrics
	SetActiveWorkers(count int)
	IncWorkerErrors()
}

// Scanner implements ScannerMetrics
type Scanner struct {
	// Task metrics
	MessagesPublished *prometheus.CounterVec // labels: topic
	MessagesConsumed  *prometheus.CounterVec // labels: topic
	PublishErrors     *prometheus.CounterVec // labels: topic
	ConsumeErrors     *prometheus.CounterVec // labels: topic

	TasksProcessed  prometheus.Counter
	TaskErrors      prometheus.Counter
	ActiveTasks     prometheus.Gauge
	TaskProcessTime prometheus.Histogram

	// Git operations metrics
	CloneTime   prometheus.Histogram
	CloneErrors prometheus.Counter

	// Finding metrics
	FindingsPerTask      prometheus.Histogram
	LastFindingFoundTime prometheus.Gauge

	// Worker metrics
	ActiveWorkers prometheus.Gauge
	WorkerErrors  prometheus.Counter
}

const namespace = "scanner"

// New creates a new ScannerMetricsImpl instance
func New() *Scanner {
	return &Scanner{
		// Task metrics
		MessagesPublished: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "messages_published_total",
			Help:      "Total number of messages published",
		}, []string{"topic"}),
		MessagesConsumed: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "messages_consumed_total",
			Help:      "Total number of messages consumed",
		}, []string{"topic"}),
		PublishErrors: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "publish_errors_total",
			Help:      "Total number of publish errors",
		}, []string{"topic"}),
		ConsumeErrors: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "consume_errors_total",
			Help:      "Total number of consume errors",
		}, []string{"topic"}),

		TasksProcessed: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "tasks_processed_total",
			Help:      "Total number of tasks successfully processed",
		}),
		TaskErrors: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "task_errors_total",
			Help:      "Total number of task processing errors",
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

		// Git operations metrics
		CloneTime: promauto.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "git_clone_duration_seconds",
			Help:      "Time taken to clone repositories",
			Buckets:   prometheus.ExponentialBuckets(1, 2, 10),
		}),
		CloneErrors: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "git_clone_errors_total",
			Help:      "Total number of repository clone errors",
		}),

		// Finding metrics
		FindingsPerTask: promauto.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "findings_per_task",
			Help:      "Number of findings discovered per task",
			Buckets:   prometheus.LinearBuckets(0, 5, 20),
		}),
		LastFindingFoundTime: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "last_finding_timestamp",
			Help:      "Timestamp of the last finding discovered",
		}),

		// Worker metrics
		ActiveWorkers: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "active_workers",
			Help:      "Number of active workers",
		}),
		WorkerErrors: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "worker_errors_total",
			Help:      "Total number of worker errors",
		}),
	}
}

// Task metrics implementations
func (m *Scanner) IncTasksProcessed() { m.TasksProcessed.Inc() }

func (m *Scanner) IncTaskErrors() { m.TaskErrors.Inc() }

func (m *Scanner) TrackTask(f func() error) error {
	start := time.Now()
	m.ActiveTasks.Inc()
	defer m.ActiveTasks.Dec()

	err := f()
	m.TaskProcessTime.Observe(time.Since(start).Seconds())
	return err
}

// Git operations metrics implementations
func (m *Scanner) ObserveCloneTime(duration time.Duration) {
	m.CloneTime.Observe(duration.Seconds())
}

func (m *Scanner) IncCloneErrors() { m.CloneErrors.Inc() }

// Finding metrics implementations
func (m *Scanner) ObserveFindings(count int) {
	m.FindingsPerTask.Observe(float64(count))
	m.LastFindingFoundTime.SetToCurrentTime()
}

// Worker metrics implementations
func (m *Scanner) SetActiveWorkers(count int) { m.ActiveWorkers.Set(float64(count)) }

func (m *Scanner) IncWorkerErrors() { m.WorkerErrors.Inc() }

// Kafka BrokerMetrics implementations
func (m *Scanner) IncMessagePublished(topic string) {
	m.MessagesPublished.WithLabelValues(topic).Inc()
}

func (m *Scanner) IncMessageConsumed(topic string) {
	m.MessagesConsumed.WithLabelValues(topic).Inc()
}

func (m *Scanner) IncPublishError(topic string) {
	m.PublishErrors.WithLabelValues(topic).Inc()
}

func (m *Scanner) IncConsumeError(topic string) {
	m.ConsumeErrors.WithLabelValues(topic).Inc()
}
