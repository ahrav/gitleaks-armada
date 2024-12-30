package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/ahrav/gitleaks-armada/pkg/messaging/kafka"
)

// ControllerMetrics defines metrics operations needed by the controller.
type ControllerMetrics interface {
	// Messaging metrics
	kafka.BrokerMetrics

	// Enumeration metrics
	TrackEnumeration(f func() error) error

	// Target metrics
	IncTargetsProcessed()
	ObserveTargetProcessingTime(duration time.Duration)

	// Leader election metrics
	SetLeaderStatus(isLeader bool)

	// Config metrics
	IncConfigReloads()
	IncConfigReloadErrors()

	// Rules storage metrics (renamed to be more clear)
	IncRulesSaved()     // Tracks individual rules saved to DB
	IncRuleSaveErrors() // Tracks errors saving rules to DB
}

// Controller implements ControllerMetrics
type Controller struct {
	// Broker metrics.
	MessagesPublished *prometheus.CounterVec // labels: topic
	MessagesConsumed  *prometheus.CounterVec // labels: topic
	PublishErrors     *prometheus.CounterVec // labels: topic
	ConsumeErrors     *prometheus.CounterVec // labels: topic

	// Task metrics
	TasksEnqueued        prometheus.Counter
	TasksRetried         prometheus.Counter
	TasksFailedToEnqueue prometheus.Counter

	// Enumeration metrics
	EnumerationTime   prometheus.Histogram
	ActiveEnumeration prometheus.Gauge

	// Target metrics
	TargetsProcessed        prometheus.Counter
	TargetProcessingTime    prometheus.Histogram
	LastTargetProcessedTime prometheus.Gauge

	// Leader election metrics
	LeaderStatus prometheus.Gauge

	// Config metrics
	ConfigReloads      prometheus.Counter
	ConfigReloadErrors prometheus.Counter

	// Rules storage metrics
	RulesSaved     prometheus.Counter // Total number of individual rules saved to DB
	RuleSaveErrors prometheus.Counter // Total number of errors saving rules to DB
}

const namespace = "controller"

// New creates a new Controller instance.
func New() *Controller {
	return &Controller{
		// Messaging metrics
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

		// Task metrics
		TasksEnqueued: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "tasks_enqueued_total",
			Help:      "Total number of tasks published to Kafka",
		}),
		TasksRetried: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "tasks_retried_total",
			Help:      "Total number of tasks that were retried",
		}),
		TasksFailedToEnqueue: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "tasks_failed_to_enqueue_total",
			Help:      "Total number of tasks that failed to be enqueued",
		}),

		// Enumeration metrics
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

		// Target metrics
		TargetsProcessed: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "targets_processed_total",
			Help:      "Total number of targets processed",
		}),
		TargetProcessingTime: promauto.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "target_processing_duration_seconds",
			Help:      "Time taken to process each target",
			Buckets:   prometheus.ExponentialBuckets(0.1, 2, 10),
		}),
		LastTargetProcessedTime: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "last_target_processed_timestamp",
			Help:      "Timestamp of the last target processed",
		}),

		// Leader election metrics
		LeaderStatus: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "leader_status",
			Help:      "Indicates if this instance is the leader (1) or follower (0)",
		}),

		// Config metrics
		ConfigReloads: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "config_reloads_total",
			Help:      "Total number of configuration reloads",
		}),
		ConfigReloadErrors: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "config_reload_errors_total",
			Help:      "Total number of configuration reload errors",
		}),

		// Rules storage metrics
		RulesSaved: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "rules_saved_total",
			Help:      "Total number of individual rules saved to DB",
		}),
		RuleSaveErrors: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "rule_save_errors_total",
			Help:      "Total number of errors saving rules to DB",
		}),
	}
}

// Interface implementation methods.
func (c *Controller) IncMessagePublished(topic string) {
	c.MessagesPublished.WithLabelValues(topic).Inc()
}
func (c *Controller) IncMessageConsumed(topic string) {
	c.MessagesConsumed.WithLabelValues(topic).Inc()
}
func (c *Controller) IncPublishError(topic string) { c.PublishErrors.WithLabelValues(topic).Inc() }
func (c *Controller) IncConsumeError(topic string) { c.ConsumeErrors.WithLabelValues(topic).Inc() }
func (c *Controller) IncTasksEnqueued()            { c.TasksEnqueued.Inc() }
func (c *Controller) IncTasksRetried()             { c.TasksRetried.Inc() }
func (c *Controller) IncTasksFailedToEnqueue()     { c.TasksFailedToEnqueue.Inc() }
func (c *Controller) IncTargetsProcessed()         { c.TargetsProcessed.Inc() }
func (c *Controller) IncConfigReloads()            { c.ConfigReloads.Inc() }
func (c *Controller) IncConfigReloadErrors()       { c.ConfigReloadErrors.Inc() }
func (c *Controller) IncRulesSaved()               { c.RulesSaved.Inc() }
func (c *Controller) IncRuleSaveErrors()           { c.RuleSaveErrors.Inc() }

func (c *Controller) SetLeaderStatus(isLeader bool) {
	if isLeader {
		c.LeaderStatus.Set(1)
	} else {
		c.LeaderStatus.Set(0)
	}
}

func (c *Controller) ObserveTargetProcessingTime(duration time.Duration) {
	c.TargetProcessingTime.Observe(duration.Seconds())
	c.LastTargetProcessedTime.SetToCurrentTime()
}

func (c *Controller) TrackEnumeration(f func() error) error {
	c.ActiveEnumeration.Inc()
	defer c.ActiveEnumeration.Dec()

	start := time.Now()
	err := f()
	c.EnumerationTime.Observe(time.Since(start).Seconds())
	return err
}
