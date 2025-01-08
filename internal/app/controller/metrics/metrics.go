package metrics

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/ahrav/gitleaks-armada/internal/infra/eventbus/kafka"
)

// ControllerMetrics defines metrics operations needed by the controller.
type ControllerMetrics interface {
	// Messaging metrics
	kafka.BrokerMetrics

	// Enumeration metrics
	TrackEnumeration(ctx context.Context, f func() error) error

	// Target metrics
	IncTargetsProcessed(ctx context.Context)
	ObserveTargetProcessingTime(ctx context.Context, duration time.Duration)

	// Leader election metrics
	SetLeaderStatus(ctx context.Context, isLeader bool)

	// Config metrics
	IncConfigReloads(ctx context.Context)
	IncConfigReloadErrors(ctx context.Context)

	// Rules storage metrics (renamed to be more clear)
	IncRulesSaved(ctx context.Context)     // Tracks individual rules saved to DB
	IncRuleSaveErrors(ctx context.Context) // Tracks errors saving rules to DB
}

// Controller implements ControllerMetrics
type Controller struct {
	// Broker metrics.
	messagesPublished metric.Int64Counter
	messagesConsumed  metric.Int64Counter
	publishErrors     metric.Int64Counter
	consumeErrors     metric.Int64Counter

	// Task metrics
	tasksEnqueued        metric.Int64Counter
	tasksRetried         metric.Int64Counter
	tasksFailedToEnqueue metric.Int64Counter

	// Enumeration metrics
	enumerationTime   metric.Float64Histogram
	activeEnumeration metric.Int64UpDownCounter

	// Target metrics
	targetsProcessed     metric.Int64Counter
	targetProcessingTime metric.Float64Histogram

	// Leader election metrics
	leaderStatus metric.Int64UpDownCounter

	// Config metrics
	configReloads      metric.Int64Counter
	configReloadErrors metric.Int64Counter

	// Rules storage metrics
	rulesSaved     metric.Int64Counter // Total number of individual rules saved to DB
	ruleSaveErrors metric.Int64Counter // Total number of errors saving rules to DB
}

const namespace = "controller"

// New creates a new Controller metrics instance.
func New(mp metric.MeterProvider) (*Controller, error) {
	meter := mp.Meter(namespace, metric.WithInstrumentationVersion("v0.1.0"))

	c := new(Controller)
	var err error

	if c.messagesPublished, err = meter.Int64Counter(
		"messages_published_total",
		metric.WithDescription("Total number of messages published"),
	); err != nil {
		return nil, err
	}

	if c.messagesConsumed, err = meter.Int64Counter(
		"messages_consumed_total",
		metric.WithDescription("Total number of messages consumed"),
	); err != nil {
		return nil, err
	}

	if c.publishErrors, err = meter.Int64Counter(
		"publish_errors_total",
		metric.WithDescription("Total number of publish errors"),
	); err != nil {
		return nil, err
	}

	if c.consumeErrors, err = meter.Int64Counter(
		"consume_errors_total",
		metric.WithDescription("Total number of consume errors"),
	); err != nil {
		return nil, err
	}

	if c.tasksEnqueued, err = meter.Int64Counter(
		"tasks_enqueued_total",
		metric.WithDescription("Total number of tasks published to Kafka"),
	); err != nil {
		return nil, err
	}

	if c.tasksRetried, err = meter.Int64Counter(
		"tasks_retried_total",
		metric.WithDescription("Total number of tasks that were retried"),
	); err != nil {
		return nil, err
	}

	if c.tasksFailedToEnqueue, err = meter.Int64Counter(
		"tasks_failed_to_enqueue_total",
		metric.WithDescription("Total number of tasks that failed to be enqueued"),
	); err != nil {
		return nil, err
	}

	if c.enumerationTime, err = meter.Float64Histogram(
		"enumeration_duration_seconds",
		metric.WithDescription("Time taken to enumerate repositories"),
	); err != nil {
		return nil, err
	}

	if c.activeEnumeration, err = meter.Int64UpDownCounter(
		"active_enumeration",
		metric.WithDescription("Indicates if repository enumeration is in progress"),
	); err != nil {
		return nil, err
	}

	if c.targetsProcessed, err = meter.Int64Counter(
		"targets_processed_total",
		metric.WithDescription("Total number of targets processed"),
	); err != nil {
		return nil, err
	}

	if c.targetProcessingTime, err = meter.Float64Histogram(
		"target_processing_duration_seconds",
		metric.WithDescription("Time taken to process each target"),
	); err != nil {
		return nil, err
	}

	if c.leaderStatus, err = meter.Int64UpDownCounter(
		"leader_status",
		metric.WithDescription("Indicates if this instance is the leader (1) or follower (0)"),
	); err != nil {
		return nil, err
	}

	if c.configReloads, err = meter.Int64Counter(
		"config_reloads_total",
		metric.WithDescription("Total number of configuration reloads"),
	); err != nil {
		return nil, err
	}

	if c.configReloadErrors, err = meter.Int64Counter(
		"config_reload_errors_total",
		metric.WithDescription("Total number of configuration reload errors"),
	); err != nil {
		return nil, err
	}

	if c.rulesSaved, err = meter.Int64Counter(
		"rules_saved_total",
		metric.WithDescription("Total number of individual rules saved to DB"),
	); err != nil {
		return nil, err
	}

	if c.ruleSaveErrors, err = meter.Int64Counter(
		"rule_save_errors_total",
		metric.WithDescription("Total number of errors saving rules to DB"),
	); err != nil {
		return nil, err
	}

	return c, nil
}

// Interface implementation methods.
func (c *Controller) IncMessagePublished(ctx context.Context, topic string) {
	c.messagesPublished.Add(ctx, 1, metric.WithAttributes(attribute.String("topic", topic)))
}
func (c *Controller) IncMessageConsumed(ctx context.Context, topic string) {
	c.messagesConsumed.Add(ctx, 1, metric.WithAttributes(attribute.String("topic", topic)))
}
func (c *Controller) IncPublishError(ctx context.Context, topic string) {
	c.publishErrors.Add(ctx, 1, metric.WithAttributes(attribute.String("topic", topic)))
}
func (c *Controller) IncConsumeError(ctx context.Context, topic string) {
	c.consumeErrors.Add(ctx, 1, metric.WithAttributes(attribute.String("topic", topic)))
}
func (c *Controller) IncTasksEnqueued(ctx context.Context) {
	c.tasksEnqueued.Add(ctx, 1)
}
func (c *Controller) IncTasksRetried(ctx context.Context) {
	c.tasksRetried.Add(ctx, 1)
}
func (c *Controller) IncTasksFailedToEnqueue(ctx context.Context) {
	c.tasksFailedToEnqueue.Add(ctx, 1)
}
func (c *Controller) IncTargetsProcessed(ctx context.Context) {
	c.targetsProcessed.Add(ctx, 1)
}
func (c *Controller) IncConfigReloads(ctx context.Context) {
	c.configReloads.Add(ctx, 1)
}
func (c *Controller) IncConfigReloadErrors(ctx context.Context) {
	c.configReloadErrors.Add(ctx, 1)
}
func (c *Controller) IncRulesSaved(ctx context.Context) {
	c.rulesSaved.Add(ctx, 1)
}
func (c *Controller) IncRuleSaveErrors(ctx context.Context) {
	c.ruleSaveErrors.Add(ctx, 1)
}

func (c *Controller) SetLeaderStatus(ctx context.Context, isLeader bool) {
	if isLeader {
		c.leaderStatus.Add(ctx, 1)
	} else {
		c.leaderStatus.Add(ctx, -1)
	}
}

func (c *Controller) ObserveTargetProcessingTime(ctx context.Context, duration time.Duration) {
	c.targetProcessingTime.Record(ctx, duration.Seconds())
}

func (c *Controller) TrackEnumeration(ctx context.Context, f func() error) error {
	c.activeEnumeration.Add(ctx, 1)
	defer c.activeEnumeration.Add(ctx, -1)

	start := time.Now()
	err := f()
	c.enumerationTime.Record(ctx, time.Since(start).Seconds())
	return err
}
