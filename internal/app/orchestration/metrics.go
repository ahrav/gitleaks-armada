package orchestration

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/ahrav/gitleaks-armada/internal/infra/eventbus/kafka"
)

// OrchestrationMetrics defines metrics operations needed by the orchestrator.
type OrchestrationMetrics interface {
	// EventBus metrics.
	kafka.EventBusMetrics

	// EventReplayer metrics.
	kafka.EventReplayerMetrics

	// OffsetCommitter metrics.
	kafka.OffsetCommitterMetrics

	// Leader election metrics
	SetLeaderStatus(ctx context.Context, isLeader bool)

	// Config metrics
	IncConfigReloads(ctx context.Context)
	IncConfigReloadErrors(ctx context.Context)

	// Rules storage metrics (renamed to be more clear)
	IncRulesSaved(ctx context.Context)     // Tracks individual rules saved to DB
	IncRuleSaveErrors(ctx context.Context) // Tracks errors saving rules to DB

	// Enumeration metrics.
	TrackEnumeration(ctx context.Context, f func() error) error
	IncTargetsProcessed(ctx context.Context)
	ObserveTargetProcessingTime(ctx context.Context, duration time.Duration)
	IncEnumerationStarted(ctx context.Context)                 // Track how many enumerations we start
	IncEnumerationCompleted(ctx context.Context)               // Track successful completions
	IncEnumerationErrors(ctx context.Context)                  // Track enumeration failures
	ObserveEnumerationBatchSize(ctx context.Context, size int) // Track size of target batches
	ObserveTargetsPerJob(ctx context.Context, count int)       // Track targets discovered per job
	IncJobsCreated(ctx context.Context)                        // Track total jobs created
	// TODO:
	// ObserveJobDuration(ctx context.Context, duration time.Duration) // Track how long jobs take
	// IncJobsCompleted(ctx context.Context)                           // Track completed jobs
	// IncJobsFailed(ctx context.Context)                              // Track failed jobs
}

// OrchestrationMetrics implements OrchestrationMetrics
type orchestrationMetrics struct {
	// Broker metrics.
	messagesPublished metric.Int64Counter
	messagesConsumed  metric.Int64Counter
	publishErrors     metric.Int64Counter
	consumeErrors     metric.Int64Counter

	// EnumerationTask metrics
	enumerationTasksEnqueued        metric.Int64Counter
	enumerationTasksRetried         metric.Int64Counter
	enumerationTasksFailedToEnqueue metric.Int64Counter

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

	// Enumeration metrics
	enumerationsStarted   metric.Int64Counter
	enumerationsCompleted metric.Int64Counter
	enumerationErrors     metric.Int64Counter
	enumerationBatchSize  metric.Int64Histogram
	targetsPerJob         metric.Int64Histogram
	jobDuration           metric.Float64Histogram
	jobsCreated           metric.Int64Counter
	jobsCompleted         metric.Int64Counter
	jobsFailed            metric.Int64Counter

	// Event replay metrics
	replayStarted       metric.Int64Counter
	replayCompleted     metric.Int64Counter
	replayErrors        metric.Int64Counter
	messagesReplayed    metric.Int64Counter
	messageReplayErrors metric.Int64Counter
	replayBatchSize     metric.Int64Histogram
	replayDuration      metric.Float64Histogram

	// Offset committer metrics
	commitsStarted    metric.Int64Counter
	commitsCompleted  metric.Int64Counter
	commitErrors      metric.Int64Counter
	partitionsManaged metric.Int64Counter
	partitionErrors   metric.Int64Counter
	commitDuration    metric.Float64Histogram
}

const namespace = "controller"

// NewOrchestrationMetrics creates a new orchestration metrics instance.
func NewOrchestrationMetrics(mp metric.MeterProvider) (*orchestrationMetrics, error) {
	meter := mp.Meter(namespace, metric.WithInstrumentationVersion("v0.1.0"))

	c := new(orchestrationMetrics)
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

	if c.enumerationTasksEnqueued, err = meter.Int64Counter(
		"tasks_enqueued_total",
		metric.WithDescription("Total number of tasks published to Kafka"),
	); err != nil {
		return nil, err
	}

	if c.enumerationTasksRetried, err = meter.Int64Counter(
		"tasks_retried_total",
		metric.WithDescription("Total number of tasks that were retried"),
	); err != nil {
		return nil, err
	}

	if c.enumerationTasksFailedToEnqueue, err = meter.Int64Counter(
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

	if c.enumerationsStarted, err = meter.Int64Counter(
		"enumerations_started_total",
		metric.WithDescription("Total number of enumeration processes started"),
	); err != nil {
		return nil, err
	}

	if c.enumerationsCompleted, err = meter.Int64Counter(
		"enumerations_completed_total",
		metric.WithDescription("Total number of enumeration processes completed successfully"),
	); err != nil {
		return nil, err
	}

	if c.enumerationErrors, err = meter.Int64Counter(
		"enumeration_errors_total",
		metric.WithDescription("Total number of enumeration failures"),
	); err != nil {
		return nil, err
	}

	if c.enumerationBatchSize, err = meter.Int64Histogram(
		"enumeration_batch_size",
		metric.WithDescription("Size of target batches discovered during enumeration"),
	); err != nil {
		return nil, err
	}

	if c.targetsPerJob, err = meter.Int64Histogram(
		"targets_per_job",
		metric.WithDescription("Number of targets discovered per enumeration job"),
	); err != nil {
		return nil, err
	}

	if c.jobDuration, err = meter.Float64Histogram(
		"job_duration_seconds",
		metric.WithDescription("Duration of enumeration jobs"),
	); err != nil {
		return nil, err
	}

	if c.jobsCreated, err = meter.Int64Counter(
		"jobs_created_total",
		metric.WithDescription("Total number of enumeration jobs created"),
	); err != nil {
		return nil, err
	}

	if c.jobsCompleted, err = meter.Int64Counter(
		"jobs_completed_total",
		metric.WithDescription("Total number of enumeration jobs completed successfully"),
	); err != nil {
		return nil, err
	}

	if c.jobsFailed, err = meter.Int64Counter(
		"jobs_failed_total",
		metric.WithDescription("Total number of enumeration jobs that failed"),
	); err != nil {
		return nil, err
	}

	if c.replayStarted, err = meter.Int64Counter(
		"replay_started_total",
		metric.WithDescription("Total number of event replay operations started"),
	); err != nil {
		return nil, err
	}

	if c.replayCompleted, err = meter.Int64Counter(
		"replay_completed_total",
		metric.WithDescription("Total number of event replay operations completed successfully"),
	); err != nil {
		return nil, err
	}

	if c.replayErrors, err = meter.Int64Counter(
		"replay_errors_total",
		metric.WithDescription("Total number of event replay operation failures"),
	); err != nil {
		return nil, err
	}

	if c.messagesReplayed, err = meter.Int64Counter(
		"messages_replayed_total",
		metric.WithDescription("Total number of messages replayed"),
	); err != nil {
		return nil, err
	}

	if c.messageReplayErrors, err = meter.Int64Counter(
		"message_replay_errors_total",
		metric.WithDescription("Total number of message replay errors"),
	); err != nil {
		return nil, err
	}

	if c.replayBatchSize, err = meter.Int64Histogram(
		"replay_batch_size",
		metric.WithDescription("Size of message batches during replay"),
	); err != nil {
		return nil, err
	}

	if c.replayDuration, err = meter.Float64Histogram(
		"replay_duration_seconds",
		metric.WithDescription("Duration of replay operations in seconds"),
	); err != nil {
		return nil, err
	}

	// Initialize offset committer metrics
	if c.commitsStarted, err = meter.Int64Counter(
		"commits_started_total",
		metric.WithDescription("Total number of offset commit operations started"),
	); err != nil {
		return nil, err
	}

	if c.commitsCompleted, err = meter.Int64Counter(
		"commits_completed_total",
		metric.WithDescription("Total number of offset commit operations completed successfully"),
	); err != nil {
		return nil, err
	}

	if c.commitErrors, err = meter.Int64Counter(
		"commit_errors_total",
		metric.WithDescription("Total number of offset commit operation errors"),
	); err != nil {
		return nil, err
	}

	if c.partitionsManaged, err = meter.Int64Counter(
		"partitions_managed_total",
		metric.WithDescription("Total number of partitions successfully managed"),
	); err != nil {
		return nil, err
	}

	if c.partitionErrors, err = meter.Int64Counter(
		"partition_management_errors_total",
		metric.WithDescription("Total number of partition management errors"),
	); err != nil {
		return nil, err
	}

	if c.commitDuration, err = meter.Float64Histogram(
		"commit_duration_seconds",
		metric.WithDescription("Time taken to commit offsets"),
		metric.WithUnit("s"),
	); err != nil {
		return nil, err
	}

	return c, nil
}

// Interface implementation methods.
func (c *orchestrationMetrics) IncMessagePublished(ctx context.Context, topic string) {
	c.messagesPublished.Add(ctx, 1, metric.WithAttributes(attribute.String("topic", topic)))
}
func (c *orchestrationMetrics) IncMessageConsumed(ctx context.Context, topic string) {
	c.messagesConsumed.Add(ctx, 1, metric.WithAttributes(attribute.String("topic", topic)))
}
func (c *orchestrationMetrics) IncPublishError(ctx context.Context, topic string) {
	c.publishErrors.Add(ctx, 1, metric.WithAttributes(attribute.String("topic", topic)))
}
func (c *orchestrationMetrics) IncConsumeError(ctx context.Context, topic string) {
	c.consumeErrors.Add(ctx, 1, metric.WithAttributes(attribute.String("topic", topic)))
}
func (c *orchestrationMetrics) IncEnumerationTasksEnqueued(ctx context.Context) {
	c.enumerationTasksEnqueued.Add(ctx, 1)
}
func (c *orchestrationMetrics) IncEnumerationTasksRetried(ctx context.Context) {
	c.enumerationTasksRetried.Add(ctx, 1)
}
func (c *orchestrationMetrics) IncEnumerationTasksFailedToEnqueue(ctx context.Context) {
	c.enumerationTasksFailedToEnqueue.Add(ctx, 1)
}
func (c *orchestrationMetrics) IncTargetsProcessed(ctx context.Context) {
	c.targetsProcessed.Add(ctx, 1)
}
func (c *orchestrationMetrics) IncConfigReloads(ctx context.Context) {
	c.configReloads.Add(ctx, 1)
}
func (c *orchestrationMetrics) IncConfigReloadErrors(ctx context.Context) {
	c.configReloadErrors.Add(ctx, 1)
}
func (c *orchestrationMetrics) IncRulesSaved(ctx context.Context) {
	c.rulesSaved.Add(ctx, 1)
}
func (c *orchestrationMetrics) IncRuleSaveErrors(ctx context.Context) {
	c.ruleSaveErrors.Add(ctx, 1)
}

func (c *orchestrationMetrics) SetLeaderStatus(ctx context.Context, isLeader bool) {
	if isLeader {
		c.leaderStatus.Add(ctx, 1)
	} else {
		c.leaderStatus.Add(ctx, -1)
	}
}

func (c *orchestrationMetrics) ObserveTargetProcessingTime(ctx context.Context, duration time.Duration) {
	c.targetProcessingTime.Record(ctx, duration.Seconds())
}

func (c *orchestrationMetrics) TrackEnumeration(ctx context.Context, f func() error) error {
	c.activeEnumeration.Add(ctx, 1)
	defer c.activeEnumeration.Add(ctx, -1)

	start := time.Now()
	err := f()
	c.enumerationTime.Record(ctx, time.Since(start).Seconds())
	return err
}

func (c *orchestrationMetrics) IncEnumerationStarted(ctx context.Context) {
	c.enumerationsStarted.Add(ctx, 1)
}

func (c *orchestrationMetrics) IncEnumerationCompleted(ctx context.Context) {
	c.enumerationsCompleted.Add(ctx, 1)
}

func (c *orchestrationMetrics) IncEnumerationErrors(ctx context.Context) {
	c.enumerationErrors.Add(ctx, 1)
}

func (c *orchestrationMetrics) ObserveEnumerationBatchSize(ctx context.Context, size int) {
	c.enumerationBatchSize.Record(ctx, int64(size))
}

func (c *orchestrationMetrics) ObserveTargetsPerJob(ctx context.Context, count int) {
	c.targetsPerJob.Record(ctx, int64(count))
}

func (c *orchestrationMetrics) ObserveJobDuration(ctx context.Context, duration time.Duration) {
	c.jobDuration.Record(ctx, duration.Seconds())
}

func (c *orchestrationMetrics) IncJobsCreated(ctx context.Context) {
	c.jobsCreated.Add(ctx, 1)
}

func (c *orchestrationMetrics) IncJobsCompleted(ctx context.Context) {
	c.jobsCompleted.Add(ctx, 1)
}

func (c *orchestrationMetrics) IncJobsFailed(ctx context.Context) {
	c.jobsFailed.Add(ctx, 1)
}

// EventReplayerMetrics implementation
func (c *orchestrationMetrics) IncReplayStarted(ctx context.Context) {
	c.replayStarted.Add(ctx, 1)
}

func (c *orchestrationMetrics) IncReplayCompleted(ctx context.Context) {
	c.replayCompleted.Add(ctx, 1)
}

func (c *orchestrationMetrics) IncReplayErrors(ctx context.Context) {
	c.replayErrors.Add(ctx, 1)
}

func (c *orchestrationMetrics) IncMessageReplayed(ctx context.Context, topic string) {
	c.messagesReplayed.Add(ctx, 1, metric.WithAttributes(attribute.String("topic", topic)))
}

func (c *orchestrationMetrics) IncMessageReplayError(ctx context.Context, topic string) {
	c.messageReplayErrors.Add(ctx, 1, metric.WithAttributes(attribute.String("topic", topic)))
}

func (c *orchestrationMetrics) ObserveReplayBatchSize(ctx context.Context, size int) {
	c.replayBatchSize.Record(ctx, int64(size))
}

func (c *orchestrationMetrics) ObserveReplayDuration(ctx context.Context, duration time.Duration) {
	c.replayDuration.Record(ctx, duration.Seconds())
}

// OffsetCommitterMetrics implementation
func (c *orchestrationMetrics) IncCommitStarted(ctx context.Context) {
	c.commitsStarted.Add(ctx, 1)
}

func (c *orchestrationMetrics) IncCommitCompleted(ctx context.Context) {
	c.commitsCompleted.Add(ctx, 1)
}

func (c *orchestrationMetrics) IncCommitErrors(ctx context.Context) {
	c.commitErrors.Add(ctx, 1)
}

func (c *orchestrationMetrics) IncPartitionManaged(ctx context.Context, topic string) {
	c.partitionsManaged.Add(ctx, 1, metric.WithAttributes(
		attribute.String("topic", topic),
	))
}

func (c *orchestrationMetrics) IncPartitionManagementError(ctx context.Context, topic string) {
	c.partitionErrors.Add(ctx, 1, metric.WithAttributes(
		attribute.String("topic", topic),
	))
}

func (c *orchestrationMetrics) ObserveCommitDuration(ctx context.Context, duration time.Duration) {
	c.commitDuration.Record(ctx, duration.Seconds())
}
