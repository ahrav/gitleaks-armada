package scanning

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	domain "github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

// taskStatusEntry tracks the latest known status of a task and when that status
// was last updated.
type taskStatusEntry struct {
	status    domain.TaskStatus
	updatedAt time.Time
}

// shouldBeCleanedUp returns whether a task in a terminal state has remained there
// longer than the configured retention period, indicating it can be removed.
// TODO: Add OnTaskStatusChanged to the metrics.
func (t *taskStatusEntry) shouldBeCleanedUp(tp timeProvider, retentionPeriod time.Duration) bool {
	return (t.status == domain.TaskStatusCompleted || t.status == domain.TaskStatusFailed) &&
		tp.Now().Sub(t.updatedAt) > retentionPeriod
}

// pendingMetric temporarily holds a metric event until it can be associated with
// a known task. This is necessary if the event arrives before the task itself
// has been recorded.
type pendingMetric struct {
	envelope  events.EventEnvelope
	timestamp time.Time
	attempts  int
}

var _ domain.JobMetricsAggregator = (*jobMetricsAggregator)(nil)

// jobMetricsAggregator implements in-memory aggregation of job/task metrics. It
// periodically flushes metrics and checkpoint updates to persistent storage
// through a domain.MetricsRepository. It also handles dynamic replay of historical
// events for recovery.
// TODO: Maybe consider splitting out the replayer.
type jobMetricsAggregator struct {
	controllerID string

	mu sync.RWMutex
	// In-memory tracking of job metrics.
	metrics map[uuid.UUID]*domain.JobMetrics // Job ID -> Metrics
	// Latest known task status.
	taskStatus map[uuid.UUID]taskStatusEntry // Task ID -> Status
	repository domain.MetricsRepository      // Persists metrics & state

	pendingAcks map[uuid.UUID]map[int32]events.AckFunc // jobID -> partition -> latest ack func

	checkpoints map[uuid.UUID]map[int32]int64 // Job ID -> Partition ID -> Offset
	replayer    events.DomainEventReplayer    // Replayer for consuming events to recover state

	pendingMetrics map[uuid.UUID][]pendingMetric // Metric events awaiting known task
	notifyCh       chan struct{}                 // Signals new metric events to process
	stopCh         chan struct{}                 // Signals aggregator shutdown
	wg             sync.WaitGroup                // used to wait for background goroutine(s)

	// Configuration.

	// cleanupInterval is how often we look for completed/failed tasks to clean up.
	cleanupInterval time.Duration
	// retentionPeriod is how long we retain task statuses after completion/failure.
	retentionPeriod time.Duration
	// retryInterval is how long we wait before checking our pending metrics
	// to see if there are any that failed to get processed initially.
	retryInterval time.Duration
	// maxRetries is the maximum number of retries we will attempt to get a task status.
	maxRetries int
	// TODO: Consider if we should have a max number of pending metrics we will
	// store.

	timeProvider timeProvider // reuse existing timeProvider interface

	// TODO: Enhance logging.
	logger *logger.Logger
	tracer trace.Tracer
}

// NewJobMetricsAggregator returns a new jobMetricsAggregator with default intervals
// for cleanup, retention, and retry. It starts background goroutines to clean up
// task statuses and process pending metrics.
func NewJobMetricsAggregator(
	controllerID string,
	repository domain.MetricsRepository,
	replayer events.DomainEventReplayer,
	logger *logger.Logger,
	tracer trace.Tracer,
) *jobMetricsAggregator {
	const (
		defaultCleanupInterval = 15 * time.Minute
		defaultRetentionPeriod = 1 * time.Hour
		defaultRetryInterval   = 1 * time.Minute
		defaultMaxRetries      = 5
	)
	logger = logger.With("component", "job_metrics_aggregator")

	t := &jobMetricsAggregator{
		controllerID:    controllerID,
		metrics:         make(map[uuid.UUID]*domain.JobMetrics),
		taskStatus:      make(map[uuid.UUID]taskStatusEntry),
		pendingAcks:     make(map[uuid.UUID]map[int32]events.AckFunc),
		repository:      repository,
		checkpoints:     make(map[uuid.UUID]map[int32]int64),
		replayer:        replayer,
		pendingMetrics:  make(map[uuid.UUID][]pendingMetric),
		notifyCh:        make(chan struct{}, 1), // dont block on sending to notifyCh
		stopCh:          make(chan struct{}),
		logger:          logger,
		tracer:          tracer,
		cleanupInterval: defaultCleanupInterval,
		retentionPeriod: defaultRetentionPeriod,
		retryInterval:   defaultRetryInterval,
		maxRetries:      defaultMaxRetries,
		timeProvider:    realTimeProvider{},
	}

	// Start background cleanup.
	ctx := context.Background()
	go t.startStatusCleanupWorker(ctx)
	t.wg.Add(1)
	go t.runBackgroundLoop(ctx)

	return t
}

// startStatusCleanupWorker periodically removes task status entries for tasks that
// have remained in a terminal state beyond the retention period.
func (t *jobMetricsAggregator) startStatusCleanupWorker(ctx context.Context) {
	t.mu.RLock()
	retentionPeriod := t.retentionPeriod
	cleanupInterval := t.cleanupInterval
	t.mu.RUnlock()

	logger := t.logger.With(
		"operation", "start_status_cleanup_worker",
		"interval", cleanupInterval,
		"retention_period", retentionPeriod,
	)

	ctx, span := t.tracer.Start(ctx, "job_metrics_aggregator.start_status_cleanup",
		trace.WithAttributes(
			attribute.String("controller_id", t.controllerID),
			attribute.String("interval", cleanupInterval.String()),
		))

	span.AddEvent("starting_status_cleanup_worker")
	logger.Info(ctx, "starting status cleanup worker")

	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	span.End()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.cleanupTaskStatus(ctx)
		}
	}
}

// cleanupTaskStatus scans the aggregator's task statuses and removes those that
// can be safely removed. It also prunes pending acknowledgments for completed jobs
// to free memory.
func (t *jobMetricsAggregator) cleanupTaskStatus(ctx context.Context) {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := t.timeProvider.Now()
	logger := t.logger.With(
		"operation", "cleanup_task_status",
		"now", now,
		"task_status_count", len(t.taskStatus),
	)
	logger.Info(ctx, "cleaning up task statuses")
	for taskID, entry := range t.taskStatus {
		if entry.shouldBeCleanedUp(t.timeProvider, t.retentionPeriod) {
			delete(t.taskStatus, taskID)
			logger.Info(ctx, "task status cleaned up", "task_id", taskID)
		}
	}

	// TODO: I need to come back to this and make sure this is okay.
	// Cleanup pendingAcks for completed jobs.
	for jobID := range t.pendingAcks {
		// If job is completed/failed and retention period passed
		if metrics, exists := t.metrics[jobID]; exists && metrics.IsCompleted() {
			delete(t.pendingAcks, jobID)
		}
	}

	logger.Info(ctx, "finished cleaning up task statuses")
}

// runBackgroundLoop processes pending metrics on a schedule or when signaled by notifyCh.
func (t *jobMetricsAggregator) runBackgroundLoop(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer t.wg.Done()

	logger := t.logger.With("operation", "run_background_loop")

	ctx, span := t.tracer.Start(ctx, "job_metrics_aggregator.run_background_loop",
		trace.WithAttributes(
			attribute.String("controller_id", t.controllerID),
		),
	)
	span.AddEvent("starting_background_loop")
	logger.Info(ctx, "starting background loop")

	span.End()

	ticker := time.NewTicker(t.retryInterval)
	defer ticker.Stop()

	for {
		t.mu.RLock()
		hasPending := len(t.pendingMetrics) > 0
		t.mu.RUnlock()

		// If there's nothing pending, block until we get a notify or a stop.
		if !hasPending {
			select {
			case <-t.notifyCh:
				t.processPendingMetrics(ctx)
			case <-t.stopCh:
				return
			}
		}

		select {
		case <-ticker.C:
			t.processPendingMetrics(ctx)
		case <-t.notifyCh:
			t.processPendingMetrics(ctx)
		case <-t.stopCh:
			return
		}
	}
}

// HandleEnumerationCompleted reacts to JobEnumerationCompletedEvent, setting the
// total number of tasks for the specified job. If metrics don't exist yet, it
// attempts to load them from storage or create new ones.
// TODO: What happens if the controller crashes before we process this event, do
// we still track job completion correctly?
func (t *jobMetricsAggregator) HandleEnumerationCompleted(
	ctx context.Context,
	evt events.EventEnvelope,
	ack events.AckFunc,
) error {
	logger := logger.NewLoggerContext(t.logger.With(
		"operation", "handle_enumeration_completed",
		"event_type", evt.Type,
	))
	ctx, span := t.tracer.Start(ctx, "job_metrics_aggregator.handle_enumeration_completed",
		trace.WithAttributes(
			attribute.String("controller_id", t.controllerID),
		),
	)
	defer span.End()

	enumEvt, ok := evt.Payload.(scanning.JobEnumerationCompletedEvent)
	if !ok {
		err := fmt.Errorf("invalid payload type, expected JobEnumerationCompletedEvent, got %T", evt.Payload)
		span.RecordError(err)
		span.SetStatus(codes.Error, "invalid payload type")
		return err
	}

	jobID := enumEvt.JobID
	totalTasks := enumEvt.TotalTasks

	span.SetAttributes(
		attribute.String("job_id", jobID.String()),
		attribute.Int("total_tasks", totalTasks),
	)
	logger.Add(
		"job_id", jobID.String(),
		"total_tasks", totalTasks,
	)

	logger.Info(ctx, "enumeration completed event received")

	// First, update/check shared fields using the lock.
	t.mu.Lock()
	// Update pending ack functions.
	if t.pendingAcks[jobID] == nil {
		t.pendingAcks[jobID] = make(map[int32]events.AckFunc)
	}
	t.pendingAcks[jobID][evt.Metadata.Partition] = ack

	// Update checkpoint information.
	if t.checkpoints[jobID] == nil {
		t.checkpoints[jobID] = make(map[int32]int64)
	}
	t.checkpoints[jobID][evt.Metadata.Partition] = evt.Metadata.Offset

	// See if job metrics have already been loaded.
	jm, exists := t.metrics[jobID]
	t.mu.Unlock()

	// If not loaded, perform a DB call outside the lock.
	if !exists {
		metrics, err := t.repository.GetJobMetrics(ctx, jobID)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "failed to load job metrics")
			return fmt.Errorf("failed to load job metrics for job %s: %w", jobID, err)
		}
		t.mu.Lock()
		// Double-check: it is possible another routine loaded metrics meanwhile.
		if existing, ok := t.metrics[jobID]; ok {
			jm = existing
		} else {
			t.metrics[jobID] = metrics
			jm = metrics
		}
		t.mu.Unlock()
	}

	// Now update the job metrics within the lock.
	t.mu.Lock()
	// Set or update the total number of tasks.
	jm.SetTotalTasks(totalTasks)
	// Check if the job is already completed.
	t.maybeMarkJobCompletedLocked(ctx, jobID, jm, logger)
	t.mu.Unlock()

	return nil
}

// maybeMarkJobCompletedLocked checks if a job has reached the "completed" state:
// that is, whether the number of completed/failed tasks matches the total number
// of enumerated tasks. If so, it updates the job status in persistent storage and
// optionally publishes a JobCompletedEvent.
//
// This method must be called while holding the t.mu lock. It is assumed the caller
// has already updated the in-memory JobMetrics counts accordingly (e.g., incremented
// the completed or failed counts) and/or set the total task count.
func (t *jobMetricsAggregator) maybeMarkJobCompletedLocked(
	ctx context.Context,
	jobID uuid.UUID,
	jm *domain.JobMetrics,
	logger *logger.LoggerContext,
) {
	span := trace.SpanFromContext(ctx)

	total := jm.TotalTasks()
	doneCount := jm.CompletedTasks() + jm.FailedTasks()

	if total > 0 && doneCount == total && !jm.IsCompleted() {
		err := t.repository.UpdateJobStatus(ctx, jobID, domain.JobStatusCompleted)
		if err != nil {
			// TODO: Maybe retry?
			span.RecordError(err)
			span.SetStatus(codes.Error, "failed to update job status")
			return
		}

		span.AddEvent("job_marked_completed")
		logger.Info(ctx, "job is completed", "job_id", jobID.String())

		// TODO: Maybe publish a job completed event?
	}
}

// HandleJobMetrics processes any TaskJobMetricEvent related to scanning tasks (e.g.,
// TaskStartedEvent, TaskCompletedEvent). It updates in-memory metrics, sets the
// latest ack function for the relevant partition, and handles out-of-order arrival
// by queueing metrics if the task record isn't available yet.
func (t *jobMetricsAggregator) HandleJobMetrics(ctx context.Context, evt events.EventEnvelope, ack events.AckFunc) error {
	logger := logger.NewLoggerContext(t.logger.With(
		"operation", "handle_job_metrics",
		"event_type", evt.Type,
	))

	ctx, span := t.tracer.Start(ctx, "job_metrics_aggregator.handle_job_metrics",
		trace.WithAttributes(
			attribute.String("controller_id", t.controllerID),
		),
	)
	defer span.End()

	metricEvt, ok := evt.Payload.(scanning.TaskJobMetricEvent)
	if !ok {
		err := fmt.Errorf("invalid event type for job metrics: expected TaskJobMetricEvent, got %T", evt.Payload)
		span.SetStatus(codes.Error, err.Error())
		span.RecordError(err)
		return fmt.Errorf("handle job metrics failed: %w", err)
	}

	span.SetAttributes(
		attribute.Int("partition", int(evt.Metadata.Partition)),
		attribute.Int64("offset", evt.Metadata.Offset),
		attribute.String("job_id", metricEvt.JobID.String()),
		attribute.String("task_id", metricEvt.TaskID.String()),
		attribute.String("status", string(metricEvt.Status)),
	)
	logger.Add(
		"job_id", metricEvt.JobID.String(),
		"task_id", metricEvt.TaskID.String(),
		"status", metricEvt.Status,
	)

	t.mu.Lock()
	// Store the latest ack function for this job's partition.
	if t.pendingAcks[metricEvt.JobID] == nil {
		t.pendingAcks[metricEvt.JobID] = make(map[int32]events.AckFunc)
	}
	// Only keep the latest ack function for each partition.
	t.pendingAcks[metricEvt.JobID][evt.Metadata.Partition] = ack

	// If we already have a pending metric for this task, append to the list.
	// This enforces task status changes are processed in order.
	// This avoids any regressive transitions.
	if _, exists := t.pendingMetrics[metricEvt.TaskID]; exists {
		span.AddEvent("task_id_in_pending_metrics")
		logger.Debug(ctx, "task_id in pending metrics, appending to list")
		t.pendingMetrics[metricEvt.TaskID] = append(t.pendingMetrics[metricEvt.TaskID], pendingMetric{
			envelope:  evt,
			timestamp: time.Now(),
		})
		t.mu.Unlock()
		return nil
	}
	t.mu.Unlock()

	// Check if we need state recovery.
	t.mu.RLock()
	_, exists := t.metrics[metricEvt.JobID]
	t.mu.RUnlock()

	if !exists {
		span.AddEvent("no_job_metrics_found_in_memory")
		metrics, err := t.repository.GetJobMetrics(ctx, metricEvt.JobID)
		if err != nil {
			// TODO: This should get removed once job metrics creation is fully handled post enumeration.
			if errors.Is(err, domain.ErrNoJobMetricsFound) {
				span.AddEvent("no_metrics_found", trace.WithAttributes(
					attribute.String("job_id", metricEvt.JobID.String()),
				))
				logger.Debug(ctx, "no job metrics found, creating new job metrics")
				metrics = domain.NewJobMetrics()
			} else {
				span.RecordError(err)
				span.SetStatus(codes.Error, "getting job metrics")
				return fmt.Errorf("failed to retrieve job metrics for (job_id: %s, task_id: %s, status: %s): %w",
					metricEvt.JobID, metricEvt.TaskID, metricEvt.Status, err)
			}
		}
		t.mu.Lock()
		t.metrics[metricEvt.JobID] = metrics
		t.mu.Unlock()

		checkpoints, err := t.repository.GetCheckpoints(ctx, metricEvt.JobID)
		if err != nil {
			if !errors.Is(err, domain.ErrNoCheckpointsFound) {
				span.RecordError(err)
				span.SetStatus(codes.Error, "getting checkpoints")
				return fmt.Errorf("failed to get checkpoints (job_id: %s, task_id: %s, status: %s): %w",
					metricEvt.JobID, metricEvt.TaskID, metricEvt.Status, err)
			}
			logger.Debug(ctx, "no checkpoints found, creating new checkpoints")
			span.AddEvent("no_checkpoints_found")
		}

		// Only replay if this partition has previous events.
		if len(checkpoints) > 0 {
			logger.Add("checkpoints_count", len(checkpoints))
			metadata := evt.Metadata
			if lastOffset, ok := checkpoints[metadata.Partition]; ok {
				logger.Add(
					"partition", metadata.Partition,
					"last_offset", lastOffset,
				)
				span.AddEvent("replaying_events", trace.WithAttributes(
					attribute.Int("partition", int(metadata.Partition)),
					attribute.Int64("offset", lastOffset),
				))
				logger.Info(ctx, "replaying events")
				if err := t.replayEvents(ctx, metricEvt.JobID, metadata.Partition, lastOffset); err != nil {
					span.RecordError(err)
					span.SetStatus(codes.Error, "replaying events")
					return fmt.Errorf("failed to replay events (job_id: %s, task_id: %s, status: %s, last_offset: %d): %w",
						metricEvt.JobID, metricEvt.TaskID, metricEvt.Status, lastOffset, err)
				}
				logger.Info(ctx, "events replayed successfully")
				span.AddEvent("events_replayed_successfully")
			}

			t.checkpoints[metricEvt.JobID] = checkpoints
			logger.Info(ctx, "replayed events, checkpoints updated")
		}
	}

	// Attempt to process the metric immediately.
	if err := t.processMetric(ctx, metricEvt); err != nil {
		if errors.Is(err, domain.ErrTaskNotFound) {
			span.AddEvent("task_not_found", trace.WithAttributes(
				attribute.String("task_id", metricEvt.TaskID.String()),
			))

			t.mu.Lock()
			// We don't have the task status yet: add to pending for retry.
			t.pendingMetrics[metricEvt.TaskID] = append(t.pendingMetrics[metricEvt.TaskID], pendingMetric{
				envelope:  evt,
				timestamp: time.Now(),
			})
			t.mu.Unlock()

			span.AddEvent("pending_metric_added")
			logger.Debug(ctx, "pending metric added", "task_id", metricEvt.TaskID.String())
			// Notify the background loop that we have new pending work.
			select {
			case t.notifyCh <- struct{}{}:
			default:
			}
			return nil
		}
		span.AddEvent("failed_to_process_metric", trace.WithAttributes(
			attribute.String("error", err.Error()),
		))
		span.RecordError(err)
		return fmt.Errorf("failed to process metric (job_id: %s, task_id: %s, status: %s): %w",
			metricEvt.JobID, metricEvt.TaskID, metricEvt.Status, err)
	}
	if t.checkpoints[metricEvt.JobID] == nil {
		t.checkpoints[metricEvt.JobID] = make(map[int32]int64)
	}
	t.checkpoints[metricEvt.JobID][evt.Metadata.Partition] = evt.Metadata.Offset
	logger.Info(ctx, "checkpoints updated")
	span.AddEvent("metric_processed")
	span.SetStatus(codes.Ok, "metric processed")

	return nil
}

// replayEvents replays historical events from a specific offset to rebuild metrics state
// for the specified partition. This is typically invoked if the aggregator hasn't
// seen job metrics for a while or upon startup.
func (t *jobMetricsAggregator) replayEvents(ctx context.Context, jobID uuid.UUID, partition int32, fromOffset int64) error {
	logger := t.logger.With(
		"operation", "replay_events",
		"job_id", jobID.String(),
		"partition", partition,
		"from_offset", fromOffset,
	)
	ctx, span := t.tracer.Start(ctx, "job_metrics_aggregator.replay_events",
		trace.WithAttributes(
			attribute.String("controller_id", t.controllerID),
			attribute.String("job_id", jobID.String()),
			attribute.Int("partition", int(partition)),
			attribute.Int64("from_offset", fromOffset),
		),
	)
	defer span.End()

	events, err := t.replayer.ReplayFromPosition(ctx, scanning.NewJobMetricsPosition(jobID, partition, fromOffset))
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "replaying events")
		return fmt.Errorf("failed to get events. error: %w", err)
	}
	span.AddEvent("starting_event_replay_stream")

	for evt := range events {
		if metricEvt, ok := evt.Payload.(scanning.TaskJobMetricEvent); ok {
			if metricEvt.JobID == jobID {
				if err := t.processMetric(ctx, metricEvt); err != nil {
					// During replay, if task not found, just skip it
					// These are historical events, so if task doesn't exist
					// now, it likely never will
					if errors.Is(err, domain.ErrTaskNotFound) {
						span.RecordError(err)
						logger.Warn(ctx, "task not found, skipping event", "error", err)
						continue
					}
					span.RecordError(err)
					span.SetStatus(codes.Error, "processing replayed event")
					return fmt.Errorf("processing replayed event: %w", err)
				}
			} else {
				logger.Warn(ctx, "skipping event for different job", "job_id", metricEvt.JobID.String())
			}
		}
	}
	span.AddEvent("event_replay_stream_completed")
	span.SetStatus(codes.Ok, "event replay stream completed")

	return nil
}

// processPendingMetrics attempts to process any metrics that arrived before the
// corresponding task was known. It re-queues metrics if they still cannot be resolved.
// TODO: come back to this and see if reusing the underlying slice is a good idea.
// Probably not worth it right now.
func (t *jobMetricsAggregator) processPendingMetrics(ctx context.Context) {
	t.mu.Lock()
	pending := t.pendingMetrics
	t.pendingMetrics = make(map[uuid.UUID][]pendingMetric)
	t.mu.Unlock()

	logger := t.logger.With(
		"operation", "process_pending_metrics",
		"pending_metrics_count", len(pending),
	)
	ctx, span := t.tracer.Start(ctx, "job_metrics_aggregator.process_pending_metrics",
		trace.WithAttributes(
			attribute.String("controller_id", t.controllerID),
		),
	)
	defer span.End()

	span.AddEvent("processing_pending_metrics", trace.WithAttributes(
		attribute.Int("count", len(pending)),
	))

	remaining := make(map[uuid.UUID][]pendingMetric)
	for taskID, pMetric := range pending {
		for _, pm := range pMetric {
			metricEvt, ok := pm.envelope.Payload.(scanning.TaskJobMetricEvent)
			if !ok {
				continue
			}
			if pm.attempts > t.maxRetries {
				// TODO: drop + do something.
				span.AddEvent("metric_dropped", trace.WithAttributes(
					attribute.String("task_id", metricEvt.TaskID.String()),
				))
				logger.Warn(ctx, "metric dropped", "task_id", taskID.String())
				continue
			}

			err := t.processMetric(ctx, metricEvt)
			if err != nil {
				if errors.Is(err, domain.ErrTaskNotFound) {
					// Still not found—bump attempts and re-queue.
					pm.attempts++
					remaining[taskID] = append(remaining[taskID], pm)
					span.AddEvent("metric_re-queued", trace.WithAttributes(
						attribute.String("task_id", taskID.String()),
						attribute.Int("attempts", pm.attempts),
					))
				} else {
					span.AddEvent("failed_to_process_metric", trace.WithAttributes(
						attribute.String("task_id", taskID.String()),
						attribute.String("error", err.Error()),
					))
					span.RecordError(err)
					logger.Error(ctx,
						"failed to process pending metric",
						"task_id", taskID.String(),
						"error", err,
					)
				}
			} else {
				// Update checkpoint from the envelope since the processing succeeded.
				jobID := metricEvt.JobID
				partition := pm.envelope.Metadata.Partition
				offset := pm.envelope.Metadata.Offset

				t.mu.Lock()
				if t.checkpoints[jobID] == nil {
					t.checkpoints[jobID] = make(map[int32]int64)
				}
				t.checkpoints[jobID][partition] = offset
				t.mu.Unlock()
			}
		}
	}
	span.AddEvent("pending_metrics_processed", trace.WithAttributes(
		attribute.Int("remaining", len(remaining)),
	))
	span.SetStatus(codes.Ok, "pending metrics processed")
	logger.Info(ctx, "pending metrics processed", "remaining", len(remaining))

	t.mu.Lock()
	// Merge any new pending metrics that arrived while we were processing.
	for taskID, metrics := range t.pendingMetrics {
		remaining[taskID] = append(remaining[taskID], metrics...)
	}
	t.pendingMetrics = remaining
	span.AddEvent("pending_metrics_merged", trace.WithAttributes(
		attribute.Int("pending_metrics_count", len(t.pendingMetrics)),
	))
	t.mu.Unlock()
}

// processMetric updates in-memory metrics for a single TaskJobMetricEvent. It
// returns domain.ErrTaskNotFound if the task has not yet been created.
func (t *jobMetricsAggregator) processMetric(ctx context.Context, evt scanning.TaskJobMetricEvent) error {
	logger := logger.NewLoggerContext(t.logger.With(
		"operation", "process_metric",
		"job_id", evt.JobID.String(),
		"task_id", evt.TaskID.String(),
		"new_status", evt.Status,
	))
	ctx, span := t.tracer.Start(ctx, "job_metrics_aggregator.process_metric",
		trace.WithAttributes(
			attribute.String("controller_id", t.controllerID),
		),
	)
	defer span.End()

	span.SetAttributes(
		attribute.String("job_id", evt.JobID.String()),
		attribute.String("task_id", evt.TaskID.String()),
		attribute.String("new_status", string(evt.Status)),
	)

	if _, err := t.repository.GetTask(ctx, evt.TaskID); err != nil {
		if errors.Is(err, domain.ErrTaskNotFound) {
			return domain.ErrTaskNotFound
		}
		span.RecordError(err)
		span.SetStatus(codes.Error, "task lookup failed")
		return fmt.Errorf("task lookup failed for task %s in job %s: %w",
			evt.TaskID, evt.JobID, err)
	}

	// Check under the lock if we already have JobMetrics loaded for this job.
	t.mu.Lock()
	jm, exists := t.metrics[evt.JobID]
	t.mu.Unlock()

	// If not found, do the DB call outside the lock.
	if !exists {
		metrics, err := t.repository.GetJobMetrics(ctx, evt.JobID)
		if err != nil {
			if errors.Is(err, domain.ErrNoJobMetricsFound) {
				metrics = domain.NewJobMetrics()
			} else {
				span.RecordError(err)
				span.SetStatus(codes.Error, "failed to load job metrics")
				return fmt.Errorf("failed to load job metrics for job %s: %w",
					evt.JobID, err)
			}
		}

		// Re-lock and "double-check" if someone else already loaded metrics.
		t.mu.Lock()
		jm, exists = t.metrics[evt.JobID]
		if !exists {
			t.metrics[evt.JobID] = metrics
			jm = metrics
		}
		t.mu.Unlock()
	}

	// Now do the rest of the processing under the lock.
	t.mu.Lock()
	defer t.mu.Unlock()

	// Check the old status in t.taskStatus to see if we're transitioning.
	entry, hasEntry := t.taskStatus[evt.TaskID]
	oldStatus := domain.TaskStatusUnspecified
	if hasEntry {
		oldStatus = entry.status
	}
	logger.Add("old_status", oldStatus)

	// If old status differs from new status, update metrics accordingly.
	if oldStatus != evt.Status {
		if !hasEntry {
			// Possibly the first metric for this task; treat as OnTaskAdded.
			jm.OnTaskAdded(evt.Status)
			span.AddEvent("task_added")
		} else {
			jm.OnTaskStatusChanged(oldStatus, evt.Status)
			span.AddEvent("task_status_changed")
		}
	} else {
		logger.Debug(ctx, "task status unchanged")
		span.AddEvent("task_status_unchanged")
	}

	// Update the in-memory record of this task’s status.
	t.taskStatus[evt.TaskID] = taskStatusEntry{
		status:    evt.Status,
		updatedAt: time.Now(),
	}

	// Possibly mark job as completed if we have all tasks done, etc.
	t.maybeMarkJobCompletedLocked(ctx, evt.JobID, jm, logger)

	logger.Debug(ctx, "task metrics processed")
	span.AddEvent("task_status_cached",
		trace.WithAttributes(
			attribute.String("status", string(evt.Status)),
			attribute.String("timestamp", time.Now().UTC().String()),
		),
	)
	span.SetStatus(codes.Ok, "task metrics processed")

	return nil
}

// LaunchMetricsFlusher starts a separate goroutine that periodically invokes FlushMetrics.
// This ensures that in-memory metrics are regularly persisted to the database.
func (t *jobMetricsAggregator) LaunchMetricsFlusher(interval time.Duration) {
	logger := t.logger.With(
		"operation", "launch_metrics_flusher",
		"interval", interval,
	)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ctx, span := t.tracer.Start(ctx, "job_metrics_aggregator.start_metrics_flush",
		trace.WithAttributes(
			attribute.String("controller_id", t.controllerID),
		),
	)

	span.AddEvent("starting_metrics_flusher")
	logger.Info(ctx, "starting metrics flusher")

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	span.End()

	for {
		select {
		case <-ctx.Done():
			// Ensure final flush on shutdown.
			if err := t.FlushMetrics(ctx); err != nil {
				logger.Error(ctx, "failed to flush metrics on shutdown", "error", err)
			}
			return
		case <-ticker.C:
			if err := t.FlushMetrics(ctx); err != nil {
				logger.Error(ctx, "failed to flush metrics on tick", "error", err)
			}
		}
	}
}

// FlushMetrics persists the aggregator's in-memory metrics and checkpoints to
// storage. It attempts to update every tracked job, logging but not halting on errors.
func (t *jobMetricsAggregator) FlushMetrics(ctx context.Context) error {
	t.mu.RLock()
	metricCount := len(t.metrics)
	jobMetrics := make(map[uuid.UUID]*domain.JobMetrics, metricCount)
	for id, m := range t.metrics {
		jobMetrics[id] = m
	}
	t.mu.RUnlock()

	logger := t.logger.With("operation", "flush_metrics", "metrics_count", metricCount)
	ctx, span := t.tracer.Start(ctx, "job_metrics_aggregator.flush_metrics",
		trace.WithAttributes(
			attribute.String("controller_id", t.controllerID),
			attribute.Int("metrics_count", metricCount),
		),
	)
	defer span.End()

	span.AddEvent("starting_metrics_flush")

	var flushErrors []error
	for jobID, metrics := range jobMetrics {
		if err := t.flushJobMetrics(ctx, jobID, metrics); err != nil {
			flushErrors = append(flushErrors, fmt.Errorf("job %s: %w", jobID, err))
			span.RecordError(err)
			logger.Error(ctx, "failed to flush job metrics",
				"job_id", jobID,
				"error", err,
			)
		}
	}

	if len(flushErrors) > 0 {
		err := fmt.Errorf("failed to flush metrics for %d jobs: %w",
			len(flushErrors), errors.Join(flushErrors...))
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	span.AddEvent("metrics_flushed")
	span.SetStatus(codes.Ok, "metrics flushed")
	logger.Info(ctx, "metrics flushed")

	return nil
}

// flushJobMetrics updates persistent metrics and commits offsets for each partition
// for the given job, then acknowledges the consumed messages if successful.
func (t *jobMetricsAggregator) flushJobMetrics(ctx context.Context, jobID uuid.UUID, metrics *domain.JobMetrics) error {
	logger := t.logger.With("operation", "flush_job_metrics", "job_id", jobID.String())
	span := trace.SpanFromContext(ctx)
	t.mu.RLock()
	chckpt := make(map[int32]int64)
	for k, v := range t.checkpoints[jobID] {
		chckpt[k] = v
	}
	t.mu.RUnlock()

	if len(chckpt) == 0 {
		logger.Debug(ctx, "no partitions to flush")
		span.AddEvent("no_partitions_to_flush", trace.WithAttributes(
			attribute.String("job_id", jobID.String()),
		))
		return nil
	}

	logger.Debug(ctx, "flushing partitions", "num_partitions", len(chckpt))
	span.AddEvent("flushing_partitions", trace.WithAttributes(
		attribute.String("job_id", jobID.String()),
		attribute.Int("num_partitions", len(chckpt)),
	))

	var partitionErrors []error
	for partition, offset := range chckpt {
		logger.Debug(ctx, "flushing partition", "partition", partition, "offset", offset)
		if err := t.repository.UpdateMetricsAndCheckpoint(ctx, jobID, metrics, partition, offset); err != nil {
			partitionErrors = append(partitionErrors, fmt.Errorf("partition %d: update failed: %w", partition, err))
			continue
		}

		span.AddEvent("metrics_partition_flushed", trace.WithAttributes(
			attribute.String("job_id", jobID.String()),
			attribute.Int("partition", int(partition)),
			attribute.Int64("offset", offset),
		))

		t.mu.Lock()
		// After successful DB update, ack the latest message for this partition.
		if ack := t.pendingAcks[jobID][partition]; ack != nil {
			ack(nil) // This will mark and commit the latest offset
			delete(t.pendingAcks[jobID], partition)
		}
		t.mu.Unlock()
	}

	if len(partitionErrors) > 0 {
		return fmt.Errorf("failed to flush %d partitions: %w",
			len(partitionErrors), errors.Join(partitionErrors...))
	}
	return nil
}

// Stop signals the aggregator to shut down, waits for background loops to finish,
// and flushes any remaining pending metrics before exiting.
func (t *jobMetricsAggregator) Stop(ctx context.Context) {
	logger := t.logger.With("operation", "stop_metrics_aggregator")
	_, span := t.tracer.Start(ctx, "job_metrics_aggregator.stop",
		trace.WithAttributes(
			attribute.String("controller_id", t.controllerID),
		),
	)
	defer span.End()

	span.AddEvent("stopping_metrics_aggregator")
	logger.Info(ctx, "stopping metrics aggregator")
	close(t.stopCh)

	// Lets flush any pending metrics.
	t.processPendingMetrics(ctx)

	// TODO: This could hang if the flusher is stuck.
	t.wg.Wait()

	span.AddEvent("metrics_aggregator_stopped")
	span.SetStatus(codes.Ok, "metrics aggregator stopped")
	logger.Info(ctx, "metrics aggregator stopped")
}
