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
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

type timeProvider interface {
	Now() time.Time
}

// realTimeProvider is a real implementation of the timeProvider interface.
type realTimeProvider struct{}

// Now returns the current time.
func (realTimeProvider) Now() time.Time { return time.Now() }

var _ scanning.TaskHealthMonitor = (*taskHealthSupervisor)(nil)

// taskHealthSupervisor monitors task health by tracking heartbeats from running tasks.
// It provides two main functions:
//  1. Maintains an in-memory cache of task heartbeats that is periodically flushed to storage
//  2. Periodically checks for and marks tasks as stale if they haven't sent a heartbeat within
//     the configured threshold duration
type taskHealthSupervisor struct {
	// ID of the controller in order to only check for stale tasks for that controller.
	controllerID string

	// healthSvc provides persistence and task state management operations.
	healthSvc scanning.TaskHealthService
	// stateHandler handles task state changes.
	stateHandler scanning.TaskStateHandler

	// eventPublisher is used to publish stale task events.
	eventPublisher events.DomainEventPublisher

	// flushInterval controls how often heartbeats are persisted to storage.
	flushInterval time.Duration
	// stalenessCheckIntv controls frequency of stale task checks.
	stalenessCheckIntv time.Duration
	// stalenessThreshold is the duration after which a task with no heartbeat is considered stale.
	stalenessThreshold time.Duration

	mu             sync.RWMutex
	heartbeatCache map[uuid.UUID]time.Time

	// cancel allows graceful shutdown of background goroutines.
	cancel context.CancelCauseFunc

	// timeProvider is used to get the current time.
	timeProvider timeProvider

	// tracer provides distributed tracing for request flows.
	tracer trace.Tracer
	// logger provides structured logging for operational visibility.
	logger *logger.Logger
}

// NewTaskHealthSupervisor creates a new TaskHealthSupervisor instance that monitors task health
// by tracking heartbeats and detecting stale tasks. It uses the provided TaskHealthService
// for persistence and task state management.
func NewTaskHealthSupervisor(
	controllerID string,
	healthSvc scanning.TaskHealthService,
	stateHandler scanning.TaskStateHandler,
	eventPublisher events.DomainEventPublisher,
	tracer trace.Tracer,
	logger *logger.Logger,
) *taskHealthSupervisor {
	logger = logger.With("component", "task_health_supervisor")
	return &taskHealthSupervisor{
		controllerID:       controllerID,
		healthSvc:          healthSvc,
		stateHandler:       stateHandler,
		eventPublisher:     eventPublisher,
		flushInterval:      3 * time.Second,
		stalenessCheckIntv: 15 * time.Second,
		stalenessThreshold: 20 * time.Second,
		tracer:             tracer,
		logger:             logger,
		timeProvider:       realTimeProvider{},
		heartbeatCache:     make(map[uuid.UUID]time.Time),
	}
}

// Start launches background goroutines that:
// 1. Periodically flush cached heartbeats to persistent storage
// 2. Check for and mark tasks as stale if they haven't sent a heartbeat within the staleness threshold
//
// The goroutines run until the provided context is canceled, at which point a final
// heartbeat flush is performed before shutdown.
func (h *taskHealthSupervisor) Start(ctx context.Context) {
	ctx, span := h.tracer.Start(ctx, "heartbeat_monitor.scanning.start_staleness_loop",
		trace.WithAttributes(
			attribute.String("controller_id", h.controllerID),
			attribute.String("interval", h.stalenessCheckIntv.String()),
			attribute.String("threshold", h.stalenessThreshold.String()),
		))
	defer span.End()

	ctx, h.cancel = context.WithCancelCause(ctx)

	span.AddEvent("staleness_loop_started")

	go func() {
		flushTicker := time.NewTicker(h.flushInterval)
		staleTicker := time.NewTicker(h.stalenessCheckIntv)
		defer func() {
			flushTicker.Stop()
			staleTicker.Stop()
		}()

		for {
			select {
			case <-flushTicker.C:
				h.flushHeartbeats(ctx)

			case <-staleTicker.C:
				h.checkForStaleTasks(ctx)

			case <-ctx.Done():
				// Perform final flush before shutting down
				h.flushHeartbeats(ctx)
				return
			}
		}
	}()
}

// flushHeartbeats persists cached task heartbeats to storage. It acquires a lock,
// copies and clears the cache, then releases the lock before performing the update
// to minimize contention.
func (h *taskHealthSupervisor) flushHeartbeats(ctx context.Context) {
	logger := h.logger.With("operation", "flush_heartbeats", "flush_interval", h.flushInterval)
	ctx, span := h.tracer.Start(ctx, "heartbeat_monitor.scanning.flush_heartbeats",
		trace.WithAttributes(
			attribute.String("controller_id", h.controllerID),
		),
	)
	defer span.End()

	h.mu.Lock()
	if len(h.heartbeatCache) == 0 {
		h.mu.Unlock()
		return
	}

	batch := make(map[uuid.UUID]time.Time, len(h.heartbeatCache))
	for k, v := range h.heartbeatCache {
		batch[k] = v
		delete(h.heartbeatCache, k)
	}
	h.mu.Unlock()

	batchSize := len(batch)
	span.AddEvent("heartbeats_batch_prepared", trace.WithAttributes(
		attribute.Int("batch_size", batchSize),
	))

	if _, err := h.healthSvc.UpdateHeartbeats(ctx, batch); err != nil {
		logger.Error(ctx, "Heartbeat batch update failed",
			"batch_size", batchSize,
			"err", err,
		)
		span.SetStatus(codes.Error, fmt.Sprintf("heartbeat batch update failed (%d entries)", batchSize))
		span.RecordError(err)
		return
	}

	span.AddEvent("heartbeats_flushed")
	span.SetStatus(codes.Ok, "heartbeats flushed")
}

// checkForStaleTasks queries for tasks that haven't sent a heartbeat within the staleness
// threshold and marks them as stale. This enables automated detection and recovery of
// failed or unresponsive tasks.
func (h *taskHealthSupervisor) checkForStaleTasks(ctx context.Context) {
	logr := h.logger.With("operation", "check_for_stale_tasks", "staleness_threshold", h.stalenessThreshold)
	ctx, span := h.tracer.Start(ctx, "heartbeat_monitor.scanning.check_for_stale_tasks",
		trace.WithAttributes(
			attribute.String("controller_id", h.controllerID),
		),
	)
	defer span.End()

	now := h.timeProvider.Now().UTC()
	cutoff := now.Add(-h.stalenessThreshold)
	span.SetAttributes(
		attribute.String("cutoff_time", cutoff.Format(time.RFC3339)),
	)

	staleTasks, err := h.healthSvc.FindStaleTasks(ctx, h.controllerID, cutoff)
	if err != nil {
		logr.Error(ctx, "Stale task detection failed",
			"cutoff_time", cutoff.Format(time.RFC3339),
			"err", err,
		)
		span.SetStatus(codes.Error, "stale task detection failed")
		span.RecordError(err)
		return
	}
	staleTaskCount := len(staleTasks)
	span.AddEvent("stale_tasks_found", trace.WithAttributes(
		attribute.Int("count", staleTaskCount),
	))

	for _, t := range staleTasks {
		ctxLogr := logger.NewLoggerContext(logr)
		ctxLogr.Add("task_id", t.TaskID(), "job_id", t.JobID())
		ctxLogr.Warn(ctx, "Task detected as stale")
		span.SetAttributes(
			attribute.String("task_id", t.TaskID().String()),
			attribute.String("job_id", t.JobID().String()),
		)

		staleEvt := scanning.NewTaskStaleEvent(t.JobID(), t.TaskID(), scanning.StallReasonNoProgress, now)
		if err := h.stateHandler.HandleTaskStale(ctx, staleEvt); err != nil {
			ctxLogr.Error(ctx, "Task state transition to stale failed",
				"stall_reason", scanning.StallReasonNoProgress,
				"err", err,
			)
			span.SetStatus(codes.Error, "task state transition failed")
			span.RecordError(err)
			continue // Skip event publishing on state transition failure
		}

		ctxLogr.Info(ctx, "Task marked stale")
		span.AddEvent("task_marked_stale")
		if err := h.eventPublisher.PublishDomainEvent(ctx, staleEvt, events.WithKey(t.JobID().String())); err != nil {
			ctxLogr.Error(ctx, "Stale task event publication failed", "err", err)
			span.SetStatus(codes.Error, "event publication failed")
			span.RecordError(err)
			continue
		}

		ctxLogr.Info(ctx, "Stale task event published with job key")
		span.AddEvent("task_stale_processing_completed")
	}

	span.AddEvent("stale_task_check_completed", trace.WithAttributes(
		attribute.Int("processed_count", staleTaskCount),
	))
	span.SetStatus(codes.Ok, "stale task check completed successfully")
}

// HandleHeartbeat processes an incoming task heartbeat event by caching the current
// timestamp for the task. The cached heartbeats are periodically flushed to storage
// by the background goroutine.
func (h *taskHealthSupervisor) HandleHeartbeat(ctx context.Context, evt scanning.TaskHeartbeatEvent) {
	_, span := h.tracer.Start(ctx, "heartbeat_monitor.scanning.handle_heartbeat",
		trace.WithAttributes(
			attribute.String("controller_id", h.controllerID),
			attribute.String("task_id", evt.TaskID.String()),
			attribute.String("timestamp", evt.OccurredAt().Format(time.RFC3339)),
		))
	defer span.End()

	now := h.timeProvider.Now()
	h.mu.Lock()
	h.heartbeatCache[evt.TaskID] = now
	h.mu.Unlock()

	span.AddEvent("heartbeat_recorded", trace.WithAttributes(
		attribute.String("timestamp", now.UTC().Format(time.RFC3339)),
	))

	span.AddEvent("heartbeat_received")
	span.SetStatus(codes.Ok, "heartbeat received")
}

// Stop gracefully shuts down the TaskHealthSupervisor by canceling its background
// goroutines. This allows any in-progress operations to complete and ensures a
// final heartbeat flush is performed.
func (h *taskHealthSupervisor) Stop() {
	logger := h.logger.With("operation", "stop")
	ctx, span := h.tracer.Start(context.Background(), "heartbeat_monitor.scanning.stop")
	defer span.End()

	if h.cancel != nil {
		h.cancel(errors.New("heartbeat monitor stopped"))
	}

	span.AddEvent("heartbeat_monitor_stopped")
	logger.Info(ctx, "Heartbeat monitor stopped")
}
