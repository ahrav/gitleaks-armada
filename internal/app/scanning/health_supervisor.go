package scanning

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	domain "github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

type timeProvider interface {
	Now() time.Time
}

// realTimeProvider is a real implementation of the timeProvider interface.
type realTimeProvider struct{}

// Now returns the current time.
func (realTimeProvider) Now() time.Time { return time.Now() }

type TaskHealthService interface {
	// UpdateHeartbeats updates the last_heartbeat_at timestamp for a list of tasks.
	UpdateHeartbeats(ctx context.Context, heartbeats map[uuid.UUID]time.Time) (int64, error)

	// FindStaleTasks retrieves tasks that have not sent a heartbeat since the given cutoff time.
	FindStaleTasks(ctx context.Context, cutoff time.Time) ([]*domain.Task, error)
}

// TaskStateHandler is an interface that defines methods for handling task state changes.
type TaskStateHandler interface {
	// HandleTaskStale handles a task that has become unresponsive or stopped reporting progress.
	HandleTaskStale(ctx context.Context, evt scanning.TaskStaleEvent) error
}

// TaskHealthSupervisor monitors task health by tracking heartbeats from running tasks.
// It provides two main functions:
//  1. Maintains an in-memory cache of task heartbeats that is periodically flushed to storage
//  2. Periodically checks for and marks tasks as stale if they haven't sent a heartbeat within
//     the configured threshold duration
type TaskHealthSupervisor struct {
	// healthSvc provides persistence and task state management operations
	healthSvc TaskHealthService
	// stateHandler handles task state changes
	stateHandler TaskStateHandler

	// flushInterval controls how often heartbeats are persisted to storage
	flushInterval time.Duration
	// stalenessCheckIntv controls frequency of stale task checks
	stalenessCheckIntv time.Duration
	// stalenessThreshold is the duration after which a task with no heartbeat is considered stale
	stalenessThreshold time.Duration

	mu             sync.RWMutex
	heartbeatCache map[uuid.UUID]time.Time

	// cancel allows graceful shutdown of background goroutines
	cancel context.CancelCauseFunc

	// timeProvider is used to get the current time
	timeProvider timeProvider

	// tracer provides distributed tracing for request flows
	tracer trace.Tracer
	// logger provides structured logging for operational visibility
	logger *logger.Logger
}

// NewTaskHealthSupervisor creates a new TaskHealthSupervisor instance that monitors task health
// by tracking heartbeats and detecting stale tasks. It uses the provided TaskHealthService
// for persistence and task state management.
func NewTaskHealthSupervisor(
	healthSvc TaskHealthService,
	stateHandler TaskStateHandler,
	tracer trace.Tracer,
	logger *logger.Logger,
) *TaskHealthSupervisor {
	return &TaskHealthSupervisor{
		healthSvc:          healthSvc,
		stateHandler:       stateHandler,
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
func (h *TaskHealthSupervisor) Start(ctx context.Context) {
	ctx, span := h.tracer.Start(ctx, "heartbeat_monitor.scanning.start_staleness_loop",
		trace.WithAttributes(
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
func (h *TaskHealthSupervisor) flushHeartbeats(ctx context.Context) {
	ctx, span := h.tracer.Start(ctx, "heartbeat_monitor.scanning.flush_heartbeats")
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

	span.AddEvent("heartbeats_flushed", trace.WithAttributes(
		attribute.Int("count", len(batch)),
	))

	if _, err := h.healthSvc.UpdateHeartbeats(ctx, batch); err != nil {
		h.logger.Error(ctx, "Failed to batch update heartbeats", "err", err)
		span.SetStatus(codes.Error, "failed to batch update heartbeats")
		span.RecordError(err)
		return
	}

	span.AddEvent("heartbeats_flushed")
	span.SetStatus(codes.Ok, "heartbeats flushed")
}

// checkForStaleTasks queries for tasks that haven't sent a heartbeat within the staleness
// threshold and marks them as stale. This enables automated detection and recovery of
// failed or unresponsive tasks.
func (h *TaskHealthSupervisor) checkForStaleTasks(ctx context.Context) {
	ctx, span := h.tracer.Start(ctx, "heartbeat_monitor.scanning.check_for_stale_tasks")
	defer span.End()

	now := h.timeProvider.Now()
	cutoff := now.Add(-h.stalenessThreshold)

	staleTasks, err := h.healthSvc.FindStaleTasks(ctx, cutoff)
	if err != nil {
		h.logger.Error(ctx, "Failed to find stale tasks", "err", err)
		span.SetStatus(codes.Error, "failed to find stale tasks")
		span.RecordError(err)
		return
	}
	span.AddEvent("stale_tasks_found", trace.WithAttributes(
		attribute.Int("count", len(staleTasks)),
	))

	for _, t := range staleTasks {
		h.logger.Warn(ctx, "Detected stale task", "task_id", t.TaskID())

		staleEvt := scanning.NewTaskStaleEvent(t.JobID(), t.TaskID(), scanning.StallReasonNoProgress, now)
		if err := h.stateHandler.HandleTaskStale(ctx, staleEvt); err != nil {
			h.logger.Error(ctx, "Failed to mark task stale", "task_id", t.TaskID(), "err", err)
			span.SetStatus(codes.Error, "failed to mark task stale")
			span.RecordError(err)
		} else {
			h.logger.Info(ctx, "Task marked stale", "task_id", t.TaskID())
			span.AddEvent("task_marked_stale", trace.WithAttributes(
				attribute.String("task_id", t.TaskID().String()),
			))
		}
	}

	span.AddEvent("stale_tasks_checked")
	span.SetStatus(codes.Ok, "stale tasks checked")
}

// HandleHeartbeat processes an incoming task heartbeat event by caching the current
// timestamp for the task. The cached heartbeats are periodically flushed to storage
// by the background goroutine.
func (h *TaskHealthSupervisor) HandleHeartbeat(ctx context.Context, evt scanning.TaskHeartbeatEvent) {
	_, span := h.tracer.Start(ctx, "heartbeat_monitor.scanning.handle_heartbeat",
		trace.WithAttributes(
			attribute.String("task_id", evt.TaskID.String()),
			attribute.String("timestamp", evt.OccurredAt().Format(time.RFC3339)),
		))
	defer span.End()

	now := h.timeProvider.Now()
	h.mu.Lock()
	h.heartbeatCache[evt.TaskID] = now
	h.mu.Unlock()

	span.AddEvent("heartbeat_recorded", trace.WithAttributes(
		attribute.String("timestamp", now.Format(time.RFC3339)),
	))

	span.AddEvent("heartbeat_received")
	span.SetStatus(codes.Ok, "heartbeat received")
}

// Stop gracefully shuts down the TaskHealthSupervisor by canceling its background
// goroutines. This allows any in-progress operations to complete and ensures a
// final heartbeat flush is performed.
func (h *TaskHealthSupervisor) Stop() {
	if h.cancel != nil {
		h.cancel(errors.New("heartbeat monitor stopped"))
	}
}
