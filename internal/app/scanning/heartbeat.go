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

type Monitor interface {
	// MarkTaskStale flags a task that has become unresponsive or stopped reporting progress.
	// This enables automated detection and recovery of failed tasks that require intervention.
	MarkTaskStale(ctx context.Context, jobID, taskID uuid.UUID, reason domain.StallReason) (*domain.Task, error)

	// UpdateHeartbeats updates the last_heartbeat_at timestamp for a list of tasks.
	UpdateHeartbeats(ctx context.Context, heartbeats map[uuid.UUID]time.Time) (int64, error)

	// FindStaleTasks retrieves tasks that have not sent a heartbeat since the given cutoff time.
	FindStaleTasks(ctx context.Context, cutoff time.Time) ([]*domain.Task, error)
}

// HeartbeatMonitor tracks the last heartbeat of running tasks
// and periodically checks for tasks that have not sent a heartbeat within
// a given threshold (indicating potential staleness or failure).
type HeartbeatMonitor struct {
	coordinator Monitor

	flushInterval      time.Duration
	stalenessCheckIntv time.Duration
	stalenessThreshold time.Duration

	mu             sync.RWMutex
	heartbeatCache map[uuid.UUID]time.Time

	cancel context.CancelCauseFunc

	// timeProvider is used to get the current time.
	timeProvider timeProvider

	// tracer provides distributed tracing for request flows.
	tracer trace.Tracer
	// logger provides structured logging for operational visibility.
	logger *logger.Logger
}

// NewHeartbeatMonitor creates a new HeartbeatMonitor instance.
// The taskReader and stalenessHandler are used to handle tasks and mark them as stale.
// TODO: revisit thresholds.
func NewHeartbeatMonitor(
	coordinator Monitor,
	tracer trace.Tracer,
	logger *logger.Logger,
) *HeartbeatMonitor {
	return &HeartbeatMonitor{
		coordinator:        coordinator,
		flushInterval:      3 * time.Second,
		stalenessCheckIntv: 10 * time.Second,
		stalenessThreshold: 15 * time.Second,
		tracer:             tracer,
		logger:             logger,
		timeProvider:       realTimeProvider{},
		heartbeatCache:     make(map[uuid.UUID]time.Time),
	}
}

// Start launches a background goroutine that periodically checks
// for tasks that have not sent a heartbeat within `defaultThreshold`. If a task is found
// to be stale, this loop calls TaskStaller.MarkTaskStale(...) to mark the task as stale.
//
// The loop runs until the provided context is canceled, at which point the monitor
// stops checking for stale tasks.
func (h *HeartbeatMonitor) Start(ctx context.Context) {
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
				// final flush.
				h.flushHeartbeats(ctx)
				return
			}
		}
	}()
}

func (h *HeartbeatMonitor) flushHeartbeats(ctx context.Context) {
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

	if _, err := h.coordinator.UpdateHeartbeats(ctx, batch); err != nil {
		h.logger.Error(ctx, "Failed to batch update heartbeats", "err", err)
	} else {
		h.logger.Debug(ctx, "Flushed heartbeats", "count", len(batch))
	}
}

func (h *HeartbeatMonitor) checkForStaleTasks(ctx context.Context) {
	now := h.timeProvider.Now()
	cutoff := now.Add(-h.stalenessThreshold)

	staleTasks, err := h.coordinator.FindStaleTasks(ctx, cutoff)
	if err != nil {
		h.logger.Error(ctx, "Failed to find stale tasks", "err", err)
		return
	}

	for _, t := range staleTasks {
		h.logger.Warn(ctx, "Detected stale task", "task_id", t.TaskID())

		if _, err := h.coordinator.MarkTaskStale(
			ctx,
			t.JobID(),
			t.TaskID(),
			scanning.StallReasonNoProgress,
		); err != nil {
			h.logger.Error(ctx, "Failed to mark task stale", "task_id", t.TaskID(), "err", err)
		} else {
			h.logger.Info(ctx, "Task marked stale", "task_id", t.TaskID())
		}
	}
}

// checkForStaleTasks is an internal helper that scans the lastHeartbeatByTask
// map for tasks whose last heartbeat was older than (now - threshold).
// It marks each stale task by calling taskStaller.MarkTaskStale(...).
// func (h *HeartbeatMonitor) checkForStaleTasks(ctx context.Context, threshold time.Duration) {
// 	now := h.timeProvider.Now()
// 	ctx, span := h.tracer.Start(ctx, "heartbeat_monitor.scanning.check_for_stale_tasks",
// 		trace.WithAttributes(
// 			attribute.String("threshold", threshold.String()),
// 			attribute.String("now", now.Format(time.RFC3339)),
// 		))
// 	defer span.End()

// 	span.AddEvent("checking_for_stale_tasks")

// 	var potentiallyStaleTaskIDs []uuid.UUID

// 	h.mu.RLock()
// 	for taskID, lastBeat := range h.lastHeartbeatByTask {
// 		if now.Sub(lastBeat) > threshold {
// 			potentiallyStaleTaskIDs = append(potentiallyStaleTaskIDs, taskID)
// 		}
// 	}
// 	h.mu.RUnlock()

// 	span.AddEvent("potentially_stale_tasks_found", trace.WithAttributes(
// 		attribute.Int("count", len(potentiallyStaleTaskIDs)),
// 	))

// 	// For each potentially stale task, verify state and handle accordingly.
// 	for _, tID := range potentiallyStaleTaskIDs {
// 		task, err := h.taskReader.GetTask(ctx, tID)
// 		if err != nil {
// 			h.logger.Error(ctx, "HeartbeatMonitor: Failed to get task status", "task_id", tID, "error", err)
// 			continue
// 		}

// 		if task.IsInProgress() {
// 			h.logger.Warn(ctx, "HeartbeatMonitor: Detected stale task - failing", "task_id", tID)
// 			staleEvt := scanning.NewTaskStaleEvent(tID, tID, scanning.StallReasonNoProgress, h.timeProvider.Now())

// 			if err := h.stalenessHandler.HandleTaskStale(ctx, staleEvt); err != nil {
// 				h.logger.Error(ctx, "HeartbeatMonitor: Failed to mark task as stale", "task_id", tID, "error", err)
// 				span.RecordError(err)
// 				span.SetStatus(codes.Error, "failed to mark task as stale")
// 				continue
// 			}
// 			span.AddEvent("stale_task_marked", trace.WithAttributes(
// 				attribute.String("task_id", tID.String()),
// 			))
// 			h.logger.Info(ctx, "HeartbeatMonitor: Stale task marked", "task_id", tID)
// 		}

// 		// Clean up monitoring regardless of task state.
// 		// This is okay because we will re-add the task
// 		// when we receive a heartbeat.
// 		h.mu.Lock()
// 		delete(h.lastHeartbeatByTask, tID)
// 		h.mu.Unlock()
// 		span.AddEvent("stale_task_cleaned_up", trace.WithAttributes(
// 			attribute.String("task_id", tID.String()),
// 		))
// 	}
// 	span.AddEvent("stale_tasks_checked")
// 	span.SetStatus(codes.Ok, "stale tasks checked")
// }

// HandleHeartbeat processes incoming TaskHeartbeatEvent messages.
// It updates the last-seen heartbeat timestamp for the corresponding task.
func (h *HeartbeatMonitor) HandleHeartbeat(ctx context.Context, evt scanning.TaskHeartbeatEvent) {
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

// Stop the heartbeat monitor.
// TODO: revisit to determine if we have more cleanup to do.
func (h *HeartbeatMonitor) Stop() {
	if h.cancel != nil {
		h.cancel(errors.New("heartbeat monitor stopped"))
	}
}
