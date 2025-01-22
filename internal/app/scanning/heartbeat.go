package scanning

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

// TaskFailer is a reduced interface for the ExecutionTracker.
// It's used to fail tasks once a task is deemed stale.
type TaskFailer interface {
	// FailTask is used to fail a task once a task is deemed stale.
	FailTask(ctx context.Context, evt scanning.TaskFailedEvent) error
}

// HeartbeatMonitor tracks the last heartbeat of running tasks
// and periodically checks for tasks that have not sent a heartbeat within
// a given threshold (indicating potential staleness or failure).
type HeartbeatMonitor struct {
	// taskFailer is used to fail tasks once a task is deemed stale.
	taskFailer TaskFailer

	mu sync.RWMutex
	// lastHeartbeatByTask stores the most recent timestamp
	// at which a heartbeat was received for a given task ID.
	lastHeartbeatByTask map[uuid.UUID]time.Time

	// tracer provides distributed tracing for request flows.
	tracer trace.Tracer
	// logger provides structured logging for operational visibility.
	logger *logger.Logger
}

// NewHeartbeatMonitor creates a new HeartbeatMonitor instance.
// The taskFailer is used to fail tasks once a task is deemed stale.
func NewHeartbeatMonitor(
	taskFailer TaskFailer,
	tracer trace.Tracer,
	logger *logger.Logger,
) *HeartbeatMonitor {
	return &HeartbeatMonitor{
		taskFailer:          taskFailer,
		tracer:              tracer,
		logger:              logger,
		lastHeartbeatByTask: make(map[uuid.UUID]time.Time),
	}
}

// HandleHeartbeat processes incoming TaskHeartbeatEvent messages.
// It updates the last-seen heartbeat timestamp for the corresponding task.
func (h *HeartbeatMonitor) HandleHeartbeat(ctx context.Context, evt scanning.TaskHeartbeatEvent) {
	_, span := h.tracer.Start(ctx, "heartbeat_monitor.scanning.handle_heartbeat",
		trace.WithAttributes(
			attribute.String("task_id", evt.TaskID.String()),
			attribute.String("timestamp", evt.OccurredAt().Format(time.RFC3339)),
		))
	defer span.End()

	h.mu.Lock()
	defer h.mu.Unlock()

	// Record the time at which we received a heartbeat for this task.
	now := time.Now()
	h.lastHeartbeatByTask[evt.TaskID] = now
	span.AddEvent("heartbeat_recorded", trace.WithAttributes(
		attribute.String("timestamp", now.Format(time.RFC3339)),
	))

	span.AddEvent("heartbeat_received")
	span.SetStatus(codes.Ok, "heartbeat received")
}

// TODO: revisit this value.
const (
	stalenessLoopInterval = 30 * time.Second
	defaultThreshold      = 90 * time.Second
)

// Start launches a background goroutine that periodically checks
// for tasks that have not sent a heartbeat within `defaultThreshold`. If a task is found
// to be stale, this loop calls TaskFailer.FailTask(...) to fail the task.
//
// The loop runs until the provided context is canceled, at which point the monitor
// stops checking for stale tasks.
func (h *HeartbeatMonitor) Start(ctx context.Context) {
	ctx, span := h.tracer.Start(ctx, "heartbeat_monitor.scanning.start_staleness_loop",
		trace.WithAttributes(
			attribute.String("interval", stalenessLoopInterval.String()),
			attribute.String("threshold", defaultThreshold.String()),
		))
	defer span.End()

	span.AddEvent("staleness_loop_started")

	ticker := time.NewTicker(stalenessLoopInterval)
	go func() {
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return

			case <-ticker.C:
				h.checkForStaleTasks(ctx, defaultThreshold)
			}
		}
	}()
}

// checkForStaleTasks is an internal helper that scans the lastHeartbeatByTask
// map for tasks whose last heartbeat was older than (now - threshold).
// It fails each stale task by calling taskFailer.FailTask(...).
func (h *HeartbeatMonitor) checkForStaleTasks(ctx context.Context, threshold time.Duration) {
	now := time.Now()
	ctx, span := h.tracer.Start(ctx, "heartbeat_monitor.scanning.check_for_stale_tasks",
		trace.WithAttributes(
			attribute.String("threshold", threshold.String()),
			attribute.String("now", now.Format(time.RFC3339)),
		))
	defer span.End()

	span.AddEvent("checking_for_stale_tasks")

	// We'll collect the tasks we deem stale in a slice to avoid holding the mutex
	// while calling external methods.
	var staleTaskIDs []uuid.UUID

	h.mu.RLock()
	for taskID, lastBeat := range h.lastHeartbeatByTask {
		// If the last heartbeat is older than the threshold, mark the task stale.
		if now.Sub(lastBeat) > threshold {
			staleTaskIDs = append(staleTaskIDs, taskID)
		}
	}
	h.mu.RUnlock()
	span.AddEvent("stale_tasks_found", trace.WithAttributes(
		attribute.Int("count", len(staleTaskIDs)),
	))

	// For each stale task, fail the task in the ExecutionTracker.
	for _, tID := range staleTaskIDs {
		h.logger.Warn(ctx, "Detected stale task - failing", "task_id", tID)

		failEvt := scanning.NewTaskFailedEvent(tID, tID, "stale: no heartbeat within threshold")
		if err := h.taskFailer.FailTask(ctx, failEvt); err != nil {
			h.logger.Error(ctx, "Failed to mark task as stale", "task_id", tID, "error", err)
		} else {
			// Only remove the stale task from the map after we've successfully
			// failed it.
			h.mu.Lock()
			delete(h.lastHeartbeatByTask, tID)
			h.mu.Unlock()
			span.AddEvent("stale_task_failed", trace.WithAttributes(
				attribute.String("task_id", tID.String()),
			))
		}
	}
}
