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

// StalenessHandler represents a component that can handle stale task scenarios
// by marking tasks as stale in the system.
type StalenessHandler interface {
	MarkTaskStale(ctx context.Context, evt scanning.TaskStaleEvent) error
}

type timeProvider interface {
	Now() time.Time
}

// realTimeProvider is a real implementation of the timeProvider interface.
type realTimeProvider struct{}

// Now returns the current time.
func (realTimeProvider) Now() time.Time { return time.Now() }

// HeartbeatMonitor tracks the last heartbeat of running tasks
// and periodically checks for tasks that have not sent a heartbeat within
// a given threshold (indicating potential staleness or failure).
type HeartbeatMonitor struct {
	// stalenessHandler handles tasks that have been detected as stale
	stalenessHandler StalenessHandler

	mu sync.RWMutex
	// lastHeartbeatByTask stores the most recent timestamp
	// at which a heartbeat was received for a given task ID.
	lastHeartbeatByTask map[uuid.UUID]time.Time

	// timeProvider is used to get the current time.
	timeProvider timeProvider

	// tracer provides distributed tracing for request flows.
	tracer trace.Tracer
	// logger provides structured logging for operational visibility.
	logger *logger.Logger
}

// NewHeartbeatMonitor creates a new HeartbeatMonitor instance.
// The stalenessHandler is used to fail tasks once a task is deemed stale.
func NewHeartbeatMonitor(
	stalenessHandler StalenessHandler,
	tracer trace.Tracer,
	logger *logger.Logger,
) *HeartbeatMonitor {
	return &HeartbeatMonitor{
		stalenessHandler:    stalenessHandler,
		tracer:              tracer,
		logger:              logger,
		timeProvider:        realTimeProvider{},
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
	now := h.timeProvider.Now()
	h.lastHeartbeatByTask[evt.TaskID] = now
	span.AddEvent("heartbeat_recorded", trace.WithAttributes(
		attribute.String("timestamp", now.Format(time.RFC3339)),
	))

	span.AddEvent("heartbeat_received")
	span.SetStatus(codes.Ok, "heartbeat received")
}

// TODO: revisit this value.
const (
	stalenessLoopInterval = 10 * time.Second
	defaultThreshold      = 15 * time.Second
)

// Start launches a background goroutine that periodically checks
// for tasks that have not sent a heartbeat within `defaultThreshold`. If a task is found
// to be stale, this loop calls TaskStaller.MarkTaskStale(...) to mark the task as stale.
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
// It marks each stale task by calling taskStaller.MarkTaskStale(...).
func (h *HeartbeatMonitor) checkForStaleTasks(ctx context.Context, threshold time.Duration) {
	now := h.timeProvider.Now()
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

		staleEvt := scanning.NewTaskStaleEvent(tID, tID, scanning.StallReasonNoProgress, h.timeProvider.Now())
		if err := h.stalenessHandler.MarkTaskStale(ctx, staleEvt); err != nil {
			h.logger.Error(ctx, "Failed to mark task as stale", "task_id", tID, "error", err)
		} else {
			// Only remove the stale task from the map after we've successfully
			// marked it as stale.
			h.mu.Lock()
			delete(h.lastHeartbeatByTask, tID)
			h.mu.Unlock()
			span.AddEvent("stale_task_marked", trace.WithAttributes(
				attribute.String("task_id", tID.String()),
			))
		}
	}
}
