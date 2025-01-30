package scanning

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// TaskHealthMonitor defines the core health monitoring capabilities.
type TaskHealthMonitor interface {
	// Start starts the health monitor.
	Start(ctx context.Context)
	// HandleHeartbeat handles a heartbeat event.
	HandleHeartbeat(ctx context.Context, evt TaskHeartbeatEvent)
	// Stop stops the health monitor.
	Stop()
}

// TaskHealthService defines the persistence operations for health monitoring.
type TaskHealthService interface {
	// UpdateHeartbeats updates the last_heartbeat_at timestamp for a list of tasks.
	UpdateHeartbeats(ctx context.Context, heartbeats map[uuid.UUID]time.Time) (int64, error)

	// FindStaleTasks retrieves tasks that have not sent a heartbeat since the given cutoff time.
	FindStaleTasks(ctx context.Context, cutoff time.Time) ([]*Task, error)
}

// TaskStateHandler defines methods for handling task state changes,
// particularly when tasks become unresponsive or stop reporting progress.
type TaskStateHandler interface {
	// HandleTaskStale handles a task that has become unresponsive or stopped reporting progress.
	HandleTaskStale(ctx context.Context, evt TaskStaleEvent) error
}
