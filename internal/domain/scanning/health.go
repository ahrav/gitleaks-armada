// Package scanning provides domain types and interfaces for managing distributed scanning operations.
package scanning

import (
	"context"
	"time"

	"github.com/ahrav/gitleaks-armada/pkg/common/uuid"
)

// Health monitoring is a critical component of our distributed scanning system.
// It ensures tasks remain responsive and enables automatic detection and recovery
// of failed operations. The interfaces defined here establish the contract for
// monitoring task health through heartbeats, detecting stale tasks, and managing
// task state transitions when health issues are detected.

// TaskHealthMonitor manages the health and liveness of distributed scanning tasks.
// It provides heartbeat tracking and stale task detection to ensure reliable
// operation of the distributed scanning system. When tasks become unresponsive
// or fail silently, the monitor enables early detection and recovery.
type TaskHealthMonitor interface {
	// Start starts the health monitor.
	Start(ctx context.Context)
	// HandleHeartbeat handles a heartbeat event.
	HandleHeartbeat(ctx context.Context, evt TaskHeartbeatEvent)
	// Stop stops the health monitor.
	Stop()
}

// TaskHealthService defines the persistence operations needed for health monitoring.
// It abstracts the storage layer for task health data, allowing efficient tracking
// and querying of task heartbeats without coupling to specific storage implementations.
type TaskHealthService interface {
	// UpdateHeartbeats updates the last_heartbeat_at timestamp for a list of tasks.
	UpdateHeartbeats(ctx context.Context, heartbeats map[uuid.UUID]time.Time) (int64, error)

	// FindStaleTasks retrieves tasks that have not sent a heartbeat since the given cutoff time.
	FindStaleTasks(ctx context.Context, controllerID string, cutoff time.Time) ([]StaleTaskInfo, error)
}

// TaskStateHandler defines how the system reacts to task state changes,
// particularly when tasks become unresponsive. It separates state change
// detection from handling, enabling flexible recovery strategies and
// consistent system responses to task health issues.
type TaskStateHandler interface {
	// HandleTaskStale handles a task that has become unresponsive or stopped reporting progress.
	HandleTaskStale(ctx context.Context, evt TaskStaleEvent) error
}
