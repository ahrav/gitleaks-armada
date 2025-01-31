// Package scanning provides domain types and interfaces for managing scan jobs and tasks.
// It defines the core abstractions needed to coordinate distributed scanning operations,
// track progress, and handle failure recovery.
package scanning

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
)

var (
	// ErrJobNotFound indicates the requested job was not found in storage
	ErrJobNotFound = errors.New("job not found")
	// ErrTaskNotFound indicates the requested task was not found in storage
	ErrTaskNotFound = errors.New("task not found")
	// ErrNoJobMetricsUpdated indicates that no job metrics were updated
	ErrNoJobMetricsUpdated = errors.New("no job metrics updated")
	// ErrNoJobMetricsFound indicates that no job metrics were found
	ErrNoJobMetricsFound = errors.New("no job metrics found")
)

// JobRepository defines the persistence operations for scan jobs.
// It provides an abstraction layer over the storage mechanism used to maintain
// job state and history.
type JobRepository interface {
	// CreateJob inserts a new job record, setting status and initial timestamps.
	CreateJob(ctx context.Context, job *Job) error

	// UpdateJob modifies an existing job's fields (status, end_time, etc.).
	UpdateJob(ctx context.Context, job *Job) error

	// AssociateTargets associates scan targets with a job.
	AssociateTargets(ctx context.Context, jobID uuid.UUID, targetIDs []uuid.UUID) error

	// GetJob retrieves a job's state (including associated tasks if needed).
	GetJob(ctx context.Context, jobID uuid.UUID) (*Job, error)

	// GetJobMetrics retrieves the metrics for a job.
	GetJobMetrics(ctx context.Context, jobID uuid.UUID) (*JobMetrics, error)

	// BulkUpdateJobMetrics updates metrics for multiple jobs in a single operation.
	BulkUpdateJobMetrics(ctx context.Context, updates map[uuid.UUID]*JobMetrics) (int64, error)
}

// TaskRepository defines the persistence operations for scan tasks.
// It provides an abstraction layer over the storage mechanism used to maintain
// task state and progress data.
type TaskRepository interface {
	// CreateTask persists a new task's initial state.
	CreateTask(ctx context.Context, task *Task, controllerID string) error

	// GetTask retrieves a task's current state.
	GetTask(ctx context.Context, taskID uuid.UUID) (*Task, error)

	// UpdateTask persists changes to an existing task's state.
	UpdateTask(ctx context.Context, task *Task) error

	// GetTaskSourceType retrieves the source type for a task from the core tasks table
	GetTaskSourceType(ctx context.Context, taskID uuid.UUID) (shared.SourceType, error)

	// FindStaleTasks retrieves tasks that have not sent a heartbeat since the given cutoff time
	// and belong to the specified controller.
	FindStaleTasks(ctx context.Context, controllerID string, cutoff time.Time) ([]StaleTaskInfo, error)

	// BatchUpdateHeartbeats updates each task's last_heartbeat_at timestamp.
	BatchUpdateHeartbeats(ctx context.Context, heartbeats map[uuid.UUID]time.Time) (int64, error)

	// ListTasksByJobAndStatus retrieves tasks associated with a job and matching a specific status.
	ListTasksByJobAndStatus(ctx context.Context, jobID uuid.UUID, status TaskStatus) ([]*Task, error)
}
