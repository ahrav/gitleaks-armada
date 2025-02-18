package scanning

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
)

// JobTaskService provides the primary interface for managing scan operations in our distributed
// scanning system. It manages the lifecycle and relationships between jobs and their constituent
// tasks, providing core abstractions for maintaining consistency, handling state transitions,
// and ensuring reliable execution. The service handles both job-level coordination and task
// lifecycle management while maintaining consistency between distributed components.
type JobTaskService interface {
	// ---------------------------
	// Job-level operations
	// ---------------------------

	// CreateJob initializes a new scanning operation in the system
	CreateJob(ctx context.Context) (*Job, error)

	// LinkTargets associates scan targets with a job, enabling parallel processing
	// of multiple repositories or code bases within a single scanning operation
	LinkTargets(ctx context.Context, jobID uuid.UUID, targetIDs []uuid.UUID) error

	// IncrementJobTotalTasks increments the total tasks count for a job.
	// This is used during the enumeration process to track the total number of tasks
	// that will be processed for a job.
	// Note: This is handled via increments because enumeration tasks are streamed
	// in batches and the total is unknown until all batches have been processed.
	IncrementJobTotalTasks(ctx context.Context, jobID uuid.UUID, amount int) error

	// ---------------------------
	// Task-level operations
	// ---------------------------

	// CreateTask creates a new scanning task.
	CreateTask(ctx context.Context, task *Task) error

	// StartTask begins a new scanning task.
	StartTask(ctx context.Context, taskID uuid.UUID, resourceURI string) error

	// UpdateTaskProgress handles incremental updates from running scanners.
	// Updates are cached in memory and periodically persisted to reduce database load
	// while maintaining reasonable consistency guarantees.
	UpdateTaskProgress(ctx context.Context, progress Progress) (*Task, error)

	// CompleteTask marks a task as successful.
	CompleteTask(ctx context.Context, taskID uuid.UUID) (*Task, error)

	// FailTask handles task failure scenarios.
	FailTask(ctx context.Context, taskID uuid.UUID) (*Task, error)

	// MarkTaskStale flags a task that has become unresponsive or stopped reporting progress.
	// This enables automated detection and recovery of failed tasks that require intervention.
	MarkTaskStale(ctx context.Context, taskID uuid.UUID, reason StallReason) (*Task, error)

	// GetTaskSourceType retrieves the source type of a task.
	// This is needed for task resume operations.
	GetTaskSourceType(ctx context.Context, taskID uuid.UUID) (shared.SourceType, error)

	// UpdateHeartbeats updates the last_heartbeat_at timestamp for a list of tasks.
	UpdateHeartbeats(ctx context.Context, heartbeats map[uuid.UUID]time.Time) (int64, error)

	// FindStaleTasks retrieves tasks that have not sent a heartbeat since the given cutoff time.
	FindStaleTasks(ctx context.Context, controllerID string, cutoff time.Time) ([]StaleTaskInfo, error)

	// // RecoverTask attempts to resume execution of a previously stalled task.
	// // It uses the last recorded checkpoint to restart the task from its last known good state.
	// RecoverTask(ctx context.Context, jobID, taskID uuid.UUID) error

	// // GetJob retrieves the current state and task details for a specific scan job.
	// // This enables external components to monitor job progress and handle failures.
	// GetJob(ctx context.Context, jobID uuid.UUID) (*domain.Job, error)

	// // ListJobs retrieves a paginated list of jobs filtered by their status.
	// // This supports system-wide job monitoring and management capabilities.
	// ListJobs(ctx context.Context, status []domain.JobStatus, limit, offset int) ([]*domain.Job, error)
}
