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

	// AssociateEnumeratedTargets links the provided scan targets to the specified job
	// and updates the job's total task count in a single atomic operation. This ensures
	// newly discovered targets are both associated for scanning and reflected in the
	// job's overall task tally, preserving data consistency if any step fails.
	AssociateEnumeratedTargets(ctx context.Context, jobID uuid.UUID, targetIDs []uuid.UUID) error

	// UpdateJobStatus updates the status of a job.
	UpdateJobStatus(ctx context.Context, job *Job, status JobStatus) error

	// CompleteEnumeration finalizes the enumeration phase of a job and transitions it
	// to the appropriate next state based on whether any tasks were created.
	CompleteEnumeration(ctx context.Context, job *Job) (*JobMetrics, error)

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
