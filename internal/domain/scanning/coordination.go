// Package scanning provides domain types and interfaces for managing distributed scanning operations.
package scanning

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
)

// Coordination in our distributed scanning system manages the lifecycle and relationships
// between jobs and their constituent tasks. It provides the core abstractions needed
// to maintain consistency, handle state transitions, and ensure reliable execution
// across the distributed system. The coordinator acts as the primary interface for
// job management, task execution, and system-wide state coordination.

// ScanJobCoordinator provides the primary interface for managing scan operations
// across the system. It handles both job-level coordination and task lifecycle
// management while maintaining consistency between distributed components.
type ScanJobCoordinator interface {
	// ---------------------------
	// Job-level operations
	// ---------------------------

	// CreateJob initializes a new scanning operation in the system
	CreateJob(ctx context.Context) (*Job, error)

	// LinkTargets associates scan targets with a job, enabling parallel processing
	// of multiple repositories or code bases within a single scanning operation
	LinkTargets(ctx context.Context, jobID uuid.UUID, targetIDs []uuid.UUID) error

	// ---------------------------
	// Task-level operations
	// ---------------------------
	// StartTask begins a new scanning task and updates job metrics accordingly.
	// This is crucial for tracking progress and ensuring all targets are processed.
	StartTask(ctx context.Context, jobID, taskID uuid.UUID, resourceURI string, controllerID string) (*Task, error)

	// UpdateTaskProgress handles incremental updates from running scanners.
	// Updates are cached in memory and periodically persisted to reduce database load
	// while maintaining reasonable consistency guarantees.
	UpdateTaskProgress(ctx context.Context, progress Progress) (*Task, error)

	// CompleteTask marks a task as successful and updates job metrics.
	// This triggers potential job completion checks if all tasks are finished.
	CompleteTask(ctx context.Context, jobID, taskID uuid.UUID) (*Task, error)

	// FailTask handles task failure scenarios, updating job state appropriately
	// to ensure accurate status reporting and potential retry mechanisms.
	FailTask(ctx context.Context, jobID, taskID uuid.UUID) (*Task, error)

	// MarkTaskStale flags a task that has become unresponsive or stopped reporting progress.
	// This enables automated detection and recovery of failed tasks that require intervention.
	MarkTaskStale(ctx context.Context, jobID, taskID uuid.UUID, reason StallReason) (*Task, error)

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
