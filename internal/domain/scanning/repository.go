// Package scanning provides domain types and interfaces for managing scan jobs and tasks.
// It defines the core abstractions needed to coordinate distributed scanning operations,
// track progress, and handle failure recovery.
package scanning

import (
	"context"

	"github.com/google/uuid"
)

// JobRepository defines the persistence operations for scan jobs.
// It provides an abstraction layer over the storage mechanism used to maintain
// job state and history.
type JobRepository interface {
	// CreateJob inserts a new job record, setting status and initial timestamps.
	CreateJob(ctx context.Context, job *ScanJob) error

	// UpdateJob modifies an existing job’s fields (status, end_time, etc.).
	UpdateJob(ctx context.Context, job *ScanJob) error

	// AssociateTargets associates scan targets with a job.
	AssociateTargets(ctx context.Context, jobID uuid.UUID, targetIDs []uuid.UUID) error

	// GetJob retrieves a job’s state (including associated tasks if needed).
	GetJob(ctx context.Context, jobID uuid.UUID) (*ScanJob, error)
}

// TaskRepository defines the persistence operations for scan tasks.
// It provides an abstraction layer over the storage mechanism used to maintain
// task state and progress data.
type TaskRepository interface {
	// CreateTask persists a new task’s initial state.
	CreateTask(ctx context.Context, task *Task) error

	// GetTask retrieves a task’s current state.
	GetTask(ctx context.Context, taskID uuid.UUID) (*Task, error)

	// UpdateTask persists changes to an existing task's state.
	UpdateTask(ctx context.Context, task *Task) error

	// ListTasksByJobAndStatus retrieves tasks associated with a job and matching a specific status.
	ListTasksByJobAndStatus(ctx context.Context, jobID uuid.UUID, status TaskStatus) ([]*Task, error)
}
