// Package scanning provides domain types and interfaces for managing scan jobs and tasks.
// It defines the core abstractions needed to coordinate distributed scanning operations,
// track progress, and handle failure recovery.
package scanning

import "context"

// ScanJobService coordinates the lifecycle of scan jobs and their associated tasks.
// It provides high-level operations for job management while abstracting the underlying
// implementation details of task distribution and state management.
type ScanJobService interface {
	// CreateJob initializes a new scan job with the given ID.
	// The job starts in an initialized state to allow task configuration before execution.
	CreateJob(ctx context.Context, jobID string) (*ScanJob, error)

	// AddTasksToJob associates one or more tasks with an existing job.
	// This enables building up complex scan jobs from multiple discrete tasks.
	AddTasksToJob(ctx context.Context, jobID string, tasks ...*ScanTask) error

	// StartJob begins execution of a job's tasks.
	// This transitions the job to an in-progress state and initiates task distribution.
	StartJob(ctx context.Context, jobID string) error

	// MarkJobCompleted finalizes a job's execution state.
	// The job transitions to completed if all tasks succeeded, or failed if any were unsuccessful.
	MarkJobCompleted(ctx context.Context, jobID string) error

	// GetJob retrieves the current state of a scan job and its tasks.
	GetJob(ctx context.Context, jobID string) (*ScanJob, error)

	// ListJobs retrieves a paginated list of jobs filtered by status.
	// This enables monitoring and management of jobs across the system.
	ListJobs(ctx context.Context, status []JobStatus, limit, offset int) ([]*ScanJob, error)
}

// ScanTaskService manages the execution state of individual scan tasks.
// It handles task progress updates, failure detection, and recovery operations
// to ensure reliable task completion.
type ScanTaskService interface {
	// UpdateProgress processes a status update from an executing scanner.
	// This maintains task state and enables progress monitoring.
	UpdateProgress(ctx context.Context, progress ScanProgress) error

	// GetTask retrieves the current state of a specific task.
	GetTask(ctx context.Context, jobID, taskID string) (*ScanTask, error)

	// MarkTaskStale flags a task that has stopped reporting progress.
	// This enables detection of failed or hung tasks that require intervention.
	MarkTaskStale(ctx context.Context, jobID, taskID string, reason StallReason) error

	// RecoverTask attempts to resume execution of a stalled task.
	// This uses the last checkpoint to restart the task from its previous progress point.
	RecoverTask(ctx context.Context, jobID, taskID string) error
}

// JobRepository defines the persistence operations for scan jobs.
// It provides an abstraction layer over the storage mechanism used to maintain
// job state and history.
type JobRepository interface {
	// SaveJob persists the current state of a scan job.
	SaveJob(ctx context.Context, job *ScanJob) error

	// GetJob retrieves a job's complete state including associated tasks.
	GetJob(ctx context.Context, jobID string) (*ScanJob, error)

	// ListJobs retrieves a filtered, paginated list of jobs.
	ListJobs(ctx context.Context, status []JobStatus, limit, offset int) ([]*ScanJob, error)
}

// TaskRepository defines the persistence operations for scan tasks.
// It provides an abstraction layer over the storage mechanism used to maintain
// task state and progress data.
type TaskRepository interface {
	// SaveTask persists a new task's initial state.
	SaveTask(ctx context.Context, task *ScanTask) error

	// GetTask retrieves a task's current state.
	GetTask(ctx context.Context, jobID, taskID string) (*ScanTask, error)

	// UpdateTask persists changes to an existing task's state.
	UpdateTask(ctx context.Context, task *ScanTask) error
}
