package scanning

import (
	"context"

	domain "github.com/ahrav/gitleaks-armada/internal/domain/scanning"
)

// ScanJobService coordinates the lifecycle of scan jobs and their associated tasks.
// It provides high-level operations for job management while abstracting the underlying
// implementation details of task distribution and state management.
type ScanJobService interface {
	// CreateJob initializes a new scan job with the given ID.
	// The job starts in an initialized state to allow task configuration before execution.
	CreateJob(ctx context.Context, jobID string) (*domain.ScanJob, error)

	// AddTasksToJob associates one or more tasks with an existing job.
	// This enables building up complex scan jobs from multiple discrete tasks.
	AddTasksToJob(ctx context.Context, jobID string, tasks ...*domain.ScanTask) error

	// StartJob begins execution of a job's tasks.
	// This transitions the job to an in-progress state and initiates task distribution.
	StartJob(ctx context.Context, jobID string) error

	// MarkJobCompleted finalizes a job's execution state.
	// The job transitions to completed if all tasks succeeded, or failed if any were unsuccessful.
	MarkJobCompleted(ctx context.Context, jobID string) error

	// GetJob retrieves the current state of a scan job and its tasks.
	GetJob(ctx context.Context, jobID string) (*domain.ScanJob, error)

	// ListJobs retrieves a paginated list of jobs filtered by status.
	// This enables monitoring and management of jobs across the system.
	ListJobs(ctx context.Context, status []domain.JobStatus, limit, offset int) ([]*domain.ScanJob, error)
}
