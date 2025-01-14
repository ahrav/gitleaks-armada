package scanning

import (
	"context"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
)

// ScanJobService coordinates the lifecycle of scan jobs and their associated tasks.
// It provides high-level operations for job management while abstracting the underlying
// implementation details of task distribution and state management.
// TODO: Add cleanup daemon to delete jobs. (requirements TBH)
type ScanJobService interface {
	// AddTasks associates one or more tasks with an existing job.
	// This enables building up complex scan jobs from multiple discrete tasks.
	AddTasks(ctx context.Context, job *scanning.ScanJob, tasks ...*scanning.Task) error

	// StartJob begins execution of a job's tasks.
	// This transitions the job to an in-progress state and initiates task distribution.
	StartJob(ctx context.Context, jobID uuid.UUID) error

	// MarkJobCompleted finalizes a job's execution state.
	// The job transitions to completed if all tasks succeeded, or failed if any were unsuccessful.
	MarkJobCompleted(ctx context.Context, jobID uuid.UUID) error

	// GetJob retrieves the current state of a scan job and its tasks.
	GetJob(ctx context.Context, jobID uuid.UUID) (*scanning.ScanJob, error)

	// ListJobs retrieves a paginated list of jobs filtered by status.
	// This enables monitoring and management of jobs across the system.
	ListJobs(ctx context.Context, status []scanning.JobStatus, limit, offset int) ([]*scanning.ScanJob, error)
}

// jobService implements the ScanJobService interface, providing concrete implementations
// for job lifecycle management operations.
type jobService struct {
	jobRepo scanning.JobRepository

	// TODO: Add logger and metrics
	tracer trace.Tracer
}

// NewJobService creates a new instance of the job service with required dependencies.
func NewJobService(jobRepo scanning.JobRepository, tracer trace.Tracer) *jobService {
	return &jobService{jobRepo: jobRepo, tracer: tracer}
}

// AddTasks associates one or more tasks with an existing job.
func (s *jobService) AddTasks(ctx context.Context, job *scanning.ScanJob, tasks ...*scanning.Task) error {
	return nil
}

// StartJob is a no-op implementation for now
func (s *jobService) StartJob(ctx context.Context, jobID uuid.UUID) error {
	return nil
}

// MarkJobCompleted is a no-op implementation for now
func (s *jobService) MarkJobCompleted(ctx context.Context, jobID uuid.UUID) error {
	return nil
}

// GetJob is a no-op implementation for now
func (s *jobService) GetJob(ctx context.Context, jobID uuid.UUID) (*scanning.ScanJob, error) {
	return nil, nil
}

// ListJobs is a no-op implementation for now
func (s *jobService) ListJobs(ctx context.Context, status []scanning.JobStatus, limit, offset int) ([]*scanning.ScanJob, error) {
	return nil, nil
}
