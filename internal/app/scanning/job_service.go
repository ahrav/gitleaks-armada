package scanning

import (
	"context"
	"fmt"
	"sync"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	domain "github.com/ahrav/gitleaks-armada/internal/domain/scanning"
)

// ScanJobService coordinates the lifecycle of scan jobs and their associated tasks.
// It provides high-level operations for job management while abstracting the underlying
// implementation details of task distribution and state management.
// TODO: Add cleanup daemon to delete jobs. (requirements TBH)
type ScanJobService interface {
	// OnTaskStarted is called when a task is started.
	// This transitions the job to an in-progress state and initiates task distribution.
	OnTaskStarted(ctx context.Context, jobID uuid.UUID, task *domain.Task) error

	// MarkJobCompleted finalizes a job's execution state.
	// The job transitions to completed if all tasks succeeded, or failed if any were unsuccessful.
	MarkJobCompleted(ctx context.Context, jobID uuid.UUID) error

	// GetJob retrieves the current state of a scan job and its tasks.
	GetJob(ctx context.Context, jobID uuid.UUID) (*domain.ScanJob, error)

	// ListJobs retrieves a paginated list of jobs filtered by status.
	// This enables monitoring and management of jobs across the system.
	ListJobs(ctx context.Context, status []domain.JobStatus, limit, offset int) ([]*domain.ScanJob, error)
}

// jobService implements the ScanJobService interface, providing concrete implementations
// for job lifecycle management operations.
type jobService struct {
	mu       sync.RWMutex
	jobCache map[uuid.UUID]*domain.ScanJob

	jobRepo domain.JobRepository

	// TODO: Add logger and metrics
	tracer trace.Tracer
}

// NewJobService creates a new instance of the job service with required dependencies.
func NewJobService(jobRepo domain.JobRepository, tracer trace.Tracer) *jobService {
	const defaultJobCacheSize = 64
	return &jobService{
		jobCache: make(map[uuid.UUID]*domain.ScanJob, defaultJobCacheSize),
		jobRepo:  jobRepo,
		tracer:   tracer,
	}
}

// OnTaskStarted is called when a task is started.
// This transitions the job to an in-progress state and initiates task distribution.
func (s *jobService) OnTaskStarted(ctx context.Context, jobID uuid.UUID, task *domain.Task) error {
	ctx, span := s.tracer.Start(ctx, "job_service.scanning.on_task_started",
		trace.WithAttributes(
			attribute.String("job_id", jobID.String()),
			attribute.String("task_id", task.GetTaskID().String()),
		))
	defer span.End()

	s.mu.RLock()
	job, isCached := s.jobCache[jobID]
	s.mu.RUnlock()
	span.AddEvent("job_cached", trace.WithAttributes(attribute.Bool("exists", isCached)))

	if !isCached {
		var err error
		job, err = s.loadJob(ctx, jobID)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "failed to load job")
			return fmt.Errorf("failed to load job: %w", err)
		}
		span.AddEvent("job_loaded")
	}

	if err := job.AddTask(task); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to add task to job")
		return fmt.Errorf("failed to add task to job: %w", err)
	}
	span.AddEvent("task_added")

	if err := s.jobRepo.UpdateJob(ctx, job); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to update job status")
		return fmt.Errorf("failed to update job status: %w", err)
	}
	span.AddEvent("job_updated")
	span.SetStatus(codes.Ok, "job updated successfully")

	return nil
}

func (s *jobService) loadJob(ctx context.Context, jobID uuid.UUID) (*domain.ScanJob, error) {
	ctx, span := s.tracer.Start(ctx, "job_service.scanning.load_job",
		trace.WithAttributes(
			attribute.String("job_id", jobID.String()),
		))
	defer span.End()

	job, err := s.jobRepo.GetJob(ctx, jobID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to get job")
		return nil, err
	}
	span.AddEvent("job_retrieved")

	s.mu.Lock()
	s.jobCache[jobID] = job
	s.mu.Unlock()
	span.AddEvent("job_cached")

	return job, nil
}

// MarkJobCompleted is a no-op implementation for now
func (s *jobService) MarkJobCompleted(ctx context.Context, jobID uuid.UUID) error {
	return nil
}

// GetJob is a no-op implementation for now
func (s *jobService) GetJob(ctx context.Context, jobID uuid.UUID) (*domain.ScanJob, error) {
	return nil, nil
}

// ListJobs is a no-op implementation for now
func (s *jobService) ListJobs(ctx context.Context, status []domain.JobStatus, limit, offset int) ([]*domain.ScanJob, error) {
	return nil, nil
}
