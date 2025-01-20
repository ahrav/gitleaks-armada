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
// It manages job state transitions, task distribution, and provides high-level operations
// for monitoring job execution across the system. The service abstracts the underlying
// implementation details to provide a clean interface for job management.
type ScanJobService interface {
	// CreateJob creates a new job and returns it.
	CreateJob(ctx context.Context) (*domain.Job, error)

	// LinkTargets links targets to a job.
	LinkTargets(ctx context.Context, jobID uuid.UUID, targetIDs []uuid.UUID) error

	// OnTaskStarted transitions a job to an in-progress state when a new task begins.
	// This ensures proper job state tracking and enables task distribution.
	OnTaskStarted(ctx context.Context, jobID uuid.UUID, task *domain.Task) error

	// OnTaskProgressed updates a job's progress state when a task reports new progress.
	// This helps maintain accurate job status and allows for external monitoring.
	OnTaskProgressed(ctx context.Context, jobID uuid.UUID, task *domain.Task) error

	// MarkJobCompleted finalizes a job's execution state based on task outcomes.
	// A job is marked as completed only if all tasks succeeded, otherwise it is marked as failed.
	MarkJobCompleted(ctx context.Context, jobID uuid.UUID) error

	// GetJob retrieves the current state and task details for a specific scan job.
	// This enables external components to monitor job progress and handle failures.
	GetJob(ctx context.Context, jobID uuid.UUID) (*domain.Job, error)

	// ListJobs retrieves a paginated list of jobs filtered by their status.
	// This supports system-wide job monitoring and management capabilities.
	ListJobs(ctx context.Context, status []domain.JobStatus, limit, offset int) ([]*domain.Job, error)
}

// jobService implements ScanJobService by managing job state through a combination
// of in-memory caching and persistent storage.
type jobService struct {
	// TODO: consider using a proper cache.
	mu       sync.RWMutex
	jobCache map[uuid.UUID]*domain.Job // Caches active jobs to reduce database load

	jobRepo domain.JobRepository
	tracer  trace.Tracer
}

// NewJobService creates a new job service instance with the provided dependencies.
// It initializes an in-memory cache to optimize job state access.
func NewJobService(jobRepo domain.JobRepository, tracer trace.Tracer) *jobService {
	const defaultJobCacheSize = 64 // Reasonable default for most workloads
	return &jobService{
		jobCache: make(map[uuid.UUID]*domain.Job, defaultJobCacheSize),
		jobRepo:  jobRepo,
		tracer:   tracer,
	}
}

// CreateJob creates a new job and returns it.
func (svc *jobService) CreateJob(ctx context.Context) (*domain.Job, error) {
	ctx, span := svc.tracer.Start(ctx, "job_service.scanning.create_job")
	defer span.End()

	job := domain.NewJob()
	if err := svc.jobRepo.CreateJob(ctx, job); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to create job")
		return nil, err
	}
	span.AddEvent("job_created")
	span.SetStatus(codes.Ok, "job created successfully")

	svc.storeJobInCache(ctx, job)

	return job, nil
}

// LinkTargets associates targets with a job.
func (svc *jobService) LinkTargets(ctx context.Context, jobID uuid.UUID, targetIDs []uuid.UUID) error {
	ctx, span := svc.tracer.Start(ctx, "job_service.scanning.link_targets",
		trace.WithAttributes(
			attribute.String("job_id", jobID.String()),
			attribute.String("target_ids", fmt.Sprintf("%v", targetIDs)),
		))
	defer span.End()

	if err := svc.jobRepo.AssociateTargets(ctx, jobID, targetIDs); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to associate targets")
		return fmt.Errorf("failed to associate targets: %w", err)
	}
	span.AddEvent("targets_associated")
	span.SetStatus(codes.Ok, "targets associated successfully")

	return nil
}

// OnTaskStarted handles the start of a new task within a job.
func (s *jobService) OnTaskStarted(ctx context.Context, jobID uuid.UUID, task *domain.Task) error {
	ctx, span := s.tracer.Start(ctx, "job_service.scanning.on_task_started",
		trace.WithAttributes(
			attribute.String("job_id", jobID.String()),
			attribute.String("task_id", task.TaskID().String()),
		))
	defer span.End()

	job, err := s.loadJob(ctx, jobID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to load job")
		return fmt.Errorf("failed to load job: %w", err)
	}

	if err := job.AddTask(task); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to add task to job")
		return fmt.Errorf("failed to add task to job: %w", err)
	}
	span.AddEvent("task_added_to_job")

	if err := s.jobRepo.UpdateJob(ctx, job); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to update job status")
		return fmt.Errorf("failed to update job status: %w", err)
	}
	span.AddEvent("job_updated")
	span.SetStatus(codes.Ok, "job updated successfully")

	return nil
}

// OnTaskProgressed updates a job's progress state when a task reports new progress.
// This helps maintain accurate job status and allows for external monitoring.
func (s *jobService) OnTaskProgressed(ctx context.Context, jobID uuid.UUID, task *domain.Task) error {
	ctx, span := s.tracer.Start(ctx, "job_service.scanning.on_task_progressed",
		trace.WithAttributes(
			attribute.String("job_id", jobID.String()),
			attribute.String("task_id", task.TaskID().String()),
		))
	defer span.End()

	job, err := s.loadJob(ctx, jobID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to load job")
		return fmt.Errorf("failed to load job: %w", err)
	}

	if err := job.UpdateJobProgress(); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to update job progress")
		return fmt.Errorf("failed to update job progress: %w", err)
	}
	span.AddEvent("job_progress_updated")

	if err := s.jobRepo.UpdateJob(ctx, job); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to update job status")
		return fmt.Errorf("failed to update job status: %w", err)
	}
	span.AddEvent("job_updated")
	span.SetStatus(codes.Ok, "job updated successfully")

	return nil
}

// lookupJobInCache retrieves a job from the cache if it exists.
// Returns the job and a boolean indicating if it was found.
func (s *jobService) lookupJobInCache(ctx context.Context, jobID uuid.UUID) (*domain.Job, bool) {
	_, span := s.tracer.Start(ctx, "job_service.scanning.lookup_job_cache")
	defer span.End()

	s.mu.RLock()
	job, exists := s.jobCache[jobID]
	s.mu.RUnlock()
	span.AddEvent("job_cached", trace.WithAttributes(attribute.Bool("exists", exists)))

	return job, exists
}

// storeJobInCache stores a job in the cache.
func (s *jobService) storeJobInCache(ctx context.Context, job *domain.Job) {
	_, span := s.tracer.Start(ctx, "job_service.scanning.store_job_in_cache")
	defer span.End()

	s.mu.Lock()
	s.jobCache[job.JobID()] = job
	s.mu.Unlock()
	span.AddEvent("job_cached")
}

// loadJob retrieves a job from persistent storage and caches it for future access.
// This helps optimize subsequent operations on the same job.
func (s *jobService) loadJob(ctx context.Context, jobID uuid.UUID) (*domain.Job, error) {
	ctx, span := s.tracer.Start(ctx, "job_service.scanning.load_job",
		trace.WithAttributes(
			attribute.String("job_id", jobID.String()),
		))
	defer span.End()

	if job, exists := s.lookupJobInCache(ctx, jobID); exists {
		span.AddEvent("job_cached")
		return job, nil
	}

	job, err := s.jobRepo.GetJob(ctx, jobID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to get job")
		return nil, err
	}
	span.AddEvent("job_retrieved")

	s.storeJobInCache(ctx, job)
	span.AddEvent("job_cached")

	return job, nil
}

// MarkJobCompleted is a no-op implementation for now
func (s *jobService) MarkJobCompleted(ctx context.Context, jobID uuid.UUID) error {
	return nil
}

// GetJob is a no-op implementation for now
func (s *jobService) GetJob(ctx context.Context, jobID uuid.UUID) (*domain.Job, error) {
	return nil, nil
}

// ListJobs is a no-op implementation for now
func (s *jobService) ListJobs(ctx context.Context, status []domain.JobStatus, limit, offset int) ([]*domain.Job, error) {
	return nil, nil
}
