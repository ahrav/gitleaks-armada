package scanning

import (
	"context"
	"fmt"
	"sync"
	"time"

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
	// ---------------------------
	// Job-level operations
	// ---------------------------

	// CreateJob creates a new job and returns it.
	CreateJob(ctx context.Context) (*domain.Job, error)

	// LinkTargets links targets to a job.
	LinkTargets(ctx context.Context, jobID uuid.UUID, targetIDs []uuid.UUID) error

	// ---------------------------
	// Task-level operations
	// ---------------------------

	// StartTask begins tracking a new task. It also updates the corresponding job
	// to reflect this new task (e.g., increment the job's total task count).
	StartTask(ctx context.Context, jobID, taskID uuid.UUID) (*domain.Task, error)

	// UpdateTaskProgress processes a status update from a running scanner task.
	// It maintains the task's execution state and enables monitoring of scan progress.
	// The update is cached in memory and periodically persisted based on configured intervals.
	// Returns the updated task, or nil if the task is not found.
	UpdateTaskProgress(ctx context.Context, progress domain.Progress) (*domain.Task, error)

	// CompleteTask marks a task as completed, then updates the associated job's
	// metrics if the status changed (e.g., increments the job's completed task count).
	CompleteTask(ctx context.Context, jobID, taskID uuid.UUID) (*domain.Task, error)

	// FailTask marks a task as failed, then updates the associated job's metrics if necessary.
	FailTask(ctx context.Context, jobID, taskID uuid.UUID) (*domain.Task, error)

	// // OnTaskStarted transitions a job to an in-progress state when a new task begins.
	// // This ensures proper job state tracking and enables task distribution.
	// OnTaskStarted(ctx context.Context, jobID uuid.UUID, task *domain.Task) error

	// // OnTaskUpdated handles any task state change, updating the job's progress
	// // and state accordingly. This method maintains job status consistency
	// // as tasks progress through their lifecycle.
	// OnTaskUpdated(ctx context.Context, jobID uuid.UUID, task *domain.Task) error

	// // MarkJobCompleted finalizes a job's execution state based on task outcomes.
	// // A job is marked as completed only if all tasks succeeded, otherwise it is marked as failed.
	// MarkJobCompleted(ctx context.Context, jobID uuid.UUID) error

	// // GetJob retrieves the current state and task details for a specific scan job.
	// // This enables external components to monitor job progress and handle failures.
	// GetJob(ctx context.Context, jobID uuid.UUID) (*domain.Job, error)

	// // ListJobs retrieves a paginated list of jobs filtered by their status.
	// // This supports system-wide job monitoring and management capabilities.
	// ListJobs(ctx context.Context, status []domain.JobStatus, limit, offset int) ([]*domain.Job, error)
}

// jobService implements ScanJobService by managing job state through a combination
// of in-memory caching and persistent storage.
type jobService struct {
	// TODO: consider using a proper cache.
	mu        sync.RWMutex
	jobCache  map[uuid.UUID]*domain.Job
	taskCache map[uuid.UUID]*domain.Task

	jobRepo  domain.JobRepository
	taskRepo domain.TaskRepository

	persistInterval  time.Duration // How often to persist task state to storage
	staleTaskTimeout time.Duration // Duration after which a task is considered stale

	tracer trace.Tracer
}

// NewJobService creates a new job service instance with the provided dependencies.
// It initializes an in-memory cache to optimize job state access.
func NewJobService(
	jobRepo domain.JobRepository,
	taskRepo domain.TaskRepository,
	persistInterval time.Duration,
	staleTimeout time.Duration,
	tracer trace.Tracer,
) *jobService {
	const (
		defaultJobCacheSize  = 64 // Reasonable default for most workloads
		defaultTaskCacheSize = 1000
	)
	return &jobService{
		jobCache:         make(map[uuid.UUID]*domain.Job, defaultJobCacheSize),
		taskCache:        make(map[uuid.UUID]*domain.Task, defaultTaskCacheSize),
		jobRepo:          jobRepo,
		taskRepo:         taskRepo,
		persistInterval:  persistInterval,
		staleTaskTimeout: staleTimeout,
		tracer:           tracer,
	}
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

// loadTask retrieves a task from storage and adds it to the cache.
func (s *jobService) loadTask(ctx context.Context, taskID uuid.UUID) (*domain.Task, error) {
	ctx, span := s.tracer.Start(ctx, "job_service.scanning.load_task")
	defer span.End()

	if task, exists := s.lookupTaskInCache(ctx, taskID); exists {
		span.AddEvent("task_loaded_from_cache")
		return task, nil
	}

	task, err := s.taskRepo.GetTask(ctx, taskID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to get task")
		return nil, err
	}

	s.mu.Lock()
	s.taskCache[taskID] = task
	s.mu.Unlock()
	span.AddEvent("task_cached")

	span.AddEvent("task_loaded")
	span.SetStatus(codes.Ok, "task loaded")

	return task, nil
}

// lookupTaskInCache retrieves a task from the cache if it exists.
// Returns the task and a boolean indicating if it was found.
func (s *jobService) lookupTaskInCache(ctx context.Context, taskID uuid.UUID) (*domain.Task, bool) {
	_, span := s.tracer.Start(ctx, "job_service.scanning.lookup_task_cache")
	defer span.End()

	s.mu.RLock()
	task, exists := s.taskCache[taskID]
	s.mu.RUnlock()

	span.AddEvent("cache_lookup_complete", trace.WithAttributes(
		attribute.Bool("found_in_cache", exists),
	))
	return task, exists
}

// StartTask begins tracking a new task. It also updates the job domain object
// to reflect that a new task has been started (increments metrics, etc.).
func (s *jobService) StartTask(ctx context.Context, jobID, taskID uuid.UUID) (*domain.Task, error) {
	ctx, span := s.tracer.Start(ctx, "job_service.scanning.start_task",
		trace.WithAttributes(
			attribute.String("job_id", jobID.String()),
			attribute.String("task_id", taskID.String()),
		))
	defer span.End()

	job, err := s.loadJob(ctx, jobID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to load job")
		return nil, fmt.Errorf("job %s not found: %w", jobID, err)
	}

	s.mu.RLock()
	if _, found := s.taskCache[taskID]; found {
		s.mu.RUnlock()
		span.AddEvent("task_already_exists")
		span.SetStatus(codes.Error, "task already exists")
		return nil, fmt.Errorf("task %s already exists", taskID)
	}
	s.mu.RUnlock()

	newTask := domain.NewScanTask(jobID, taskID)
	if err := s.taskRepo.CreateTask(ctx, newTask); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to create task in repo")
		return nil, fmt.Errorf("creating task: %w", err)
	}
	span.AddEvent("task_created_in_repo")

	if err := job.AddTask(newTask); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to add task to job domain")
		return nil, fmt.Errorf("adding task to job: %w", err)
	}

	if err := s.jobRepo.UpdateJob(ctx, job); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to update job in repo")
		return nil, fmt.Errorf("updating job: %w", err)
	}

	s.mu.Lock()
	s.taskCache[taskID] = newTask
	s.mu.Unlock()
	span.AddEvent("task_cached")

	span.SetStatus(codes.Ok, "task started successfully")

	return newTask, nil
}

// UpdateTaskProgress processes a status update from a running scanner task.
// It maintains the task's execution state and enables monitoring of scan progress.
// The update is cached in memory and periodically persisted based on configured intervals.
// Returns the updated task, or nil if the task is not found.
func (s *jobService) UpdateTaskProgress(ctx context.Context, progress domain.Progress) (*domain.Task, error) {
	ctx, span := s.tracer.Start(ctx, "job_service.scanning.update_task_progress",
		trace.WithAttributes(
			attribute.String("task_id", progress.TaskID().String()),
			attribute.Int64("sequence_num", progress.SequenceNum()),
		))
	defer span.End()

	task, err := s.loadTask(ctx, progress.TaskID())
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to load task")
		return nil, fmt.Errorf("load task: %w", err)
	}

	if err := task.ApplyProgress(progress); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to apply progress update")
		return nil, fmt.Errorf("apply progress: %w", err)
	}
	span.AddEvent("progress_applied")

	if time.Since(task.LastUpdateTime()) >= s.persistInterval {
		if err := s.taskRepo.UpdateTask(ctx, task); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "failed to persist updated task")
			return nil, fmt.Errorf("persist task: %w", err)
		}
		span.AddEvent("task_persisted_due_to_interval")

		job, err := s.loadJob(ctx, task.JobID())
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "failed to load job")
			return nil, fmt.Errorf("load job: %w", err)
		}

		if err := s.jobRepo.UpdateJob(ctx, job); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "failed to update job status")
			return nil, fmt.Errorf("failed to update job status: %w", err)
		}
		span.AddEvent("job_updated_after_task_persistence")
		span.SetStatus(codes.Ok, "job updated successfully")
	}
	span.AddEvent("task_progress_updated")
	span.SetStatus(codes.Ok, "task progress updated successfully")

	return task, nil
}

// CompleteTask marks a task as completed, then updates the associated job's metrics accordingly.
func (s *jobService) CompleteTask(ctx context.Context, jobID, taskID uuid.UUID) (*domain.Task, error) {
	ctx, span := s.tracer.Start(ctx, "job_service.scanning.complete_task",
		trace.WithAttributes(
			attribute.String("job_id", jobID.String()),
			attribute.String("task_id", taskID.String()),
		))
	defer span.End()

	task, err := s.loadTask(ctx, taskID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to load task")
		return nil, fmt.Errorf("load task: %w", err)
	}

	job, err := s.loadJob(ctx, jobID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to load job")
		return nil, fmt.Errorf("load job: %w", err)
	}

	if err := job.CompleteTask(taskID); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to complete task in job domain")
		return nil, fmt.Errorf("complete task: %w", err)
	}

	if err := s.taskRepo.UpdateTask(ctx, task); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to persist completed task")
		return nil, fmt.Errorf("persist task: %w", err)
	}

	if err := s.jobRepo.UpdateJob(ctx, job); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to update job status")
		return nil, fmt.Errorf("failed to update job status: %w", err)
	}
	span.AddEvent("job_updated")
	span.SetStatus(codes.Ok, "job updated successfully")

	return task, nil
}

// FailTask marks a task as failed, then updates the associated job's metrics.
func (s *jobService) FailTask(ctx context.Context, jobID, taskID uuid.UUID) (*domain.Task, error) {
	ctx, span := s.tracer.Start(ctx, "job_service.scanning.fail_task",
		trace.WithAttributes(
			attribute.String("job_id", jobID.String()),
			attribute.String("task_id", taskID.String()),
		))
	defer span.End()

	task, err := s.loadTask(ctx, taskID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to load task")
		return nil, fmt.Errorf("load task: %w", err)
	}

	job, err := s.loadJob(ctx, jobID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to load job")
		return nil, fmt.Errorf("load job: %w", err)
	}

	if err := job.FailTask(taskID); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to fail task in job domain")
		return nil, fmt.Errorf("fail task: %w", err)
	}
	span.AddEvent("task_failed_in_job_domain")

	if err := s.taskRepo.UpdateTask(ctx, task); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to persist failed task")
		return nil, fmt.Errorf("persist task: %w", err)
	}
	span.AddEvent("task_failed_persisted")

	if err := s.jobRepo.UpdateJob(ctx, job); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to update job status")
		return nil, fmt.Errorf("failed to update job status: %w", err)
	}
	span.AddEvent("job_updated_with_task_failure")

	span.SetStatus(codes.Ok, "task failed successfully")
	span.AddEvent("task_failed_successfully")

	return task, nil
}

// OnTaskStarted handles the start of a new task within a job.
// func (s *jobService) OnTaskStarted(ctx context.Context, jobID uuid.UUID, task *domain.Task) error {
// 	ctx, span := s.tracer.Start(ctx, "job_service.scanning.on_task_started",
// 		trace.WithAttributes(
// 			attribute.String("job_id", jobID.String()),
// 			attribute.String("task_id", task.TaskID().String()),
// 		))
// 	defer span.End()

// 	job, err := s.loadJob(ctx, jobID)
// 	if err != nil {
// 		span.RecordError(err)
// 		span.SetStatus(codes.Error, "failed to load job")
// 		return fmt.Errorf("failed to load job: %w", err)
// 	}

// 	if err := job.AddTask(task); err != nil {
// 		span.RecordError(err)
// 		span.SetStatus(codes.Error, "failed to add task to job")
// 		return fmt.Errorf("failed to add task to job: %w", err)
// 	}
// 	span.AddEvent("task_added_to_job")

// 	if err := s.jobRepo.UpdateJob(ctx, job); err != nil {
// 		span.RecordError(err)
// 		span.SetStatus(codes.Error, "failed to update job status")
// 		return fmt.Errorf("failed to update job status: %w", err)
// 	}
// 	span.AddEvent("job_updated")
// 	span.SetStatus(codes.Ok, "job updated successfully")

// 	return nil
// }

// OnTaskUpdated handles any task state change, updating the job's progress
// and state accordingly. This method maintains job status consistency
// as tasks progress through their lifecycle.
// func (s *jobService) OnTaskUpdated(ctx context.Context, jobID uuid.UUID, task *domain.Task) error {
// 	ctx, span := s.tracer.Start(ctx, "job_service.scanning.on_task_updated",
// 		trace.WithAttributes(
// 			attribute.String("job_id", jobID.String()),
// 			attribute.String("task_id", task.TaskID().String()),
// 			attribute.String("task_status", string(task.Status())),
// 		))
// 	defer span.End()

// 	job, err := s.loadJob(ctx, jobID)
// 	if err != nil {
// 		span.RecordError(err)
// 		span.SetStatus(codes.Error, "failed to load job")
// 		return fmt.Errorf("failed to load job: %w", err)
// 	}

// 	if err := job.UpdateTask(task); err != nil {
// 		span.RecordError(err)
// 		span.SetStatus(codes.Error, "failed to update job task")
// 		return fmt.Errorf("failed to update job task: %w", err)
// 	}
// 	span.AddEvent("job_task_updated")

// 	if err := s.jobRepo.UpdateJob(ctx, job); err != nil {
// 		span.RecordError(err)
// 		span.SetStatus(codes.Error, "failed to update job status")
// 		return fmt.Errorf("failed to update job status: %w", err)
// 	}
// 	span.AddEvent("job_updated")
// 	span.SetStatus(codes.Ok, "job updated successfully")

// 	return nil
// }

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
