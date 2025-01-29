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
	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
)

// ScanJobCoordinator provides the primary interface for managing scan operations across the system.
// We need this coordination layer to:
// - Ensure consistency between distributed scanning tasks and their parent jobs
// - Provide reliable progress tracking for long-running scan operations
// - Handle failure scenarios and state transitions consistently
// - Optimize performance through strategic caching while maintaining data consistency
type ScanJobCoordinator interface {
	// ---------------------------
	// Job-level operations
	// ---------------------------

	// CreateJob initializes a new scanning operation in the system
	CreateJob(ctx context.Context) (*domain.Job, error)

	// LinkTargets associates scan targets with a job, enabling parallel processing
	// of multiple repositories or code bases within a single scanning operation
	LinkTargets(ctx context.Context, jobID uuid.UUID, targetIDs []uuid.UUID) error

	// ---------------------------
	// Task-level operations
	// ---------------------------
	// StartTask begins a new scanning task and updates job metrics accordingly.
	// This is crucial for tracking progress and ensuring all targets are processed.
	StartTask(ctx context.Context, jobID, taskID uuid.UUID, resourceURI string) (*domain.Task, error)

	// UpdateTaskProgress handles incremental updates from running scanners.
	// Updates are cached in memory and periodically persisted to reduce database load
	// while maintaining reasonable consistency guarantees.
	UpdateTaskProgress(ctx context.Context, progress domain.Progress) (*domain.Task, error)

	// CompleteTask marks a task as successful and updates job metrics.
	// This triggers potential job completion checks if all tasks are finished.
	CompleteTask(ctx context.Context, jobID, taskID uuid.UUID) (*domain.Task, error)

	// FailTask handles task failure scenarios, updating job state appropriately
	// to ensure accurate status reporting and potential retry mechanisms.
	FailTask(ctx context.Context, jobID, taskID uuid.UUID) (*domain.Task, error)

	// MarkTaskStale flags a task that has become unresponsive or stopped reporting progress.
	// This enables automated detection and recovery of failed tasks that require intervention.
	MarkTaskStale(ctx context.Context, jobID, taskID uuid.UUID, reason domain.StallReason) (*domain.Task, error)

	// GetTaskSourceType retrieves the source type of a task.
	// This is needed for task resume operations.
	GetTaskSourceType(ctx context.Context, taskID uuid.UUID) (shared.SourceType, error)

	// UpdateHeartbeats updates the last_heartbeat_at timestamp for a list of tasks.
	UpdateHeartbeats(ctx context.Context, heartbeats map[uuid.UUID]time.Time) (int64, error)

	// FindStaleTasks retrieves tasks that have not sent a heartbeat since the given cutoff time.
	FindStaleTasks(ctx context.Context, cutoff time.Time) ([]*domain.Task, error)

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

// scanJobCoordinator implements ScanJobCoordinator using a hybrid approach of
// in-memory caching and persistent storage to balance performance with reliability.
type scanJobCoordinator struct {
	mu        sync.RWMutex
	taskCache map[uuid.UUID]*domain.Task // Caches active tasks to reduce database load

	jobRepo  domain.JobRepository
	taskRepo domain.TaskRepository

	// TODO: Revist the idea of a persistence interval.

	tracer trace.Tracer
}

// NewScanJobCoordinator initializes the coordination system with configured thresholds
// for caching and persistence to optimize performance under expected load.
func NewScanJobCoordinator(
	jobRepo domain.JobRepository,
	taskRepo domain.TaskRepository,
	tracer trace.Tracer,
) *scanJobCoordinator {
	// TODO: If we want to use a cache, it will need to be a distributed cache.
	// Cache sizes are tuned for typical concurrent workloads while preventing excessive memory usage
	const defaultTaskCacheSize = 1000 // Accommodates tasks across active jobs
	return &scanJobCoordinator{
		taskCache: make(map[uuid.UUID]*domain.Task, defaultTaskCacheSize),
		jobRepo:   jobRepo,
		taskRepo:  taskRepo,
		tracer:    tracer,
	}
}

// CreateJob initializes a new scanning operation and ensures it's immediately
// available in both the cache and persistent storage.
func (svc *scanJobCoordinator) CreateJob(ctx context.Context) (*domain.Job, error) {
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

	return job, nil
}

// LinkTargets establishes the scope of a scanning job by connecting it with specific targets.
// This relationship is crucial for tracking progress and ensuring complete coverage.
func (svc *scanJobCoordinator) LinkTargets(ctx context.Context, jobID uuid.UUID, targetIDs []uuid.UUID) error {
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

// loadTask retrieves a task using a cache-first strategy to minimize database access
// during high-frequency progress updates.
func (s *scanJobCoordinator) loadTask(ctx context.Context, taskID uuid.UUID) (*domain.Task, error) {
	ctx, span := s.tracer.Start(ctx, "job_service.scanning.load_task")
	defer span.End()

	// if task, exists := s.lookupTaskInCache(ctx, taskID); exists {
	// 	span.AddEvent("task_loaded_from_cache")
	// 	return task, nil
	// }

	task, err := s.taskRepo.GetTask(ctx, taskID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to get task")
		return nil, err
	}

	// s.mu.Lock()
	// s.taskCache[taskID] = task
	// s.mu.Unlock()
	// span.AddEvent("task_cached")

	span.AddEvent("task_loaded")
	span.SetStatus(codes.Ok, "task loaded")

	return task, nil
}

// lookupTaskInCache provides fast access to cached tasks, reducing database load
// during frequent task status checks and updates.
// func (s *scanJobCoordinator) lookupTaskInCache(ctx context.Context, taskID uuid.UUID) (*domain.Task, bool) {
// 	_, span := s.tracer.Start(ctx, "job_service.scanning.lookup_task_cache")
// 	defer span.End()

// 	s.mu.RLock()
// 	task, exists := s.taskCache[taskID]
// 	s.mu.RUnlock()

// 	span.AddEvent("cache_lookup_complete", trace.WithAttributes(
// 		attribute.Bool("found_in_cache", exists),
// 	))
// 	return task, exists
// }

// StartTask initializes a new scanning task and updates the parent job's metrics.
// The task is cached immediately to optimize subsequent progress updates.
func (s *scanJobCoordinator) StartTask(ctx context.Context, jobID, taskID uuid.UUID, resourceURI string) (*domain.Task, error) {
	ctx, span := s.tracer.Start(ctx, "job_service.scanning.start_task",
		trace.WithAttributes(
			attribute.String("job_id", jobID.String()),
			attribute.String("task_id", taskID.String()),
		))
	defer span.End()

	// s.mu.RLock()
	// if _, found := s.taskCache[taskID]; found {
	// 	s.mu.RUnlock()
	// 	span.AddEvent("task_already_exists")
	// 	span.SetStatus(codes.Error, "task already exists")
	// 	return nil, fmt.Errorf("task %s already exists", taskID)
	// }
	// s.mu.RUnlock()

	newTask := domain.NewScanTask(jobID, taskID, resourceURI)
	if err := s.taskRepo.CreateTask(ctx, newTask); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to create task in repo")
		return nil, fmt.Errorf("creating task: %w", err)
	}
	span.AddEvent("task_created_in_repo")

	// s.mu.Lock()
	// s.taskCache[taskID] = newTask
	// s.mu.Unlock()
	// span.AddEvent("task_cached")

	span.SetStatus(codes.Ok, "task started successfully")

	return newTask, nil
}

// UpdateTaskProgress handles incremental scan progress updates while managing database load.
// Updates are cached and only persisted based on configured intervals to prevent database bottlenecks
// during high-frequency progress reporting.
func (s *scanJobCoordinator) UpdateTaskProgress(ctx context.Context, progress domain.Progress) (*domain.Task, error) {
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
	span.SetAttributes(
		attribute.String("task_status", string(task.Status())),
	)

	if err := task.ApplyProgress(progress); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to apply progress update")
		return nil, fmt.Errorf("apply progress: %w", err)
	}
	span.AddEvent("progress_applied",
		trace.WithAttributes(
			attribute.String("task_status", string(task.Status())),
		),
	)

	if err := s.taskRepo.UpdateTask(ctx, task); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to persist updated task")
		return nil, fmt.Errorf("persist task: %w", err)
	}
	span.AddEvent("task_persisted_due_to_interval")

	span.AddEvent("task_progress_updated")
	span.SetStatus(codes.Ok, "task progress updated successfully")

	return task, nil
}

// CompleteTask finalizes a successful task execution and updates the parent job's state.
// This may trigger job completion if all tasks are finished.
func (s *scanJobCoordinator) CompleteTask(ctx context.Context, jobID, taskID uuid.UUID) (*domain.Task, error) {
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

	if err := task.Complete(); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to complete task")
		return nil, fmt.Errorf("complete task: %w", err)
	}
	span.AddEvent("task_completed")

	if err := s.taskRepo.UpdateTask(ctx, task); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to persist completed task")
		return nil, fmt.Errorf("persist task: %w", err)
	}
	span.AddEvent("task_completed_persisted")
	span.SetStatus(codes.Ok, "task completed successfully")

	return task, nil
}

// FailTask handles task failure scenarios and updates the parent job accordingly.
// This information is crucial for error reporting and potential retry mechanisms.
func (s *scanJobCoordinator) FailTask(ctx context.Context, jobID, taskID uuid.UUID) (*domain.Task, error) {
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

	if err := task.Fail(); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to fail task")
		return nil, fmt.Errorf("fail task: %w", err)
	}
	span.AddEvent("task_failed")

	if err := s.taskRepo.UpdateTask(ctx, task); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to persist failed task")
		return nil, fmt.Errorf("persist task: %w", err)
	}
	span.AddEvent("task_failed_persisted")
	span.SetStatus(codes.Ok, "task failed successfully")

	return task, nil
}

// MarkTaskStale flags a task that has become unresponsive or stopped reporting progress.
// This enables automated detection and recovery of failed tasks that require intervention.
func (s *scanJobCoordinator) MarkTaskStale(ctx context.Context, jobID, taskID uuid.UUID, reason domain.StallReason) (*domain.Task, error) {
	ctx, span := s.tracer.Start(ctx, "job_service.scanning.mark_task_stale",
		trace.WithAttributes(
			attribute.String("job_id", jobID.String()),
			attribute.String("task_id", taskID.String()),
			attribute.String("reason", string(reason)),
		))
	defer span.End()

	task, err := s.loadTask(ctx, taskID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to load task")
		return nil, fmt.Errorf("load task: %w", err)
	}

	if err := task.MarkStale(&reason); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "job coordinator failed to mark task as stale")
		return nil, fmt.Errorf("job coordinator failed to mark task as stale: %w", err)
	}
	span.AddEvent("task_marked_as_stale")

	if err := s.taskRepo.UpdateTask(ctx, task); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to persist stale task")
		return nil, fmt.Errorf("persist task: %w", err)
	}
	span.AddEvent("task_stale_persisted")
	span.SetStatus(codes.Ok, "task marked as stale successfully")

	return task, nil
}

// GetTask retrieves a task using cache-first strategy to minimize database access.
func (s *scanJobCoordinator) GetTask(ctx context.Context, taskID uuid.UUID) (*domain.Task, error) {
	ctx, span := s.tracer.Start(ctx, "job_service.scanning.get_task",
		trace.WithAttributes(
			attribute.String("task_id", taskID.String()),
		))
	defer span.End()

	task, err := s.loadTask(ctx, taskID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to get task")
		return nil, fmt.Errorf("get task: %w", err)
	}

	span.AddEvent("task_retrieved")
	span.SetStatus(codes.Ok, "task retrieved successfully")
	return task, nil
}

// GetTaskSourceType retrieves the source type of a task using cache-first strategy.
func (s *scanJobCoordinator) GetTaskSourceType(ctx context.Context, taskID uuid.UUID) (shared.SourceType, error) {
	ctx, span := s.tracer.Start(ctx, "job_service.scanning.get_task_source_type",
		trace.WithAttributes(
			attribute.String("task_id", taskID.String()),
		))
	defer span.End()

	sourceType, err := s.taskRepo.GetTaskSourceType(ctx, taskID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to get task source type")
		return "", fmt.Errorf("get task source type: %w", err)
	}

	span.AddEvent("task_source_type_retrieved")
	span.SetStatus(codes.Ok, "task source type retrieved successfully")
	return sourceType, nil
}

// UpdateHeartbeats updates the last_heartbeat_at timestamp for a list of tasks.
func (s *scanJobCoordinator) UpdateHeartbeats(ctx context.Context, heartbeats map[uuid.UUID]time.Time) (int64, error) {
	ctx, span := s.tracer.Start(ctx, "job_service.scanning.update_heartbeats",
		trace.WithAttributes(
			attribute.Int("num_heartbeats", len(heartbeats)),
		))
	defer span.End()

	updatedTasks, err := s.taskRepo.BatchUpdateHeartbeats(ctx, heartbeats)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to update heartbeats")
		return 0, fmt.Errorf("update heartbeats: %w", err)
	}

	span.AddEvent("heartbeats_updated", trace.WithAttributes(
		attribute.Int("num_updated_tasks", int(updatedTasks)),
	))
	span.SetStatus(codes.Ok, "heartbeats updated successfully")

	return updatedTasks, nil
}

// FindStaleTasks finds tasks that have not sent a heartbeat within the staleness threshold.
func (s *scanJobCoordinator) FindStaleTasks(ctx context.Context, cutoff time.Time) ([]*domain.Task, error) {
	ctx, span := s.tracer.Start(ctx, "job_service.scanning.find_stale_tasks",
		trace.WithAttributes(
			attribute.String("cutoff", cutoff.Format(time.RFC3339)),
		))
	defer span.End()

	staleTasks, err := s.taskRepo.FindStaleTasks(ctx, cutoff)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to find stale tasks")
		return nil, fmt.Errorf("find stale tasks: %w", err)
	}

	span.AddEvent("stale_tasks_found", trace.WithAttributes(
		attribute.Int("num_stale_tasks", len(staleTasks)),
	))
	span.SetStatus(codes.Ok, "stale tasks found successfully")

	return staleTasks, nil
}
