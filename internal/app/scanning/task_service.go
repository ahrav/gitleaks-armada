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

// ScanTaskService manages the lifecycle and state of individual scan tasks within the system.
// It provides a high-level interface for task operations while handling the underlying
// complexity of caching, persistence, and domain rules.
type ScanTaskService interface {
	// StartTask begins tracking a new task.
	StartTask(ctx context.Context, jobID, taskID uuid.UUID) (*domain.Task, error)

	// UpdateProgress processes a status update from a running scanner task.
	// It maintains the task's execution state and enables monitoring of scan progress.
	// The update is cached in memory and periodically persisted based on configured intervals.
	// Returns the updated task, or nil if the task is not found.
	UpdateProgress(ctx context.Context, progress domain.Progress) (*domain.Task, error)

	// CompleteTask marks a task as completed.
	CompleteTask(ctx context.Context, taskID uuid.UUID) (*domain.Task, error)

	// FailTask marks a task as failed.
	FailTask(ctx context.Context, taskID uuid.UUID) (*domain.Task, error)

	// GetTask retrieves the current state of a specific task within a job.
	// This allows external components to monitor task execution and handle failures.
	GetTask(ctx context.Context, jobID, taskID uuid.UUID) (*domain.Task, error)

	// MarkTaskStale flags a task that has become unresponsive or stopped reporting progress.
	// This enables automated detection and recovery of failed tasks that require intervention.
	MarkTaskStale(ctx context.Context, jobID, taskID uuid.UUID, reason domain.StallReason) error

	// RecoverTask attempts to resume execution of a previously stalled task.
	// It uses the last recorded checkpoint to restart the task from its last known good state.
	RecoverTask(ctx context.Context, jobID, taskID uuid.UUID) error
}

// TaskService orchestrates task operations by coordinating between domain services,
// repositories, caching, and concurrency controls.
type TaskService struct {
	// TODO: consider using an actual cache.
	// tasksCache provides in-memory caching of active tasks to reduce database load.
	mu         sync.RWMutex
	tasksCache map[uuid.UUID]*domain.Task

	taskRepo domain.TaskRepository

	persistInterval  time.Duration // How often to persist task state to storage
	staleTaskTimeout time.Duration // Duration after which a task is considered stale

	// taskDomainService handles core business logic and rules for tasks.
	// taskDomainService domain.TaskDomainService

	tracer trace.Tracer
}

// NewTaskService creates a new task service with the provided dependencies.
// It initializes an in-memory cache and configures persistence/timeout intervals.
func NewTaskService(
	taskRepo domain.TaskRepository,
	// domainSvc domain.TaskDomainService,
	persistInterval time.Duration,
	staleTimeout time.Duration,
	tracer trace.Tracer,
) *TaskService {
	const defaultTaskCacheSize = 1000
	return &TaskService{
		tasksCache:       make(map[uuid.UUID]*domain.Task, defaultTaskCacheSize),
		taskRepo:         taskRepo,
		persistInterval:  persistInterval,
		staleTaskTimeout: staleTimeout,
		// taskDomainService: domainSvc,
		tracer: tracer,
	}
}

// loadTask retrieves a task from storage and adds it to the cache.
func (s *TaskService) loadTask(ctx context.Context, taskID uuid.UUID) (*domain.Task, error) {
	ctx, span := s.tracer.Start(ctx, "task_service.scanning.load_task")
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
	s.tasksCache[taskID] = task
	s.mu.Unlock()
	span.AddEvent("task_cached")

	span.AddEvent("task_loaded")
	span.SetStatus(codes.Ok, "task loaded")

	return task, nil
}

// lookupTaskInCache retrieves a task from the cache if it exists.
// Returns the task and a boolean indicating if it was found.
func (s *TaskService) lookupTaskInCache(ctx context.Context, taskID uuid.UUID) (*domain.Task, bool) {
	_, span := s.tracer.Start(ctx, "task_service.scanning.lookup_task_cache")
	defer span.End()

	s.mu.RLock()
	task, exists := s.tasksCache[taskID]
	s.mu.RUnlock()

	span.AddEvent("cache_lookup_complete", trace.WithAttributes(
		attribute.Bool("found_in_cache", exists),
	))
	return task, exists
}

// StartTask initializes a new scan task for tracking within the system. It ensures
// the task is properly registered and persisted before monitoring can begin. This
// method should be called before any progress updates can be processed for the task.
//
// Returns the newly created task or an error if initialization fails. Will return
// an error if a task with the given ID already exists to prevent duplicate tracking.
func (s *TaskService) StartTask(ctx context.Context, jobID, taskID uuid.UUID) (*domain.Task, error) {
	ctx, span := s.tracer.Start(ctx, "task_service.scanning.start_task",
		trace.WithAttributes(
			attribute.String("task_id", taskID.String()),
			attribute.String("job_id", jobID.String()),
		))
	defer span.End()

	if _, exists := s.lookupTaskInCache(ctx, taskID); exists {
		span.AddEvent("task_already_exists")
		span.SetStatus(codes.Error, "task already exists")
		return nil, fmt.Errorf("task %s already exists", taskID)
	}

	newTask := domain.NewScanTask(jobID, taskID)
	if err := s.taskRepo.CreateTask(ctx, newTask); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to persist new task")
		return nil, fmt.Errorf("failed to persist new task: %w", err)
	}
	span.AddEvent("task_created")

	s.mu.Lock()
	s.tasksCache[taskID] = newTask
	s.mu.Unlock()
	span.AddEvent("task_cached")

	span.AddEvent("task_started")
	span.SetStatus(codes.Ok, "task started")

	return newTask, nil
}

// UpdateProgress processes a progress update for an active scan task. This allows the
// system to track task execution and maintain accurate status information. Progress
// updates are cached in memory and periodically persisted based on configured intervals
// to optimize performance while ensuring durability.
//
// Returns the updated task state or an error if the update cannot be processed. The
// task must exist and be in a valid state to accept progress updates.
func (s *TaskService) UpdateProgress(ctx context.Context, progress domain.Progress) (*domain.Task, error) {
	ctx, span := s.tracer.Start(ctx, "task_service.scanning.update_progress",
		trace.WithAttributes(
			attribute.String("task_id", progress.TaskID().String()),
			attribute.Int64("sequence_num", progress.SequenceNum()),
		))
	defer span.End()

	task, err := s.loadTask(ctx, progress.TaskID())
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to load task")
		return nil, fmt.Errorf("failed to load task: %w", err)
	}

	if err := task.ApplyProgress(progress); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to apply progress update")
		return nil, fmt.Errorf("failed to apply progress update: %w", err)
	}
	span.AddEvent("progress_update_applied")

	shouldPersist := time.Since(task.LastUpdateTime()) >= s.persistInterval
	if shouldPersist {
		if err := s.taskRepo.UpdateTask(ctx, task); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "failed to persist progress update")
			return nil, fmt.Errorf("failed to persist progress update: %w", err)
		}
		span.AddEvent("progress_update_persisted")
	}
	span.AddEvent("progress_update_complete")
	span.SetStatus(codes.Ok, "progress update complete")

	return task, nil
}

// CompleteTask marks a scan task as finished, finalizing its execution state. This
// should be called when a task has successfully processed all of its assigned work.
// The task must have processed at least one item and be in an in-progress state
// to be completed successfully.
//
// Returns the updated task state or an error if the task cannot be completed due to
// invalid state or persistence failures.
func (s *TaskService) CompleteTask(ctx context.Context, taskID uuid.UUID) (*domain.Task, error) {
	ctx, span := s.tracer.Start(ctx, "task_service.scanning.complete_task",
		trace.WithAttributes(
			attribute.String("task_id", taskID.String()),
		))
	defer span.End()

	task, err := s.loadTask(ctx, taskID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to load task")
		return nil, err
	}

	if err := task.Complete(); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to apply complete task")
		return nil, err
	}
	span.AddEvent("complete_task_applied")

	if err := s.taskRepo.UpdateTask(ctx, task); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to persist task completed")
		return nil, err
	}
	span.AddEvent("task_completed_persisted")
	span.SetStatus(codes.Ok, "task completed")

	return task, nil
}

// FailTask marks a task as failed
func (s *TaskService) FailTask(ctx context.Context, taskID uuid.UUID) (*domain.Task, error) {
	ctx, span := s.tracer.Start(ctx, "task_service.scanning.fail_task",
		trace.WithAttributes(
			attribute.String("task_id", taskID.String()),
		))
	defer span.End()

	task, err := s.loadTask(ctx, taskID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to load task")
		return nil, err
	}

	if err := task.Fail(); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to apply fail task")
		return nil, err
	}
	span.AddEvent("fail_task_applied")

	if err := s.taskRepo.UpdateTask(ctx, task); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to persist fail task")
		return nil, err
	}
	span.AddEvent("fail_task_persisted")
	span.SetStatus(codes.Ok, "task failed")

	return nil, nil
}

func (s *TaskService) GetTask(ctx context.Context, jobID uuid.UUID, taskID uuid.UUID) (*domain.Task, error) {
	// // purely orchestration logic
	// job, err := s.jobRepo.GetJob(ctx, jobID)
	// if err != nil {
	// 	return nil, err
	// }
	// if job == nil {
	// 	return nil, fmt.Errorf("job %s not found", jobID)
	// }
	// var found *domain.Task
	// job.UpdateTask(taskID, func(t *domain.Task) {
	// 	found = t
	// })
	// if found == nil {
	// 	return nil, fmt.Errorf("task %s not found in job %s", taskID, jobID)
	// }
	// return found, nil

	return nil, nil
}

func (s *TaskService) MarkTaskStale(ctx context.Context, jobID uuid.UUID, taskID uuid.UUID, reason domain.StallReason) error {
	// job, err := s.jobRepo.GetJob(ctx, jobID)
	// if err != nil {
	// 	return err
	// }
	// if job == nil {
	// 	return fmt.Errorf("job %s not found", jobID)
	// }

	// var foundTask *domain.Task
	// job.UpdateTask(taskID, func(task *domain.Task) {
	// 	// now we call domain logic, not do it ourselves
	// 	_ = s.taskDomainService.MarkTaskStale(task, reason)
	// 	foundTask = task
	// })
	// if foundTask == nil {
	// 	return fmt.Errorf("task %s not found in job %s", taskID, jobID)
	// }

	// // persist
	// if err := s.jobRepo.UpdateJob(ctx, job); err != nil {
	// 	return err
	// }
	// return nil

	return nil
}

func (s *TaskService) RecoverTask(ctx context.Context, jobID uuid.UUID, taskID uuid.UUID) error {
	// job, err := s.jobRepo.GetJob(ctx, jobID)
	// if err != nil {
	// 	return err
	// }
	// if job == nil {
	// 	return fmt.Errorf("job %s not found", jobID)
	// }

	// var foundTask *domain.Task
	// job.UpdateTask(taskID, func(task *domain.Task) {
	// 	_ = s.taskDomainService.RecoverTask(task)
	// 	foundTask = task
	// })
	// if foundTask == nil {
	// 	return fmt.Errorf("task %s not found in job %s", taskID, jobID)
	// }

	// // maybe re-publish the task, or reassign it
	// // ...
	// if err := s.jobRepo.UpdateJob(ctx, job); err != nil {
	// 	return err
	// }
	// return nil

	return nil
}
