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
	// UpdateProgress processes a status update from a running scanner task.
	// It maintains the task's execution state and enables monitoring of scan progress.
	// The update is cached in memory and periodically persisted based on configured intervals.
	UpdateProgress(ctx context.Context, progress domain.Progress) error

	// GetTask retrieves the current state of a specific task within a job.
	// This allows external components to monitor task execution and handle failures.
	GetTask(ctx context.Context, jobID, taskID string) (*domain.Task, error)

	// MarkTaskStale flags a task that has become unresponsive or stopped reporting progress.
	// This enables automated detection and recovery of failed tasks that require intervention.
	MarkTaskStale(ctx context.Context, jobID, taskID string, reason domain.StallReason) error

	// RecoverTask attempts to resume execution of a previously stalled task.
	// It uses the last recorded checkpoint to restart the task from its last known good state.
	RecoverTask(ctx context.Context, jobID, taskID string) error
}

// ScanTaskServiceImpl orchestrates task operations by coordinating between domain services,
// repositories, caching, and concurrency controls.
type ScanTaskServiceImpl struct {
	// tasksCache provides in-memory caching of active tasks to reduce database load.
	mu         sync.RWMutex
	tasksCache map[uuid.UUID]*domain.Task

	taskRepo domain.TaskRepository
	// checkpointRepo   domain.CheckpointRepository

	persistInterval  time.Duration // How often to persist task state to storage
	staleTaskTimeout time.Duration // Duration after which a task is considered stale

	// taskDomainService handles core business logic and rules for tasks.
	taskDomainService domain.TaskDomainService

	tracer trace.Tracer
}

// NewScanTaskServiceImpl creates a new task service with the provided dependencies.
// It initializes an in-memory cache and configures persistence/timeout intervals.
func NewScanTaskServiceImpl(
	taskRepo domain.TaskRepository,
	// checkpointRepo domain.CheckpointRepository,
	domainSvc domain.TaskDomainService,
	persistInterval time.Duration,
	staleTimeout time.Duration,
) *ScanTaskServiceImpl {
	const defaultTaskCacheSize = 1000
	return &ScanTaskServiceImpl{
		tasksCache: make(map[uuid.UUID]*domain.Task, defaultTaskCacheSize),
		taskRepo:   taskRepo,
		// checkpointRepo:    checkpointRepo,
		persistInterval:   persistInterval,
		staleTaskTimeout:  staleTimeout,
		taskDomainService: domainSvc,
	}
}

// UpdateProgress handles a task progress update by coordinating cache access,
// domain logic, and persistence operations.
func (s *ScanTaskServiceImpl) UpdateProgress(ctx context.Context, progress domain.Progress) error {
	ctx, span := s.tracer.Start(ctx, "scan_task_service.update_progress",
		trace.WithAttributes(
			attribute.String("task_id", progress.TaskID.String()),
			attribute.Int64("sequence_num", progress.SequenceNum),
		))
	defer span.End()

	s.mu.RLock()
	task, isCached := s.tasksCache[progress.TaskID]
	s.mu.RUnlock()
	span.AddEvent("task_cached", trace.WithAttributes(attribute.Bool("is_cached", isCached)))

	if !isCached {
		var err error
		task, err = s.loadTask(ctx, progress.TaskID)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "failed to get task")
			return fmt.Errorf("failed to get task: %w", err)
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := task.ApplyProgress(progress); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to apply progress update")
		return fmt.Errorf("failed to apply progress update: %w", err)
	}
	span.AddEvent("progress_applied")

	s.tasksCache[progress.TaskID] = task

	shouldPersist := time.Since(task.GetLastUpdateTime()) >= s.persistInterval
	if shouldPersist {
		if err := s.taskRepo.UpdateTask(ctx, task); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "failed to persist task update")
			return fmt.Errorf("failed to persist task update: %w", err)
		}
		span.AddEvent("task_persisted")
	}
	span.AddEvent("task_update_complete")
	span.SetStatus(codes.Ok, "task update complete")

	return nil
}

// loadTask retrieves a task from storage and adds it to the cache.
func (s *ScanTaskServiceImpl) loadTask(ctx context.Context, taskID uuid.UUID) (*domain.Task, error) {
	ctx, span := s.tracer.Start(ctx, "scan_task_service.load_task")
	defer span.End()

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

func (s *ScanTaskServiceImpl) GetTask(ctx context.Context, jobID uuid.UUID, taskID uuid.UUID) (*domain.Task, error) {
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

func (s *ScanTaskServiceImpl) MarkTaskStale(ctx context.Context, jobID uuid.UUID, taskID uuid.UUID, reason domain.StallReason) error {
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

func (s *ScanTaskServiceImpl) RecoverTask(ctx context.Context, jobID uuid.UUID, taskID uuid.UUID) error {
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
