package scanning

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	domain "github.com/ahrav/gitleaks-armada/internal/domain/scanning"
)

// ScanTaskService manages the execution state of individual scan tasks.
// It handles task progress updates, failure detection, and recovery operations
// to ensure reliable task completion.
type ScanTaskService interface {
	// UpdateProgress processes a status update from an executing scanner.
	// This maintains task state and enables progress monitoring.
	UpdateProgress(ctx context.Context, progress domain.Progress) error

	// GetTask retrieves the current state of a specific task."context"
	GetTask(ctx context.Context, jobID, taskID string) (*domain.Task, error)

	// MarkTaskStale flags a task that has stopped reporting progress.
	// This enables detection of failed or hung tasks that require intervention.
	MarkTaskStale(ctx context.Context, jobID, taskID string, reason domain.StallReason) error

	// RecoverTask attempts to resume execution of a stalled task.
	// This uses the last checkpoint to restart the task from its previous progress point.
	RecoverTask(ctx context.Context, jobID, taskID string) error
}

// Implementation that orchestrates domain service, repositories, concurrency, caching, etc.
type ScanTaskServiceImpl struct {
	mu        sync.RWMutex
	jobsCache map[string]*domain.ScanJob // ephemeral cache
	jobRepo   domain.JobRepository
	taskRepo  domain.TaskRepository
	// checkpointRepo   domain.CheckpointRepository
	persistInterval  time.Duration
	staleTaskTimeout time.Duration

	// domain-level service for the actual task rules
	taskDomainService domain.TaskDomainService
}

func NewScanTaskServiceImpl(
	jobRepo domain.JobRepository,
	taskRepo domain.TaskRepository,
	// checkpointRepo domain.CheckpointRepository,
	domainSvc domain.TaskDomainService,
	persistInterval time.Duration,
	staleTimeout time.Duration,
) *ScanTaskServiceImpl {
	return &ScanTaskServiceImpl{
		jobsCache: make(map[string]*domain.ScanJob),
		jobRepo:   jobRepo,
		taskRepo:  taskRepo,
		// checkpointRepo:    checkpointRepo,
		persistInterval:   persistInterval,
		staleTaskTimeout:  staleTimeout,
		taskDomainService: domainSvc,
	}
}

// UpdateProgress orchestrates the domain calls + repo calls + concurrency
func (s *ScanTaskServiceImpl) UpdateProgress(ctx context.Context, progress domain.Progress) error {
	if progress.JobID == uuid.Nil || progress.TaskID == uuid.Nil {
		return errors.New("missing jobID or taskID")
	}

	// 1. Load job from in-memory or repo
	s.mu.RLock()
	job, inCache := s.jobsCache[progress.JobID.String()]
	s.mu.RUnlock()
	if !inCache {
		loadedJob, err := s.jobRepo.GetJob(ctx, progress.JobID.String())
		if err != nil {
			return err
		}
		if loadedJob == nil {
			return fmt.Errorf("job %s not found", progress.JobID)
		}
		s.mu.Lock()
		job, inCache = s.jobsCache[progress.JobID.String()]
		if !inCache {
			job = loadedJob
			s.jobsCache[progress.JobID.String()] = job
		}
		s.mu.Unlock()
	}

	// 2. Update the task in the domain
	s.mu.Lock()
	updated := job.UpdateTask(progress.TaskID, func(task *domain.Task) {
		// Instead of direct domain logic, we call the domain service method:
		_ = s.taskDomainService.UpdateProgress(task, progress)
		// ignoring out-of-order updates is a domain rule => in domain service
	})
	if !updated {
		// If the task doesn't exist in memory, create a new one
		newTask := domain.NewScanTask(job.GetJobID(), progress.TaskID)
		_ = s.taskDomainService.UpdateProgress(newTask, progress)
		job.AddTask(newTask)
	}

	persistNow := time.Since(job.GetLastUpdateTime()) >= s.persistInterval
	s.mu.Unlock()

	// 3. Persist checkpoint if needed
	// if progress.Checkpoint != nil && s.checkpointRepo != nil {
	// 	if err := s.checkpointRepo.SaveCheckpoint(ctx, *progress.Checkpoint); err != nil {
	// 		return err
	// 	}
	// }

	// 4. Persist changes if needed
	if persistNow {
		if err := s.jobRepo.UpdateJob(ctx, job); err != nil {
			return err
		}
		// If tasks live in a separate table, we might do:
		t, _ := s.GetTask(ctx, progress.JobID, progress.TaskID)
		if t != nil {
			if err := s.taskRepo.UpdateTask(ctx, t); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *ScanTaskServiceImpl) GetTask(ctx context.Context, jobID uuid.UUID, taskID uuid.UUID) (*domain.Task, error) {
	// purely orchestration logic
	job, err := s.jobRepo.GetJob(ctx, jobID.String())
	if err != nil {
		return nil, err
	}
	if job == nil {
		return nil, fmt.Errorf("job %s not found", jobID)
	}
	var found *domain.Task
	job.UpdateTask(taskID, func(t *domain.Task) {
		found = t
	})
	if found == nil {
		return nil, fmt.Errorf("task %s not found in job %s", taskID, jobID)
	}
	return found, nil
}

func (s *ScanTaskServiceImpl) MarkTaskStale(ctx context.Context, jobID uuid.UUID, taskID uuid.UUID, reason domain.StallReason) error {
	job, err := s.jobRepo.GetJob(ctx, jobID.String())
	if err != nil {
		return err
	}
	if job == nil {
		return fmt.Errorf("job %s not found", jobID)
	}

	var foundTask *domain.Task
	job.UpdateTask(taskID, func(task *domain.Task) {
		// now we call domain logic, not do it ourselves
		_ = s.taskDomainService.MarkTaskStale(task, reason)
		foundTask = task
	})
	if foundTask == nil {
		return fmt.Errorf("task %s not found in job %s", taskID, jobID)
	}

	// persist
	if err := s.jobRepo.UpdateJob(ctx, job); err != nil {
		return err
	}
	return nil
}

func (s *ScanTaskServiceImpl) RecoverTask(ctx context.Context, jobID uuid.UUID, taskID uuid.UUID) error {
	job, err := s.jobRepo.GetJob(ctx, jobID.String())
	if err != nil {
		return err
	}
	if job == nil {
		return fmt.Errorf("job %s not found", jobID)
	}

	var foundTask *domain.Task
	job.UpdateTask(taskID, func(task *domain.Task) {
		_ = s.taskDomainService.RecoverTask(task)
		foundTask = task
	})
	if foundTask == nil {
		return fmt.Errorf("task %s not found in job %s", taskID, jobID)
	}

	// maybe re-publish the task, or reassign it
	// ...
	if err := s.jobRepo.UpdateJob(ctx, job); err != nil {
		return err
	}
	return nil
}
