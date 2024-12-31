// Package manager provides state management for scan jobs and tasks.
package manager

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/ahrav/gitleaks-armada/pkg/state"
)

// Ensure StateManager implements the Manager interface.
var _ state.Manager = (*StateManager)(nil)

// StateManager coordinates the lifecycle and state of scan jobs and their tasks.
// It provides thread-safe access to job state and handles persistence to a backing store.
type StateManager struct {
	mu    sync.RWMutex
	jobs  map[string]*state.ScanJob // Maps job IDs to their state
	store state.Store

	// Configuration
	persistInterval  time.Duration // How often to persist state updates
	staleTaskTimeout time.Duration // When to mark inactive tasks as stale
}

// Option allows for functional configuration of a StateManager.
type Option func(*StateManager)

// WithPersistInterval configures how frequently state changes are persisted to storage.
// This helps balance durability with performance.
func WithPersistInterval(d time.Duration) Option {
	return func(sm *StateManager) {
		sm.persistInterval = d
	}
}

// WithStaleTaskTimeout configures when to mark tasks as stale due to inactivity.
// This enables detection of hung or failed tasks that don't properly report status.
func WithStaleTaskTimeout(d time.Duration) Option {
	return func(sm *StateManager) {
		sm.staleTaskTimeout = d
	}
}

// NewStateManager creates a StateManager with the given store and options.
// It initializes with default intervals that can be overridden via options.
func NewStateManager(store state.Store, opts ...Option) *StateManager {
	sm := &StateManager{
		jobs:             make(map[string]*state.ScanJob),
		store:            store,
		persistInterval:  5 * time.Minute,  // Default persistence interval
		staleTaskTimeout: 10 * time.Minute, // Default stale timeout
	}

	// Apply any custom options
	for _, opt := range opts {
		opt(sm)
	}

	return sm
}

// HandleProgressUpdate processes a progress update from a scanner, managing both
// in-memory state and persistence. It ensures updates are applied in sequence
// and handles checkpointing of scan progress.
func (sm *StateManager) HandleProgressUpdate(ctx context.Context, progress state.ScanProgress) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Load or create job state
	job, ok := sm.jobs[progress.JobID]
	if !ok {
		// Try loading from persistent store before creating new
		loadedJob, err := sm.store.GetJob(ctx, progress.JobID)
		if err != nil {
			job = state.NewScanJob(progress.JobID)
		} else {
			job = loadedJob
		}
		sm.jobs[progress.JobID] = job
	}

	// Update existing task or create new one
	updated := job.UpdateTask(progress.TaskID, func(task *state.ScanTask) {
		// Prevent out-of-order updates
		if progress.SequenceNum <= task.GetLastSequenceNum() {
			return
		}
		task.UpdateProgress(progress)
	})

	if !updated {
		task := state.NewScanTask(progress.JobID, progress.TaskID)
		task.UpdateProgress(progress)
		job.AddTask(task)
	}

	// Persist checkpoint if provided
	if progress.Checkpoint != nil {
		if err := sm.store.SaveCheckpoint(ctx, *progress.Checkpoint); err != nil {
			return fmt.Errorf("failed to save checkpoint: %w", err)
		}
	}

	// Persist state based on configured interval or completion status
	if sm.shouldPersistState(job) {
		if err := sm.store.SaveProgress(ctx, progress); err != nil {
			return fmt.Errorf("failed to persist progress: %w", err)
		}
	}

	return nil
}

// shouldPersistState determines if the current state should be persisted based on
// job status or time since last persistence.
func (sm *StateManager) shouldPersistState(job *state.ScanJob) bool {
	status := job.GetStatus()
	if status == state.JobStatusCompleted || status == state.JobStatusFailed {
		return true
	}
	return time.Since(job.GetLastUpdateTime()) >= sm.persistInterval
}

// isTaskStale determines if a task should be marked as stale based on its status
// and last update time.
func (sm *StateManager) isTaskStale(task *state.ScanTask) bool {
	status := task.GetStatus()
	if status == state.TaskStatusCompleted || status == state.TaskStatusFailed {
		return false
	}
	return time.Since(task.GetLastUpdateTime()) >= sm.staleTaskTimeout
}

// validateJobState performs integrity checks on job state to ensure consistency.
func (sm *StateManager) validateJobState(job *state.ScanJob) error {
	if job == nil {
		return fmt.Errorf("job cannot be nil")
	}

	jobID := job.GetJobID()
	if jobID == "" {
		return fmt.Errorf("job ID cannot be empty")
	}

	summaries := job.GetAllTaskSummaries()
	taskCount := len(summaries)
	completedTasks := 0
	failedTasks := 0

	for _, summary := range summaries {
		switch summary.Status {
		case state.TaskStatusCompleted:
			completedTasks++
		case state.TaskStatusFailed:
			failedTasks++
		}
	}

	if completedTasks+failedTasks > taskCount {
		return fmt.Errorf("invalid task counts: completed(%d) + failed(%d) > total(%d)",
			completedTasks, failedTasks, taskCount)
	}

	return nil
}

// GetJob retrieves the current state of a scan job, first checking memory
// then falling back to persistent storage.
func (sm *StateManager) GetJob(ctx context.Context, jobID string) (*state.ScanJob, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if job, ok := sm.jobs[jobID]; ok {
		return job, nil
	}

	job, err := sm.store.GetJob(ctx, jobID)
	if err != nil {
		return nil, fmt.Errorf("failed to get job from store: %w", err)
	}

	if job != nil {
		sm.jobs[jobID] = job
	}

	return job, nil
}

// GetTask retrieves the current state of a specific task within a job.
func (sm *StateManager) GetTask(ctx context.Context, jobID, taskID string) (*state.ScanTask, error) {
	job, err := sm.GetJob(ctx, jobID)
	if err != nil {
		return nil, fmt.Errorf("failed to get job: %w", err)
	}

	if job == nil {
		return nil, fmt.Errorf("job %s not found", jobID)
	}

	var foundTask *state.ScanTask
	job.UpdateTask(taskID, func(task *state.ScanTask) {
		foundTask = task
	})

	if foundTask == nil {
		return nil, fmt.Errorf("task %s not found in job %s", taskID, jobID)
	}

	return foundTask, nil
}

// GetJobSummary provides a snapshot of job progress including task statuses
// and timing information.
func (sm *StateManager) GetJobSummary(ctx context.Context, jobID string) (*state.JobSummary, error) {
	job, err := sm.GetJob(ctx, jobID)
	if err != nil {
		return nil, fmt.Errorf("failed to get job: %w", err)
	}

	if job == nil {
		return nil, fmt.Errorf("job %s not found", jobID)
	}

	return &state.JobSummary{
		JobID:         job.GetJobID(),
		Status:        job.GetStatus(),
		StartTime:     job.GetStartTime(),
		Duration:      time.Since(job.GetStartTime()),
		TaskSummaries: job.GetAllTaskSummaries(),
	}, nil
}

// DetectStaleTasks identifies and marks tasks that have stopped reporting progress.
// It returns a list of stalled tasks and updates their status in the persistent store.
func (sm *StateManager) DetectStaleTasks(ctx context.Context) ([]*state.StalledTask, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	stalledTasks := make([]*state.StalledTask, 0)
	now := time.Now()

	for _, job := range sm.jobs {
		status := job.GetStatus()
		if status == state.JobStatusCompleted || status == state.JobStatusFailed {
			continue
		}

		summaries := job.GetAllTaskSummaries()
		for _, summary := range summaries {
			if summary.Status == state.TaskStatusCompleted ||
				summary.Status == state.TaskStatusFailed ||
				summary.Status == state.TaskStatusStale {
				continue
			}

			if now.Sub(summary.LastUpdate) >= sm.staleTaskTimeout {
				job.UpdateTask(summary.TaskID, func(task *state.ScanTask) {
					stalledTask := task.ToStalledTask(state.StallReasonNoProgress, task.GetLastUpdateTime())
					stalledTasks = append(stalledTasks, stalledTask)

					task.UpdateProgress(state.ScanProgress{
						Status:    state.TaskStatusStale,
						Timestamp: now,
					})
				})

				if err := sm.store.SaveJob(ctx, job); err != nil {
					return nil, fmt.Errorf("failed to persist stale task state for job %s: %w",
						job.GetJobID(), err)
				}
			}
		}
	}

	return stalledTasks, nil
}
