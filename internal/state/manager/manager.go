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
	return func(sm *StateManager) { sm.persistInterval = d }
}

// WithStaleTaskTimeout configures when to mark tasks as stale due to inactivity.
// This enables detection of hung or failed tasks that don't properly report status.
func WithStaleTaskTimeout(d time.Duration) Option {
	return func(sm *StateManager) { sm.staleTaskTimeout = d }
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

	for _, opt := range opts {
		opt(sm)
	}

	return sm
}

// HandleProgressUpdate processes a progress update from a scanner. It manages both
// in-memory state and persistence to ensure scan progress is tracked reliably.
// The method is thread-safe and handles concurrent updates by using locks
// strategically to minimize contention.
//
// Progress updates are applied in sequence using sequence numbers to prevent
// out-of-order updates. Checkpoints are persisted to enable task recovery.
// State changes are batched and persisted based on configured intervals to
// balance durability with performance.
func (sm *StateManager) HandleProgressUpdate(ctx context.Context, progress state.ScanProgress) error {
	// Validate required fields before acquiring locks
	if progress.JobID == "" {
		return fmt.Errorf("job ID cannot be empty")
	}
	if progress.TaskID == "" {
		return fmt.Errorf("task ID cannot be empty")
	}

	var job *state.ScanJob

	// First critical section: Check if job exists in memory.
	sm.mu.Lock()
	job, ok := sm.jobs[progress.JobID]
	if !ok {
		sm.mu.Unlock()

		// Load from persistent store if not in memory.
		loadedJob, err := sm.store.GetJob(ctx, progress.JobID)
		if err != nil {
			// Create new job if not found in store.
			job = state.NewScanJob(progress.JobID)
		} else {
			job = loadedJob
		}

		// Second critical section: Store job in memory if another goroutine hasn't already.
		sm.mu.Lock()
		if existing, ok := sm.jobs[progress.JobID]; ok {
			job = existing
		} else {
			sm.jobs[progress.JobID] = job
		}
	}

	// Update task state, respecting sequence numbers to prevent out-of-order updates.
	updated := job.UpdateTask(progress.TaskID, func(task *state.ScanTask) {
		if progress.SequenceNum <= task.GetLastSequenceNum() {
			return
		}
		task.UpdateProgress(progress)
	})

	if !updated {
		// Create and add new task if it doesn't exist.
		task := state.NewScanTask(progress.JobID, progress.TaskID)
		task.UpdateProgress(progress)
		job.AddTask(task)
	}

	shouldPersist := sm.shouldPersistState(job)
	sm.mu.Unlock()

	// Persist checkpoint and progress outside lock to minimize lock contention.
	if progress.Checkpoint != nil {
		if err := sm.store.SaveCheckpoint(ctx, *progress.Checkpoint); err != nil {
			return fmt.Errorf("failed to save checkpoint: %w", err)
		}
	}

	if shouldPersist {
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

// DetectStaleTasks identifies tasks that have stopped reporting progress updates within
// the configured timeout period. It marks these tasks as stale in the persistent store
// to enable automated recovery workflows and returns details about the affected tasks.
// This is critical for maintaining system health by detecting hung or failed tasks
// that require intervention.
func (sm *StateManager) DetectStaleTasks(ctx context.Context) ([]*state.StalledTask, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	stalledTasks := make([]*state.StalledTask, 0)
	now := time.Now()

	for _, job := range sm.jobs {
		// Skip jobs that have reached terminal states.
		if job.GetStatus() == state.JobStatusCompleted ||
			job.GetStatus() == state.JobStatusFailed {
			continue
		}

		for _, summary := range job.GetAllTaskSummaries() {
			// Skip tasks that have already reached a terminal state.
			if summary.GetStatus() == state.TaskStatusCompleted ||
				summary.GetStatus() == state.TaskStatusFailed ||
				summary.GetStatus() == state.TaskStatusStale {
				continue
			}

			if now.Sub(summary.GetLastUpdateTimestamp()) >= sm.staleTaskTimeout {
				job.UpdateTask(summary.GetTaskID(), func(task *state.ScanTask) {
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
