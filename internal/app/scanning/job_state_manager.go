// Package scanning provides services for coordinating and executing secret scanning operations.
package scanning

import (
	"context"
	"sync"

	"github.com/google/uuid"
)

// jobStateData represents the state of a job and all its tasks with their cancel functions.
// This is used to cancel all tasks for a given job when it is paused.
type jobStateData struct {
	paused bool
	tasks  map[uuid.UUID]context.CancelCauseFunc
}

// JobStateManager encapsulates operations for tracking job and task state.
// It provides thread-safe methods for managing job pause states and task cancellation functions.
type JobStateManager struct {
	mu        sync.RWMutex
	jobStates map[uuid.UUID]jobStateData
}

// NewJobStateManager creates a new JobStateManager instance.
func NewJobStateManager() *JobStateManager {
	return &JobStateManager{jobStates: make(map[uuid.UUID]jobStateData)}
}

// AddTask adds a task to a job with its cancellation function.
// If the job doesn't exist, it will be created.
func (j *JobStateManager) AddTask(jobID, taskID uuid.UUID, cancelFunc context.CancelCauseFunc) {
	j.mu.Lock()
	defer j.mu.Unlock()

	if _, exists := j.jobStates[jobID]; !exists {
		j.jobStates[jobID] = jobStateData{
			paused: false,
			tasks:  make(map[uuid.UUID]context.CancelCauseFunc),
		}
	}

	j.jobStates[jobID].tasks[taskID] = cancelFunc
}

// RemoveTask removes a task from a job.
func (j *JobStateManager) RemoveTask(jobID, taskID uuid.UUID) {
	j.mu.Lock()
	defer j.mu.Unlock()

	if js, exists := j.jobStates[jobID]; exists {
		delete(js.tasks, taskID)
		j.jobStates[jobID] = js
	}
}

// IsJobPaused checks if a job is paused.
// Returns true if the job is paused or doesn't exist.
func (j *JobStateManager) IsJobPaused(jobID uuid.UUID) bool {
	j.mu.RLock()
	defer j.mu.RUnlock()

	js, exists := j.jobStates[jobID]
	return !exists || js.paused
}

// PauseJob marks a job as paused and cancels all of its tasks.
// Returns the number of tasks that were cancelled.
func (j *JobStateManager) PauseJob(jobID uuid.UUID, cause error) int {
	j.mu.Lock()
	defer j.mu.Unlock()

	js, exists := j.jobStates[jobID]
	if !exists {
		return 0
	}

	js.paused = true
	j.jobStates[jobID] = js

	count := 0
	for taskID, cancel := range js.tasks {
		cancel(cause)
		delete(js.tasks, taskID)
		count++
	}

	return count
}

// ResumeJob marks a job as not paused.
// This creates a job state if it doesn't exist.
func (j *JobStateManager) ResumeJob(jobID uuid.UUID) {
	j.mu.Lock()
	defer j.mu.Unlock()

	js, exists := j.jobStates[jobID]
	if !exists {
		js = jobStateData{
			tasks: make(map[uuid.UUID]context.CancelCauseFunc),
		}
	}

	js.paused = false
	j.jobStates[jobID] = js
}
