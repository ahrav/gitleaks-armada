package scanning

import (
	"context"
	"sync"

	"github.com/google/uuid"
)

// terminationReason represents the reason a job was stopped.
// It implements the error interface to allow it to be used as a cancellation cause.
type terminationReason string

func (r terminationReason) Error() string { return string(r) }

const (
	// PauseEvent indicates a job was paused.
	PauseEvent = terminationReason("pause")
	// CancelEvent indicates a job was cancelled.
	CancelEvent = terminationReason("cancel")
)

// jobTaskCancellationRecord represents the state of a job and all its tasks with their cancel functions.
// This is used to cancel all tasks for a given job when it is paused.
type jobTaskCancellationRecord struct {
	paused    bool
	cancelled bool
	tasks     map[uuid.UUID]context.CancelCauseFunc
}

// JobTaskStateController encapsulates operations for tracking job and task state.
// It provides thread-safe methods for managing job pause states and task cancellation functions.
type JobTaskStateController struct {
	mu        sync.RWMutex
	jobStates map[uuid.UUID]jobTaskCancellationRecord
}

// NewJobTaskStateController creates a new JobTaskStateController instance.
func NewJobTaskStateController() *JobTaskStateController {
	return &JobTaskStateController{jobStates: make(map[uuid.UUID]jobTaskCancellationRecord)}
}

// AddTask adds a task to a job with its cancellation function.
// If the job doesn't exist, it will be created.
func (j *JobTaskStateController) AddTask(jobID, taskID uuid.UUID, cancelFunc context.CancelCauseFunc) {
	j.mu.Lock()
	defer j.mu.Unlock()

	if _, exists := j.jobStates[jobID]; !exists {
		j.jobStates[jobID] = jobTaskCancellationRecord{
			paused: false,
			tasks:  make(map[uuid.UUID]context.CancelCauseFunc),
		}
	}

	j.jobStates[jobID].tasks[taskID] = cancelFunc
}

// RemoveTask removes a task from a job.
func (j *JobTaskStateController) RemoveTask(jobID, taskID uuid.UUID) {
	j.mu.Lock()
	defer j.mu.Unlock()

	if js, exists := j.jobStates[jobID]; exists {
		delete(js.tasks, taskID)
		j.jobStates[jobID] = js
	}
}

// ShouldRejectTask determines if a job should reject a new task.
// Returns true if the job is paused or cancelled.
func (j *JobTaskStateController) ShouldRejectTask(jobID uuid.UUID) bool {
	j.mu.RLock()
	defer j.mu.RUnlock()

	js, exists := j.jobStates[jobID]
	return exists && (js.paused || js.cancelled)
}

// PauseJob marks a job as paused and cancels all of its tasks.
// Returns the number of tasks that were cancelled.
func (j *JobTaskStateController) PauseJob(jobID uuid.UUID) int {
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
		cancel(PauseEvent)
		delete(js.tasks, taskID)
		count++
	}

	return count
}

// CancelJob marks a job as cancelled and cancels all of its tasks.
// Returns the number of tasks that were cancelled.
func (j *JobTaskStateController) CancelJob(jobID uuid.UUID) int {
	j.mu.Lock()
	defer j.mu.Unlock()

	js, exists := j.jobStates[jobID]
	if !exists {
		return 0
	}

	js.paused = false
	js.cancelled = true
	j.jobStates[jobID] = js

	count := 0
	for taskID, cancel := range js.tasks {
		cancel(CancelEvent)
		delete(js.tasks, taskID)
		count++
	}

	return count
}

// ResumeJob marks a job as not paused.
// This creates a job state if it doesn't exist.
func (j *JobTaskStateController) ResumeJob(jobID uuid.UUID) {
	j.mu.Lock()
	defer j.mu.Unlock()

	js, exists := j.jobStates[jobID]
	if !exists {
		js = jobTaskCancellationRecord{
			tasks: make(map[uuid.UUID]context.CancelCauseFunc),
		}
	}

	js.paused = false
	j.jobStates[jobID] = js
}
