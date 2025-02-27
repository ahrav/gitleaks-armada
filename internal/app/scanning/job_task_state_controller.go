package scanning

import (
	"context"
	"sync"

	"github.com/ahrav/gitleaks-armada/pkg/common/uuid"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
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

// jobTaskState represents the state of a job, including pause and cancellation status,
// along with the cancellation functions for its tasks.
type jobTaskState struct {
	isPaused    bool
	isCancelled bool
	tasks       map[uuid.UUID]context.CancelCauseFunc
}

// JobTaskStateController encapsulates operations for tracking job and task state.
// It provides thread-safe methods for managing job pause states and task cancellation functions.
type JobTaskStateController struct {
	scannerID string

	mu        sync.RWMutex
	jobStates map[uuid.UUID]jobTaskState

	logger *logger.Logger
	tracer trace.Tracer
}

// NewJobTaskStateController creates a new JobTaskStateController instance.
func NewJobTaskStateController(scannerID string, logger *logger.Logger, tracer trace.Tracer) *JobTaskStateController {
	return &JobTaskStateController{
		scannerID: scannerID,
		jobStates: make(map[uuid.UUID]jobTaskState),
		logger:    logger.With("scanner_id", scannerID),
		tracer:    tracer,
	}
}

// AddTask adds a task to a job with its cancellation function.
// If the job doesn't exist, it will be created.
func (j *JobTaskStateController) AddTask(jobID, taskID uuid.UUID, cancelFunc context.CancelCauseFunc) {
	j.mu.Lock()
	defer j.mu.Unlock()

	if _, exists := j.jobStates[jobID]; !exists {
		j.jobStates[jobID] = jobTaskState{
			isPaused: false,
			tasks:    make(map[uuid.UUID]context.CancelCauseFunc),
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
	return exists && (js.isPaused || js.isCancelled)
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

	js.isPaused = true
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
// Returns the list of taskIDs that were cancelled.
func (j *JobTaskStateController) CancelJob(jobID uuid.UUID) []uuid.UUID {
	j.mu.Lock()
	defer j.mu.Unlock()

	js, exists := j.jobStates[jobID]
	if !exists {
		return nil
	}

	js.isPaused = false
	js.isCancelled = true
	j.jobStates[jobID] = js

	taskIDs := make([]uuid.UUID, 0, len(js.tasks))
	for taskID, cancel := range js.tasks {
		cancel(CancelEvent)
		delete(js.tasks, taskID)
		taskIDs = append(taskIDs, taskID)
	}

	return taskIDs
}

// ResumeJob marks a job as not paused.
// This creates a job state if it doesn't exist.
func (j *JobTaskStateController) ResumeJob(jobID uuid.UUID) {
	j.mu.Lock()
	defer j.mu.Unlock()

	js, exists := j.jobStates[jobID]
	if !exists {
		js = jobTaskState{
			tasks: make(map[uuid.UUID]context.CancelCauseFunc),
		}
	}

	js.isPaused = false
	j.jobStates[jobID] = js
}
