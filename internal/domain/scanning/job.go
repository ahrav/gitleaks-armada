package scanning

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// JobStatus represents the current state of a scan job. It enables tracking of
// job lifecycle from initialization through completion or failure.
type JobStatus string

const (
	// JobStatusInitialized indicates a job has been created but not yet started.
	JobStatusQueued JobStatus = "QUEUED"

	// JobStatusInProgress indicates a job is actively processing tasks.
	JobStatusRunning JobStatus = "RUNNING"

	// JobStatusCompleted indicates all job tasks finished successfully.
	JobStatusCompleted JobStatus = "COMPLETED"

	// JobStatusFailed indicates the job encountered an unrecoverable error.
	JobStatusFailed JobStatus = "FAILED"
)

func (s JobStatus) String() string { return string(s) }

// Job coordinates and tracks a collection of related scanning tasks.
// It provides aggregated status and progress tracking across all child tasks.
type Job struct {
	jobID     uuid.UUID
	targetIDs []uuid.UUID
	status    JobStatus
	timeline  *Timeline
	mu        sync.Mutex
	metrics   *JobMetrics
	tasks     map[uuid.UUID]*Task
}

// NewJob creates a new ScanJob instance with initialized state tracking.
// It ensures proper initialization of internal maps and timestamps for job monitoring.
func NewJob() *Job {
	return &Job{
		jobID:    uuid.New(),
		status:   JobStatusQueued,
		timeline: NewTimeline(new(realTimeProvider)),
		metrics:  NewJobMetrics(),
		tasks:    make(map[uuid.UUID]*Task),
	}
}

// ReconstructJob creates a ScanJob instance from stored fields, bypassing creation invariants.
// This should only be used by repositories when loading from the DB.
func ReconstructJob(
	jobID uuid.UUID,
	status JobStatus,
	timeline *Timeline,
	targetIDs []uuid.UUID,
	metrics *JobMetrics,
) *Job {
	job := &Job{
		jobID:    jobID,
		status:   status,
		timeline: timeline,
		tasks:    make(map[uuid.UUID]*Task),
		metrics:  metrics,
	}

	if len(targetIDs) > 0 {
		job.targetIDs = targetIDs
	}

	return job
}

// JobID returns the unique identifier for this scan job.
// Access is synchronized to ensure thread-safe reads.
func (j *Job) JobID() uuid.UUID { return j.jobID }

// Status returns the current execution status of the scan job.
// Access is synchronized to ensure thread-safe reads.
func (j *Job) Status() JobStatus { return j.status }

// StartTime returns when this scan job was initialized.
// Access is synchronized to ensure thread-safe reads.
func (j *Job) StartTime() time.Time { return j.timeline.StartedAt() }

// EndTime returns when this scan job was completed.
// A job only has an end time if it's in a terminal state.
func (j *Job) EndTime() (time.Time, bool) {
	if j.status == JobStatusCompleted || j.status == JobStatusFailed {
		return j.timeline.CompletedAt(), true
	}
	return time.Time{}, false
}

// TargetIDs returns the IDs of the targets associated with this job.
// Access is synchronized to ensure thread-safe reads.
func (j *Job) TargetIDs() []uuid.UUID { return j.targetIDs }

// LastUpdateTime returns when this job's state was last modified.
// Access is synchronized to ensure thread-safe reads.
func (j *Job) LastUpdateTime() time.Time { return j.timeline.LastUpdate() }

// Metrics returns the job's metrics.
func (j *Job) Metrics() *JobMetrics { return j.metrics }

// AssociateTargets links a scan target with this job.
func (j *Job) AssociateTargets(targetIDs []uuid.UUID) {
	j.targetIDs = append(j.targetIDs, targetIDs...)
}

// JobStartError is an error type for indicating that a job start operation failed.
type JobStartError struct {
	message string
}

// Error returns a string representation of the error.
func (e *JobStartError) Error() string {
	return fmt.Sprintf("job start error: %s", e.message)
}

// AddTask registers a new task to this job, updating metrics and status.
func (j *Job) AddTask(task *Task) error {
	j.mu.Lock()
	defer j.mu.Unlock()

	j.tasks[task.TaskID()] = task
	j.metrics.OnTaskAdded(task.Status())

	// If this is the first task and we were QUEUED, switch to RUNNING.
	if j.metrics.TotalTasks() == 1 && j.status == JobStatusQueued {
		j.status = JobStatusRunning
	}

	j.updateJobStatusLocked()
	return nil
}

// UpdateTask updates an existing task's status, adjusting metrics accordingly.
func (j *Job) UpdateTask(updatedTask *Task) error {
	j.mu.Lock()
	defer j.mu.Unlock()

	oldTask, found := j.tasks[updatedTask.TaskID()]
	if !found {
		return fmt.Errorf("task %s not found in job", updatedTask.TaskID())
	}

	oldStatus := oldTask.Status()
	newStatus := updatedTask.Status()

	if oldStatus != newStatus && !isValidTransition(oldStatus, newStatus) {
		return TaskInvalidTransitionError{oldStatus: oldStatus, newStatus: newStatus}
	}

	// Replace the stored task with the updated one.
	j.tasks[updatedTask.TaskID()] = updatedTask

	if oldStatus != newStatus {
		j.metrics.OnTaskStatusChanged(oldStatus, newStatus)
	}

	j.updateJobStatusLocked()
	return nil
}

// CompleteTask handles the entire task completion process within the job aggregate.
// It updates the task's status to COMPLETED and updates the job's metrics.
func (j *Job) CompleteTask(taskID uuid.UUID) error {
	j.mu.Lock()
	defer j.mu.Unlock()

	task, exists := j.tasks[taskID]
	if !exists {
		return fmt.Errorf("task %s not found in job", taskID)
	}

	oldStatus := task.Status()
	if err := task.Complete(); err != nil {
		return fmt.Errorf("failed to complete task: %w", err)
	}

	j.metrics.OnTaskStatusChanged(oldStatus, TaskStatusCompleted)
	j.updateJobStatusLocked()

	return nil
}

// FailTask handles the entire task failure process within the job aggregate.
func (j *Job) FailTask(taskID uuid.UUID) error {
	j.mu.Lock()
	defer j.mu.Unlock()

	task, exists := j.tasks[taskID]
	if !exists {
		return fmt.Errorf("task %s not found in job", taskID)
	}
	oldStatus := task.Status()
	if err := task.Fail(); err != nil {
		return fmt.Errorf("failed to fail task: %w", err)
	}

	j.metrics.OnTaskStatusChanged(oldStatus, TaskStatusFailed)
	j.updateJobStatusLocked()
	return nil
}

// TaskInvalidTransitionError is an error type for disallowed status changes.
type TaskInvalidTransitionError struct {
	oldStatus TaskStatus
	newStatus TaskStatus
}

func (e TaskInvalidTransitionError) Error() string {
	return fmt.Sprintf("invalid transition: cannot go from %s to %s", e.oldStatus, e.newStatus)
}

// isValidTransition holds the domain logic for which status changes are allowed.
func isValidTransition(oldStatus, newStatus TaskStatus) bool {
	// Example rules:
	// - We allow IN_PROGRESS -> COMPLETED, IN_PROGRESS -> FAILED, STALE -> COMPLETED, etc.
	// - We disallow COMPLETED -> IN_PROGRESS, COMPLETED -> STALE, FAILED -> IN_PROGRESS, etc.
	// This is entirely your domain’s choice—below is just an example.

	switch oldStatus {
	case TaskStatusInProgress, TaskStatusStale:
		// Allowed new states: Completed, Failed, or remain InProgress/Stale
		return newStatus == TaskStatusInProgress ||
			newStatus == TaskStatusStale ||
			newStatus == TaskStatusCompleted ||
			newStatus == TaskStatusFailed

	case TaskStatusCompleted:
		// Once completed, do not allow going back to in-progress or stale.
		return newStatus == TaskStatusCompleted

	case TaskStatusFailed:
		// Once failed, the task must remain failed.
		return newStatus == TaskStatusFailed
	}

	return true
}

// updateJobStatusLocked recalculates job status based on current metrics.
// Must be called while holding j.mu.
func (j *Job) updateJobStatusLocked() {
	total := j.metrics.TotalTasks()
	completed := j.metrics.CompletedTasks()
	failed := j.metrics.FailedTasks()
	inProgress := j.metrics.InProgressTasks()

	// If all tasks are in a terminal state (completed or failed).
	if completed+failed == total && total > 0 {
		if failed == total {
			j.status = JobStatusFailed
		} else {
			j.status = JobStatusCompleted
			j.timeline.MarkCompleted()
		}
	} else if inProgress > 0 || (completed+failed > 0) {
		// At least one task is in progress, or some have completed/failed, so job is running.
		j.status = JobStatusRunning
	} else {
		// No tasks or no progress -> job stays queued.
		j.status = JobStatusQueued
	}
	j.timeline.UpdateLastUpdate()
}

// GetAllTaskSummaries returns summaries for all tasks in this job.
func (j *Job) GetAllTaskSummaries() []TaskSummary {
	duration := time.Since(j.timeline.StartedAt())
	summaries := make([]TaskSummary, 0, len(j.tasks))
	for _, task := range j.tasks {
		summaries = append(summaries, task.GetSummary(duration))
	}
	return summaries
}

// JobSummary provides an aggregated overview of job execution progress.
// It combines overall job status with task-level metrics to enable job monitoring.
// TODO: Do something with this eventually..
type JobSummary struct {
	JobID          string
	Status         JobStatus
	StartTime      time.Time
	Duration       time.Duration
	TotalTasks     int
	CompletedTasks int
	FailedTasks    int
	TaskSummaries  []TaskSummary
}
