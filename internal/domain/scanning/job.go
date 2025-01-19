package scanning

import (
	"fmt"
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

// Job coordinates and tracks a collection of related scanning tasks.
// It provides aggregated status and progress tracking across all child tasks.
type Job struct {
	jobID     uuid.UUID
	targetIDs []uuid.UUID
	status    JobStatus
	timeline  *Timeline
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

// AddTask registers a new scan task with this job and updates task counters.
// In domain/ScanJob
func (j *Job) AddTask(task *Task) error {
	j.tasks[task.ID] = task
	j.metrics.SetTotalTasks(len(j.tasks))

	// If this is our first task and we're queued, transition to running.
	if len(j.tasks) == 1 {
		if j.status != JobStatusQueued {
			return &JobStartError{message: "job is not in a valid state to start"}
		}
		j.status = JobStatusRunning
		j.timeline.MarkStarted()
	}

	j.updateStatusCounters()
	j.timeline.UpdateLastUpdate()

	return nil
}

// UpdateTask applies changes to a task's state via the provided update function.
// It returns false if the task doesn't exist, true if the update was successful.
func (j *Job) UpdateTask(taskID uuid.UUID, updateFn func(*Task)) bool {
	task, exists := j.tasks[taskID]
	if !exists {
		return false
	}

	updateFn(task)
	j.updateStatusCounters()
	j.timeline.UpdateLastUpdate()
	return true
}

// updateStatusCounters recalculates task completion metrics and overall job status.
// This should be called after any task state changes to maintain consistency.
func (j *Job) updateStatusCounters() {
	completed := 0
	failed := 0
	inProgress := 0

	for _, task := range j.tasks {
		switch task.status {
		case TaskStatusCompleted:
			completed++
		case TaskStatusFailed:
			failed++
		case TaskStatusInProgress, TaskStatusStale:
			inProgress++
		}
	}

	j.metrics.UpdateTaskCounts(completed, failed)

	switch {
	case completed+failed == len(j.tasks) && len(j.tasks) > 0:
		if failed == len(j.tasks) {
			j.status = JobStatusFailed
			j.timeline.MarkCompleted()
		} else {
			j.status = JobStatusCompleted
			j.timeline.MarkCompleted()
		}
	case inProgress > 0 || completed > 0 || failed > 0:
		j.status = JobStatusRunning
	default:
		j.status = JobStatusQueued
	}
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
