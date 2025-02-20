package scanning

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Job coordinates and tracks a collection of related scanning tasks.
// It provides aggregated status and progress tracking across all child tasks.
type Job struct {
	jobID    uuid.UUID
	status   JobStatus
	timeline *Timeline
}

// NewJob creates a new ScanJob instance with the provided job ID.
func NewJob(jobID uuid.UUID) *Job {
	return &Job{
		jobID:    jobID,
		status:   JobStatusQueued,
		timeline: NewTimeline(new(realTimeProvider)),
	}
}

// NewJobWithStatus creates a new Job instance with a specific status.
// This should only be used when reconstructing a Job from an event.
func NewJobWithStatus(jobID uuid.UUID, status JobStatus) *Job {
	return &Job{
		jobID:    jobID,
		status:   status,
		timeline: NewTimeline(new(realTimeProvider)),
	}
}

// ReconstructJob creates a ScanJob instance from stored fields, bypassing creation invariants.
// This should only be used by repositories when loading from the DB.
func ReconstructJob(
	jobID uuid.UUID,
	status JobStatus,
	timeline *Timeline,
) *Job {
	job := &Job{
		jobID:    jobID,
		status:   status,
		timeline: timeline,
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

// LastUpdateTime returns when this job's state was last modified.
// Access is synchronized to ensure thread-safe reads.
func (j *Job) LastUpdateTime() time.Time { return j.timeline.LastUpdate() }

// CompleteEnumeration transitions the job from Enumerating state based on task count.
// If there are tasks to process, it moves to Running state.
// If there are no tasks, it moves directly to Completed state.
func (j *Job) CompleteEnumeration(metrics *JobMetrics) error {
	if j.Status() != JobStatusEnumerating {
		return fmt.Errorf("cannot complete enumeration: job is not in enumerating state (current: %s)", j.Status())
	}

	targetStatus := JobStatusCompleted
	if metrics.TotalTasks() > 0 {
		targetStatus = JobStatusRunning
	}

	if err := j.UpdateStatus(targetStatus); err != nil {
		return fmt.Errorf("failed to update job status after enumeration: %w", err)
	}

	return nil
}

// UpdateStatus changes the job's status after validating the transition.
// It returns an error if the transition is not valid.
func (j *Job) UpdateStatus(newStatus JobStatus) error {
	if err := j.status.validateTransition(newStatus); err != nil {
		return err
	}
	j.status = newStatus
	return nil
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
