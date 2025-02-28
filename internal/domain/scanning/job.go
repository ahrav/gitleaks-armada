package scanning

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/ahrav/gitleaks-armada/pkg/common/uuid"
)

// Job coordinates and tracks a collection of related scanning tasks.
// It provides aggregated status and progress tracking across all child tasks.
type Job struct {
	jobID      uuid.UUID
	sourceType string
	config     json.RawMessage
	status     JobStatus
	timeline   *Timeline
}

// NewJob creates a new ScanJob instance with the provided job ID and configuration.
func NewJob(jobID uuid.UUID, sourceType string, config json.RawMessage) *Job {
	return &Job{
		jobID:      jobID,
		sourceType: sourceType,
		config:     config,
		status:     JobStatusQueued,
		timeline:   NewTimeline(new(realTimeProvider)),
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
	sourceType string,
	config json.RawMessage,
	status JobStatus,
	timeline *Timeline,
) *Job {
	job := &Job{
		jobID:      jobID,
		sourceType: sourceType,
		config:     config,
		status:     status,
		timeline:   timeline,
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

// Getters for the new fields.
func (j *Job) SourceType() string      { return j.sourceType }
func (j *Job) Config() json.RawMessage { return j.config }

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

	// Mark the start time when transitioning from QUEUED to ENUMERATING
	// as this represents the beginning of actual job execution.
	if j.status == JobStatusQueued && newStatus == JobStatusEnumerating {
		j.timeline.MarkStarted()
	}

	// Mark completion time when transitioning to a terminal state.
	if newStatus == JobStatusCompleted || newStatus == JobStatusCancelled || newStatus == JobStatusFailed {
		j.timeline.MarkCompleted()
	}

	j.status = newStatus
	return nil
}
