package scanning

import (
	"time"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/pkg/common/uuid"
)

// Event types relevant to Jobs:
const (
	EventTypeJobRequested events.EventType = "JobRequested"

	EventTypeJobScheduled            events.EventType = "JobScheduled"
	EventTypeJobCompleted            events.EventType = "JobCompleted"
	EventTypeJobFailed               events.EventType = "JobFailed"
	EventTypeJobEnumerationCompleted events.EventType = "JobEnumerationCompleted"
	EventTypeJobPausing              events.EventType = "JobPausing"
	EventTypeJobPaused               events.EventType = "JobPaused"
	EventTypeJobResuming             events.EventType = "JobResuming"
	EventTypeJobCancelling           events.EventType = "JobCancelling"
	EventTypeJobCancelled            events.EventType = "JobCancelled"
)

// JobRequestedEvent represents the event generated when a scan job is requested.
type JobRequestedEvent struct {
	jobID       uuid.UUID
	occurredAt  time.Time
	Targets     []Target
	RequestedBy string
}

// NewJobRequestedEvent creates a new scan job requested event.
func NewJobRequestedEvent(jobID uuid.UUID, targets []Target, requestedBy string) JobRequestedEvent {
	return JobRequestedEvent{
		jobID:       jobID,
		occurredAt:  time.Now(),
		Targets:     targets,
		RequestedBy: requestedBy,
	}
}

func (e JobRequestedEvent) EventType() events.EventType { return EventTypeJobRequested }
func (e JobRequestedEvent) OccurredAt() time.Time       { return e.occurredAt }
func (e JobRequestedEvent) JobID() uuid.UUID            { return e.jobID }

// JobScheduledEvent signals that a new ScanJob was initialized.
type JobScheduledEvent struct {
	occurredAt time.Time
	JobID      uuid.UUID
	Target     Target
}

// NewJobScheduledEvent creates a new scan job scheduled event.
func NewJobScheduledEvent(jobID uuid.UUID, target Target) JobScheduledEvent {
	return JobScheduledEvent{
		occurredAt: time.Now(),
		JobID:      jobID,
		Target:     target,
	}
}

func (e JobScheduledEvent) EventType() events.EventType { return EventTypeJobScheduled }
func (e JobScheduledEvent) OccurredAt() time.Time       { return e.occurredAt }

// JobEnumerationCompletedEvent signals that all targets for a job have been enumerated.
type JobEnumerationCompletedEvent struct {
	occurredAt time.Time
	JobID      uuid.UUID
	TotalTasks int
}

// NewJobEnumerationCompletedEvent creates a new job enumeration completed event.
func NewJobEnumerationCompletedEvent(jobID uuid.UUID, totalTasks int) JobEnumerationCompletedEvent {
	return JobEnumerationCompletedEvent{
		occurredAt: time.Now(),
		JobID:      jobID,
		TotalTasks: totalTasks,
	}
}

func (e JobEnumerationCompletedEvent) EventType() events.EventType {
	return EventTypeJobEnumerationCompleted
}
func (e JobEnumerationCompletedEvent) OccurredAt() time.Time { return e.occurredAt }

// ScanTargetsDiscoveredEvent is emitted when enumeration discovers new scan targets
// JobCompletedEvent means the job finished scanning successfully.
type JobCompletedEvent struct {
	occurredAt  time.Time
	JobID       string
	CompletedAt time.Time // or store how many tasks, how long, etc.
}

// NewJobCompletedEvent creates a new scan job completed event.
func NewJobCompletedEvent(jobID string) JobCompletedEvent {
	return JobCompletedEvent{
		occurredAt:  time.Now(),
		JobID:       jobID,
		CompletedAt: time.Now(),
	}
}

func (e JobCompletedEvent) EventType() events.EventType { return EventTypeJobCompleted }
func (e JobCompletedEvent) OccurredAt() time.Time       { return e.occurredAt }

// JobFailedEvent means the job encountered an unrecoverable error.
type JobFailedEvent struct {
	occurredAt time.Time
	JobID      string
	Reason     string
}

// NewJobFailedEvent creates a new scan job failed event.
func NewJobFailedEvent(jobID, reason string) JobFailedEvent {
	return JobFailedEvent{
		occurredAt: time.Now(),
		JobID:      jobID,
		Reason:     reason,
	}
}

func (e JobFailedEvent) EventType() events.EventType { return EventTypeJobFailed }
func (e JobFailedEvent) OccurredAt() time.Time       { return e.occurredAt }

// JobPausingEvent signals that a job is in the process of pausing.
type JobPausingEvent struct {
	occurredAt  time.Time
	JobID       string
	RequestedBy string
}

// NewJobPausingEvent creates a new job pausing event.
func NewJobPausingEvent(jobID, requestedBy string) JobPausingEvent {
	return JobPausingEvent{
		occurredAt:  time.Now(),
		JobID:       jobID,
		RequestedBy: requestedBy,
	}
}

func (e JobPausingEvent) EventType() events.EventType { return EventTypeJobPausing }
func (e JobPausingEvent) OccurredAt() time.Time       { return e.occurredAt }

// JobPausedEvent signals that a job has been successfully paused.
type JobPausedEvent struct {
	occurredAt  time.Time
	JobID       string
	PausedAt    time.Time
	Reason      string
	RequestedBy string
}

// NewJobPausedEvent creates a new job paused event.
func NewJobPausedEvent(jobID, requestedBy, reason string) JobPausedEvent {
	now := time.Now()
	return JobPausedEvent{
		occurredAt:  now,
		JobID:       jobID,
		PausedAt:    now,
		Reason:      reason,
		RequestedBy: requestedBy,
	}
}

func (e JobPausedEvent) EventType() events.EventType { return EventTypeJobPaused }
func (e JobPausedEvent) OccurredAt() time.Time       { return e.occurredAt }

// JobResumingEvent signals that a job is in the process of resuming.
type JobResumingEvent struct {
	occurredAt  time.Time
	JobID       string
	RequestedBy string
}

// NewJobResumingEvent creates a new job resuming event.
func NewJobResumingEvent(jobID, requestedBy string) JobResumingEvent {
	return JobResumingEvent{
		occurredAt:  time.Now(),
		JobID:       jobID,
		RequestedBy: requestedBy,
	}
}

func (e JobResumingEvent) EventType() events.EventType { return EventTypeJobResuming }
func (e JobResumingEvent) OccurredAt() time.Time       { return e.occurredAt }

// JobCancellingEvent signals that a job is in the process of cancelling.
type JobCancellingEvent struct {
	occurredAt  time.Time
	JobID       string
	RequestedBy string
}

// NewJobCancellingEvent creates a new job cancelling event.
func NewJobCancellingEvent(jobID, requestedBy string) JobCancellingEvent {
	return JobCancellingEvent{
		occurredAt:  time.Now(),
		JobID:       jobID,
		RequestedBy: requestedBy,
	}
}

func (e JobCancellingEvent) EventType() events.EventType { return EventTypeJobCancelling }
func (e JobCancellingEvent) OccurredAt() time.Time       { return e.occurredAt }

// JobCancelledEvent signals that a job has been successfully cancelled.
type JobCancelledEvent struct {
	occurredAt  time.Time
	JobID       string
	CancelledAt time.Time
	Reason      string
	RequestedBy string
}

// NewJobCancelledEvent creates a new job cancelled event.
func NewJobCancelledEvent(jobID, requestedBy, reason string) JobCancelledEvent {
	now := time.Now()
	return JobCancelledEvent{
		occurredAt:  now,
		JobID:       jobID,
		CancelledAt: now,
		Reason:      reason,
		RequestedBy: requestedBy,
	}
}

func (e JobCancelledEvent) EventType() events.EventType { return EventTypeJobCancelled }
func (e JobCancelledEvent) OccurredAt() time.Time       { return e.occurredAt }
