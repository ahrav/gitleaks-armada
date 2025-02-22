package scanning

import (
	"time"

	"github.com/google/uuid"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
)

// Event types relevant to Jobs:
const (
	EventTypeJobRequested events.EventType = "JobRequested"

	EventTypeJobCreated              events.EventType = "JobCreated"
	EventTypeJobCompleted            events.EventType = "JobCompleted"
	EventTypeJobFailed               events.EventType = "JobFailed"
	EventTypeJobEnumerationCompleted events.EventType = "JobEnumerationCompleted"
	// TODO: Add EventTypeJobCancelled, etc.
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

// JobCreatedEvent signals that a new ScanJob was initialized.
type JobCreatedEvent struct {
	occurredAt time.Time
	JobID      uuid.UUID
	Target     Target
}

// NewJobCreatedEvent creates a new scan job created event.
func NewJobCreatedEvent(jobID uuid.UUID, target Target) JobCreatedEvent {
	return JobCreatedEvent{
		occurredAt: time.Now(),
		JobID:      jobID,
		Target:     target,
	}
}

func (e JobCreatedEvent) EventType() events.EventType { return EventTypeJobCreated }
func (e JobCreatedEvent) OccurredAt() time.Time       { return e.occurredAt }

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
