package scanning

import (
	"time"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
)

// Event types relevant to Jobs:
const (
	EventTypeJobCreated   events.EventType = "JobCreated"
	EventTypeJobStarted   events.EventType = "JobStarted"
	EventTypeJobCompleted events.EventType = "JobCompleted"
	EventTypeJobFailed    events.EventType = "JobFailed"
	// TODO: Add EventTypeJobCancelled, etc.
)

// --------------------------
// 1. JobCreatedEvent
// --------------------------

// JobCreatedEvent signals that a new ScanJob was initialized.
type JobCreatedEvent struct {
	occurredAt time.Time
	JobID      string
}

func NewJobCreatedEvent(jobID string) JobCreatedEvent {
	return JobCreatedEvent{
		occurredAt: time.Now(),
		JobID:      jobID,
	}
}

func (e JobCreatedEvent) EventType() events.EventType { return EventTypeJobCreated }

func (e JobCreatedEvent) OccurredAt() time.Time { return e.occurredAt }

// --------------------------
// 2. JobStartedEvent
// --------------------------

// JobStartedEvent indicates the job has moved from INITIALIZED -> IN_PROGRESS.
type JobStartedEvent struct {
	occurredAt time.Time
	JobID      string
}

func NewJobStartedEvent(jobID string) JobStartedEvent {
	return JobStartedEvent{
		occurredAt: time.Now(),
		JobID:      jobID,
	}
}

func (e JobStartedEvent) EventType() events.EventType { return EventTypeJobStarted }
func (e JobStartedEvent) OccurredAt() time.Time       { return e.occurredAt }

// --------------------------
// 3. JobCompletedEvent
// --------------------------

// JobCompletedEvent means the job finished scanning successfully.
type JobCompletedEvent struct {
	occurredAt  time.Time
	JobID       string
	CompletedAt time.Time // or store how many tasks, how long, etc.
}

func NewJobCompletedEvent(jobID string) JobCompletedEvent {
	return JobCompletedEvent{
		occurredAt:  time.Now(),
		JobID:       jobID,
		CompletedAt: time.Now(),
	}
}

func (e JobCompletedEvent) EventType() events.EventType { return EventTypeJobCompleted }
func (e JobCompletedEvent) OccurredAt() time.Time       { return e.occurredAt }

// --------------------------
// 4. JobFailedEvent
// --------------------------

// JobFailedEvent means the job encountered an unrecoverable error.
type JobFailedEvent struct {
	occurredAt time.Time
	JobID      string
	Reason     string
}

func NewJobFailedEvent(jobID, reason string) JobFailedEvent {
	return JobFailedEvent{
		occurredAt: time.Now(),
		JobID:      jobID,
		Reason:     reason,
	}
}

func (e JobFailedEvent) EventType() events.EventType { return EventTypeJobFailed }
func (e JobFailedEvent) OccurredAt() time.Time       { return e.occurredAt }
