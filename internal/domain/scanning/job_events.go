package scanning

import (
	"time"

	"github.com/google/uuid"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
)

// Event types relevant to Jobs:
const (
	EventTypeJobRequested events.EventType = "JobRequested"

	EventTypeJobCreated   events.EventType = "JobCreated"
	EventTypeJobCompleted events.EventType = "JobCompleted"
	EventTypeJobFailed    events.EventType = "JobFailed"
	// TODO: Add EventTypeJobCancelled, etc.
)

// JobRequestedEvent represents the event generated when a scan job is requested.
type JobRequestedEvent struct {
	id          string
	occurredAt  time.Time
	Targets     []Target
	Auth        map[string]Auth
	RequestedBy string
}

// NewJobRequestedEvent creates a new scan job requested event.
func NewJobRequestedEvent(targets []Target, auth map[string]Auth, requestedBy string) JobRequestedEvent {
	return JobRequestedEvent{
		id:          uuid.New().String(),
		occurredAt:  time.Now(),
		Targets:     targets,
		Auth:        auth,
		RequestedBy: requestedBy,
	}
}

func (e JobRequestedEvent) EventType() events.EventType { return EventTypeJobRequested }
func (e JobRequestedEvent) OccurredAt() time.Time       { return e.occurredAt }
func (e JobRequestedEvent) EventID() string             { return e.id }

// JobCreatedEvent signals that a new ScanJob was initialized.
type JobCreatedEvent struct {
	occurredAt time.Time
	JobID      string
	Target     Target
	Auth       Auth
}

// NewJobCreatedEvent creates a new scan job created event.
func NewJobCreatedEvent(jobID string, target Target, auth Auth) JobCreatedEvent {
	return JobCreatedEvent{
		occurredAt: time.Now(),
		JobID:      jobID,
		Target:     target,
		Auth:       auth,
	}
}

func (e JobCreatedEvent) EventType() events.EventType { return EventTypeJobCreated }
func (e JobCreatedEvent) OccurredAt() time.Time       { return e.occurredAt }

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
