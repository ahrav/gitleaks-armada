package enumeration

import (
	"time"

	"github.com/google/uuid"

	"github.com/ahrav/gitleaks-armada/internal/config"
	"github.com/ahrav/gitleaks-armada/internal/domain/events"
)

const (
	EventTypeTaskCreated events.EventType = "TaskCreated"

	// EventTypeEnumerationRequested represents the initial request to enumerate targets.
	EventTypeEnumerationRequested events.EventType = "EnumerationRequested"
)

// TaskCreatedEvent is a strongly typed domain event indicating that a single Task
// has been created. It references the actual Task struct from this package.
type TaskCreatedEvent struct {
	occurredAt time.Time
	JobID      uuid.UUID
	Task       *Task
}

// NewTaskCreatedEvent constructs a TaskCreatedEvent, capturing the current time
// and embedding the new Task as part of the event payload.
func NewTaskCreatedEvent(jobID uuid.UUID, t *Task) TaskCreatedEvent {
	return TaskCreatedEvent{
		occurredAt: time.Now(),
		JobID:      jobID,
		Task:       t,
	}
}

// EventType satisfies the events.DomainEvent interface.
func (e TaskCreatedEvent) EventType() events.EventType { return EventTypeTaskCreated }

// OccurredAt satisfies the events.DomainEvent interface.
func (e TaskCreatedEvent) OccurredAt() time.Time { return e.occurredAt }

// EnumerationRequestedEvent represents the event generated when enumeration is requested.
type EnumerationRequestedEvent struct {
	id          string
	occurredAt  time.Time
	Config      *config.Config
	RequestedBy string
}

// NewEnumerationRequestedEvent creates a new enumeration requested event.
func NewEnumerationRequestedEvent(cfg *config.Config, requestedBy string) EnumerationRequestedEvent {
	return EnumerationRequestedEvent{
		id:          uuid.New().String(),
		occurredAt:  time.Now(),
		Config:      cfg,
		RequestedBy: requestedBy,
	}
}

func (e EnumerationRequestedEvent) EventType() events.EventType { return EventTypeEnumerationRequested }
func (e EnumerationRequestedEvent) OccurredAt() time.Time       { return e.occurredAt }
func (e EnumerationRequestedEvent) EventID() string             { return e.id }
