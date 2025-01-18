package enumeration

import (
	"time"

	"github.com/google/uuid"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
)

const (
	EventTypeTaskCreated events.EventType = "TaskCreated"
)

// --------------------------
// 1. TaskCreatedEvent
// --------------------------

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
