package task

import (
	"time"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
)

const (
	EventTypeTaskCreated      events.EventType = "TaskCreated"
	EventTypeTaskBatchCreated events.EventType = "TaskBatchCreated"
)

// --------------------------
// 1. TaskCreatedEvent
// --------------------------

// TaskCreatedEvent is a strongly typed domain event indicating that a single Task
// has been created. It references the actual Task struct from this package.
type TaskCreatedEvent struct {
	occurredAt time.Time
	Task       Task
}

// NewTaskCreatedEvent constructs a TaskCreatedEvent, capturing the current time
// and embedding the new Task as part of the event payload.
func NewTaskCreatedEvent(t Task) TaskCreatedEvent {
	return TaskCreatedEvent{
		occurredAt: time.Now(),
		Task:       t,
	}
}

// EventType satisfies the events.DomainEvent interface.
func (e TaskCreatedEvent) EventType() events.EventType { return EventTypeTaskCreated }

// OccurredAt satisfies the events.DomainEvent interface.
func (e TaskCreatedEvent) OccurredAt() time.Time { return e.occurredAt }

// --------------------------
// 2. TaskBatchCreatedEvent
// --------------------------

// TaskBatchCreatedEvent indicates that a batch of tasks (TaskBatch) has been created.
type TaskBatchCreatedEvent struct {
	occurredAt time.Time
	Batch      TaskBatch
}

// NewTaskBatchCreatedEvent constructs a TaskBatchCreatedEvent using the provided TaskBatch.
func NewTaskBatchCreatedEvent(b TaskBatch) TaskBatchCreatedEvent {
	return TaskBatchCreatedEvent{
		occurredAt: time.Now(),
		Batch:      b,
	}
}

// EventType maps to the enumeration for batch creation.
func (e TaskBatchCreatedEvent) EventType() events.EventType { return EventTypeTaskBatchCreated }

// OccurredAt returns when the batch was created.
func (e TaskBatchCreatedEvent) OccurredAt() time.Time { return e.occurredAt }
