package scanning

import (
	"time"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
)

// Event types relevant to Tasks:
const (
	EventTypeTaskStarted    events.EventType = "TaskStarted"
	EventTypeTaskProgressed events.EventType = "TaskProgressed"
	EventTypeTaskStale      events.EventType = "TaskStale"
	EventTypeTaskCompleted  events.EventType = "TaskCompleted"
	EventTypeTaskFailed     events.EventType = "TaskFailed"
)

// TaskStartedEvent indicates a new task was added to a job.
type TaskStartedEvent struct {
	occurredAt time.Time
	JobID      string
	TaskID     string
}

func NewTaskStartedEvent(jobID, taskID string) TaskStartedEvent {
	return TaskStartedEvent{
		occurredAt: time.Now(),
		JobID:      jobID,
		TaskID:     taskID,
	}
}

func (e TaskStartedEvent) EventType() events.EventType { return EventTypeTaskStarted }
func (e TaskStartedEvent) OccurredAt() time.Time       { return e.occurredAt }

// TaskProgressedEvent signals a new ScanProgress update was received.
type TaskProgressedEvent struct {
	occurredAt time.Time
	Progress   ScanProgress
}

func NewTaskProgressedEvent(p ScanProgress) TaskProgressedEvent {
	return TaskProgressedEvent{
		occurredAt: time.Now(),
		Progress:   p,
	}
}

func (e TaskProgressedEvent) EventType() events.EventType { return EventTypeTaskProgressed }
func (e TaskProgressedEvent) OccurredAt() time.Time       { return e.occurredAt }

// TaskStaleEvent means the task was marked STALE (e.g., no progress updates).
type TaskStaleEvent struct {
	occurredAt   time.Time
	JobID        string
	TaskID       string
	Reason       StallReason
	StalledSince time.Time
}

func NewTaskStaleEvent(jobID, taskID string, reason StallReason, since time.Time) TaskStaleEvent {
	return TaskStaleEvent{
		occurredAt:   time.Now(),
		JobID:        jobID,
		TaskID:       taskID,
		Reason:       reason,
		StalledSince: since,
	}
}

func (e TaskStaleEvent) EventType() events.EventType { return EventTypeTaskStale }
func (e TaskStaleEvent) OccurredAt() time.Time       { return e.occurredAt }

// TaskCompletedEvent means the task is done scanning successfully.
type TaskCompletedEvent struct {
	occurredAt time.Time
	JobID      string
	TaskID     string
}

func NewTaskCompletedEvent(jobID, taskID string) TaskCompletedEvent {
	return TaskCompletedEvent{
		occurredAt: time.Now(),
		JobID:      jobID,
		TaskID:     taskID,
	}
}

func (e TaskCompletedEvent) EventType() events.EventType { return EventTypeTaskCompleted }
func (e TaskCompletedEvent) OccurredAt() time.Time       { return e.occurredAt }

// TaskFailedEvent means the task encountered a failure it can’t recover from.
type TaskFailedEvent struct {
	occurredAt time.Time
	JobID      string
	TaskID     string
	Reason     string
}

func NewTaskFailedEvent(jobID, taskID, reason string) TaskFailedEvent {
	return TaskFailedEvent{
		occurredAt: time.Now(),
		JobID:      jobID,
		TaskID:     taskID,
		Reason:     reason,
	}
}

func (e TaskFailedEvent) EventType() events.EventType { return EventTypeTaskFailed }
func (e TaskFailedEvent) OccurredAt() time.Time       { return e.occurredAt }
