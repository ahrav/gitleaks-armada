package scanning

import (
	"time"

	"github.com/google/uuid"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
)

// Event types relevant to Tasks:
const (
	EventTypeTaskCreated    events.EventType = "TaskCreated"
	EventTypeTaskStarted    events.EventType = "TaskStarted"
	EventTypeTaskProgressed events.EventType = "TaskProgressed"
	EventTypeTaskStale      events.EventType = "TaskStale"
	EventTypeTaskResume     events.EventType = "TaskResume"
	EventTypeTaskCompleted  events.EventType = "TaskCompleted"
	EventTypeTaskFailed     events.EventType = "TaskFailed"
	EventTypeTaskHeartbeat  events.EventType = "TaskHeartbeat"
	EventTypeTaskJobMetric  events.EventType = "TaskJobMetric"
)

// TaskCreatedEvent indicates a new task was discovered and needs to be scanned
type TaskCreatedEvent struct {
	occurredAt  time.Time
	JobID       uuid.UUID
	TaskID      uuid.UUID
	SourceType  shared.SourceType
	ResourceURI string
	Metadata    map[string]string
	Auth        Auth
}

// NewTaskCreatedEvent creates a new TaskCreatedEvent.
func NewTaskCreatedEvent(
	jobID, taskID uuid.UUID,
	sourceType shared.SourceType,
	resourceURI string,
	metadata map[string]string,
	auth Auth,
) *TaskCreatedEvent {
	return &TaskCreatedEvent{
		occurredAt:  time.Now(),
		JobID:       jobID,
		TaskID:      taskID,
		SourceType:  sourceType,
		ResourceURI: resourceURI,
		Metadata:    metadata,
		Auth:        auth,
	}
}

func (e TaskCreatedEvent) EventType() events.EventType { return EventTypeTaskCreated }
func (e TaskCreatedEvent) OccurredAt() time.Time       { return e.occurredAt }

// TaskStartedEvent indicates a new task was added to a job.
type TaskStartedEvent struct {
	occurredAt  time.Time
	JobID       uuid.UUID
	TaskID      uuid.UUID
	ResourceURI string
}

func NewTaskStartedEvent(jobID, taskID uuid.UUID, resourceURI string) TaskStartedEvent {
	return TaskStartedEvent{
		occurredAt:  time.Now(),
		JobID:       jobID,
		TaskID:      taskID,
		ResourceURI: resourceURI,
	}
}

func (e TaskStartedEvent) EventType() events.EventType { return EventTypeTaskStarted }
func (e TaskStartedEvent) OccurredAt() time.Time       { return e.occurredAt }

// TaskProgressedEvent signals a new ScanProgress update was received.
type TaskProgressedEvent struct {
	occurredAt time.Time
	Progress   Progress
}

func NewTaskProgressedEvent(p Progress) TaskProgressedEvent {
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
	JobID        uuid.UUID
	TaskID       uuid.UUID
	Reason       StallReason
	StalledSince time.Time
}

func NewTaskStaleEvent(jobID, taskID uuid.UUID, reason StallReason, since time.Time) TaskStaleEvent {
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

// TaskResumeEvent means the task was resumed from a checkpoint.
type TaskResumeEvent struct {
	occurredAt  time.Time
	JobID       uuid.UUID
	TaskID      uuid.UUID
	SourceType  shared.SourceType
	ResourceURI string
	SequenceNum int
	Checkpoint  *Checkpoint
}

func NewTaskResumeEvent(
	jobID, taskID uuid.UUID,
	sourceType shared.SourceType,
	resourceURI string,
	sequenceNum int,
	checkpoint *Checkpoint,
) *TaskResumeEvent {
	return &TaskResumeEvent{
		occurredAt:  time.Now(),
		JobID:       jobID,
		TaskID:      taskID,
		SourceType:  sourceType,
		ResourceURI: resourceURI,
		SequenceNum: sequenceNum,
		Checkpoint:  checkpoint,
	}
}

func (e TaskResumeEvent) EventType() events.EventType { return EventTypeTaskResume }
func (e TaskResumeEvent) OccurredAt() time.Time       { return e.occurredAt }

// TaskCompletedEvent means the task is done scanning successfully.
type TaskCompletedEvent struct {
	occurredAt time.Time
	JobID      uuid.UUID
	TaskID     uuid.UUID
}

func NewTaskCompletedEvent(jobID, taskID uuid.UUID) TaskCompletedEvent {
	return TaskCompletedEvent{
		occurredAt: time.Now(),
		JobID:      jobID,
		TaskID:     taskID,
	}
}

func (e TaskCompletedEvent) EventType() events.EventType { return EventTypeTaskCompleted }
func (e TaskCompletedEvent) OccurredAt() time.Time       { return e.occurredAt }

// TaskFailedEvent means the task encountered a failure it can't recover from.
type TaskFailedEvent struct {
	occurredAt time.Time
	JobID      uuid.UUID
	TaskID     uuid.UUID
	Reason     string
}

func NewTaskFailedEvent(jobID, taskID uuid.UUID, reason string) TaskFailedEvent {
	return TaskFailedEvent{
		occurredAt: time.Now(),
		JobID:      jobID,
		TaskID:     taskID,
		Reason:     reason,
	}
}

func (e TaskFailedEvent) EventType() events.EventType { return EventTypeTaskFailed }
func (e TaskFailedEvent) OccurredAt() time.Time       { return e.occurredAt }

// TaskHeartbeatEvent signals that a task is still alive and processing
type TaskHeartbeatEvent struct {
	occurredAt time.Time
	TaskID     uuid.UUID
}

func NewTaskHeartbeatEvent(taskID uuid.UUID) TaskHeartbeatEvent {
	return TaskHeartbeatEvent{
		occurredAt: time.Now(),
		TaskID:     taskID,
	}
}

func (e TaskHeartbeatEvent) EventType() events.EventType { return EventTypeTaskHeartbeat }
func (e TaskHeartbeatEvent) OccurredAt() time.Time       { return e.occurredAt }

// TaskJobMetricEvent represents a task status change for job metrics tracking.
type TaskJobMetricEvent struct {
	occurredAt time.Time
	JobID      uuid.UUID
	TaskID     uuid.UUID
	Status     TaskStatus
}

func NewTaskJobMetricEvent(jobID, taskID uuid.UUID, status TaskStatus) TaskJobMetricEvent {
	return TaskJobMetricEvent{
		occurredAt: time.Now(),
		JobID:      jobID,
		TaskID:     taskID,
		Status:     status,
	}
}

func (e TaskJobMetricEvent) EventType() events.EventType { return EventTypeTaskJobMetric }
func (e TaskJobMetricEvent) OccurredAt() time.Time       { return e.occurredAt }
