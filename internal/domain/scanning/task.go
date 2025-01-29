package scanning

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
)

// Progress represents a point-in-time status update from a scanner. It provides
// detailed metrics about the current scanning progress without maintaining task state.
type Progress struct {
	taskID          uuid.UUID
	sequenceNum     int64
	timestamp       time.Time
	itemsProcessed  int64
	errorCount      int32
	message         string
	progressDetails json.RawMessage
	checkpoint      *Checkpoint
}

// NewProgress creates a new Progress instance for tracking scan progress.
// It establishes initial state for resuming interrupted scans.
func NewProgress(
	taskID uuid.UUID,
	sequenceNum int64,
	timestamp time.Time,
	itemsProcessed int64,
	errorCount int32,
	message string,
	progressDetails json.RawMessage,
	checkpoint *Checkpoint,
) Progress {
	return Progress{
		taskID:          taskID,
		sequenceNum:     sequenceNum,
		timestamp:       timestamp,
		itemsProcessed:  itemsProcessed,
		errorCount:      errorCount,
		message:         message,
		progressDetails: progressDetails,
		checkpoint:      checkpoint,
	}
}

// ReconstructProgress creates a Progress instance from persisted data.
// This should only be used by repositories when reconstructing from storage.
func ReconstructProgress(
	taskID uuid.UUID,
	sequenceNum int64,
	timestamp time.Time,
	itemsProcessed int64,
	errorCount int32,
	message string,
	progressDetails json.RawMessage,
	checkpoint *Checkpoint,
) Progress {
	return Progress{
		taskID:          taskID,
		sequenceNum:     sequenceNum,
		timestamp:       timestamp,
		itemsProcessed:  itemsProcessed,
		errorCount:      errorCount,
		message:         message,
		progressDetails: progressDetails,
		checkpoint:      checkpoint,
	}
}

// TaskID returns the unique identifier for this scan task.
func (p Progress) TaskID() uuid.UUID { return p.taskID }

// SequenceNum returns the sequence number of this progress update.
func (p Progress) SequenceNum() int64 { return p.sequenceNum }

// Timestamp returns the time the progress update was created.
func (p Progress) Timestamp() time.Time { return p.timestamp }

// ItemsProcessed returns the total number of items scanned by this task.
func (p Progress) ItemsProcessed() int64 { return p.itemsProcessed }

// ErrorCount returns the number of errors encountered by this task.
func (p Progress) ErrorCount() int32                { return p.errorCount }
func (p Progress) Message() string                  { return p.message }
func (p Progress) ProgressDetails() json.RawMessage { return p.progressDetails }
func (p Progress) Checkpoint() *Checkpoint          { return p.checkpoint }

// Checkpoint contains the state needed to resume a scan after interruption.
// This enables fault tolerance by preserving progress markers and context.
type Checkpoint struct {
	taskID      uuid.UUID
	timestamp   time.Time
	resumeToken []byte
	metadata    map[string]string
}

// NewCheckpoint creates a new Checkpoint for tracking scan progress.
// It establishes initial state for resuming interrupted scans.
func NewCheckpoint(
	taskID uuid.UUID,
	resumeToken []byte,
	metadata map[string]string,
) *Checkpoint {
	return &Checkpoint{
		taskID:      taskID,
		timestamp:   time.Now(),
		resumeToken: resumeToken,
		metadata:    metadata,
	}
}

// ReconstructCheckpoint creates a Checkpoint instance from persisted data.
// This should only be used by repositories when reconstructing from storage.
func ReconstructCheckpoint(
	taskID uuid.UUID,
	timestamp time.Time,
	resumeToken []byte,
	metadata map[string]string,
) *Checkpoint {
	return &Checkpoint{
		taskID:      taskID,
		timestamp:   timestamp,
		resumeToken: resumeToken,
		metadata:    metadata,
	}
}

// TaskID returns the unique identifier for this scan task.
func (c *Checkpoint) TaskID() uuid.UUID { return c.taskID }

// Timestamp returns the time the checkpoint was created.
func (c *Checkpoint) Timestamp() time.Time { return c.timestamp }

// ResumeToken returns the token used to resume a scan after interruption.
func (c *Checkpoint) ResumeToken() []byte { return c.resumeToken }

// Metadata returns any additional metadata associated with this checkpoint.
func (c *Checkpoint) Metadata() map[string]string { return c.metadata }

// MarshalJSON serializes the Checkpoint object into a JSON byte array.
func (c *Checkpoint) MarshalJSON() ([]byte, error) {
	// Defensive: if c is nil, return JSON "null" (or error, depending on preference)
	if c == nil {
		return []byte("null"), nil
	}

	// Define an inner type to avoid infinite recursion of MarshalJSON.
	type checkpointDTO struct {
		TaskID      string            `json:"task_id"`
		Timestamp   time.Time         `json:"timestamp"`
		ResumeToken []byte            `json:"resume_token"`
		Metadata    map[string]string `json:"metadata"`
	}

	dto := checkpointDTO{
		TaskID:      c.taskID.String(), // zero-value UUID -> "00000000-0000-0000-0000-000000000000"
		Timestamp:   c.timestamp,
		ResumeToken: c.resumeToken,
		Metadata:    c.metadata,
	}

	return json.Marshal(&dto)
}

// UnmarshalJSON deserializes JSON data into a Checkpoint object.
func (c *Checkpoint) UnmarshalJSON(data []byte) error {
	// Defensive: if c is nil, we can't populate it
	if c == nil {
		return fmt.Errorf("cannot unmarshal JSON into nil Checkpoint")
	}

	// Matching DTO for reading JSON
	type checkpointDTO struct {
		TaskID      string            `json:"task_id"`
		Timestamp   time.Time         `json:"timestamp"`
		ResumeToken []byte            `json:"resume_token"`
		Metadata    map[string]string `json:"metadata"`
	}

	var aux checkpointDTO
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	taskID, err := uuid.Parse(aux.TaskID)
	if err != nil {
		return fmt.Errorf("invalid task ID: %w", err)
	}

	c.taskID = taskID
	c.timestamp = aux.Timestamp
	c.resumeToken = aux.ResumeToken
	c.metadata = aux.Metadata

	return nil
}

// TaskStatus represents the execution state of an individual scan task. It enables
// fine-grained tracking of task progress and error conditions.
type TaskStatus string

// ErrTaskStatusUnknown is returned when a task status is unknown.
var ErrTaskStatusUnknown = errors.New("task status unknown")

const (
	// TaskStatusPending indicates a task is created but not yet started.
	TaskStatusPending TaskStatus = "PENDING"

	// TaskStatusInProgress indicates a task is actively scanning.
	TaskStatusInProgress TaskStatus = "IN_PROGRESS"

	// TaskStatusCompleted indicates a task finished successfully.
	TaskStatusCompleted TaskStatus = "COMPLETED"

	// TaskStatusFailed indicates a task encountered an unrecoverable error.
	TaskStatusFailed TaskStatus = "FAILED"

	// TaskStatusStale indicates a task stopped reporting progress and may need recovery.
	TaskStatusStale TaskStatus = "STALE"

	// TaskStatusUnspecified is used when a task status is unknown.
	TaskStatusUnspecified TaskStatus = "UNSPECIFIED"
)

// StallReason identifies the specific cause of a task stall, enabling targeted recovery strategies.
type StallReason string

const (
	// StallReasonNoProgress indicates the task has stopped sending progress updates.
	StallReasonNoProgress StallReason = "NO_PROGRESS"

	// StallReasonLowThroughput indicates the task's processing rate has fallen below acceptable thresholds.
	StallReasonLowThroughput StallReason = "LOW_THROUGHPUT"

	// StallReasonHighErrors indicates the task has exceeded error thresholds and requires intervention.
	StallReasonHighErrors StallReason = "HIGH_ERRORS"
)

// Task tracks the full lifecycle and state of an individual scanning operation.
// It maintains historical progress data and enables task recovery and monitoring.
type Task struct {
	shared.CoreTask
	jobID uuid.UUID

	resourceURI string

	status           TaskStatus
	stallReason      *StallReason
	stalledAt        time.Time
	recoveryAttempts int // Track number of times task has recovered from STALE state

	lastSequenceNum int64
	lastHeartbeatAt time.Time
	timeline        *Timeline

	itemsProcessed  int64
	progressDetails json.RawMessage
	lastCheckpoint  *Checkpoint
}

// TaskOption defines functional options for configuring a new Task.
type TaskOption func(*Task)

// WithTimeProvider sets a custom time provider for the task.
func WithTimeProvider(tp TimeProvider) TaskOption {
	return func(t *Task) { t.timeline = NewTimeline(tp) }
}

// NewScanTask creates a new ScanTask instance for tracking an individual scan operation.
// It establishes the task's relationship to its parent job and initializes monitoring state.
func NewScanTask(jobID uuid.UUID, taskID uuid.UUID, resourceURI string, opts ...TaskOption) *Task {
	task := &Task{
		CoreTask: shared.CoreTask{
			ID: taskID,
		},
		jobID:           jobID,
		resourceURI:     resourceURI,
		status:          TaskStatusPending,
		timeline:        NewTimeline(new(realTimeProvider)),
		lastSequenceNum: 0,
	}

	for _, opt := range opts {
		opt(task)
	}

	return task
}

// ReconstructTask creates a Task instance from persisted data without enforcing
// creation-time invariants. This should only be used by repositories when
// reconstructing from storage.
func ReconstructTask(
	taskID uuid.UUID,
	jobID uuid.UUID,
	resourceURI string,
	status TaskStatus,
	lastSequenceNum int64,
	lastHeartbeatAt time.Time,
	startTime time.Time,
	endTime time.Time,
	itemsProcessed int64,
	progressDetails json.RawMessage,
	lastCheckpoint *Checkpoint,
	stallReason *StallReason,
	stalledAt time.Time,
	recoveryAttempts int,
) *Task {
	return &Task{
		CoreTask: shared.CoreTask{
			ID: taskID,
		},
		jobID:            jobID,
		resourceURI:      resourceURI,
		status:           status,
		lastSequenceNum:  lastSequenceNum,
		lastHeartbeatAt:  lastHeartbeatAt,
		timeline:         ReconstructTimeline(startTime, endTime, time.Time{}),
		itemsProcessed:   itemsProcessed,
		progressDetails:  progressDetails,
		lastCheckpoint:   lastCheckpoint,
		stallReason:      stallReason,
		stalledAt:        stalledAt,
		recoveryAttempts: recoveryAttempts,
	}
}

// JobID returns the identifier of the parent job containing this task.
func (t *Task) JobID() uuid.UUID { return t.jobID }

// Status returns the current execution status of the scan task.
func (t *Task) Status() TaskStatus { return t.status }

// ResourceURI returns the URI of the resource being scanned.
func (t *Task) ResourceURI() string { return t.resourceURI }

// LastSequenceNum returns the sequence number of the most recent progress update.
func (t *Task) LastSequenceNum() int64 { return t.lastSequenceNum }

// LastHeartbeatAt returns the time the task last reported progress.
func (t *Task) LastHeartbeatAt() time.Time { return t.lastHeartbeatAt }

// ItemsProcessed returns the total number of items scanned by this task.
func (t *Task) ItemsProcessed() int64 { return t.itemsProcessed }

// TaskID returns the unique identifier for this scan task.
func (t *Task) TaskID() uuid.UUID { return t.ID }

func (t *Task) LastCheckpoint() *Checkpoint { return t.lastCheckpoint }

func (t *Task) ProgressDetails() []byte { return t.progressDetails }

// StartTime returns the time the task was started.
func (t *Task) StartTime() time.Time { return t.timeline.StartedAt() }

// EndTime returns when this task last reported progress.
func (t *Task) EndTime() time.Time { return t.timeline.CompletedAt() }

// LastUpdate returns the time this task was last updated.
func (t *Task) LastUpdate() time.Time { return t.timeline.LastUpdate() }

// StallReason returns the reason this task is stalled.
func (t *Task) StallReason() *StallReason { return t.stallReason }

// StalledAt returns the time this task was stalled.
func (t *Task) StalledAt() time.Time { return t.stalledAt }

// StalledDuration returns the duration this task has been stalled.
func (t *Task) StalledDuration() time.Duration {
	if t.stalledAt.IsZero() {
		return 0
	}
	return time.Since(t.stalledAt)
}

// RecoveryAttempts returns the number of times this task has recovered from a stale state
func (t *Task) RecoveryAttempts() int { return t.recoveryAttempts }

// IsInProgress returns true if the task is in the IN_PROGRESS state.
func (t *Task) IsInProgress() bool { return t.status == TaskStatusInProgress }

// OutOfOrderProgressError is an error type for indicating that a progress update
// is out of order and should be ignored.
type OutOfOrderProgressError struct {
	taskID     uuid.UUID
	seqNum     int64
	lastSeqNum int64
}

// NewOutOfOrderProgressError creates a new OutOfOrderProgressError.
func NewOutOfOrderProgressError(taskID uuid.UUID, seqNum, lastSeqNum int64) *OutOfOrderProgressError {
	return &OutOfOrderProgressError{
		taskID:     taskID,
		seqNum:     seqNum,
		lastSeqNum: lastSeqNum,
	}
}

// Error returns a string representation of the error.
func (e *OutOfOrderProgressError) Error() string {
	return fmt.Sprintf("out of order progress update for task %s: sequence number %d is less than or equal to the last sequence number %d", e.taskID, e.seqNum, e.lastSeqNum)
}

// ApplyProgress applies a progress update to this task's state.
// It updates all monitoring metrics and preserves any checkpoint data.
func (t *Task) ApplyProgress(progress Progress) error {
	if t.status != TaskStatusInProgress && t.status != TaskStatusStale && t.status != TaskStatusPending {
		return TaskInvalidStateError{
			taskID: t.ID,
			status: t.status,
			reason: TaskInvalidStateReasonWrongStatus,
		}
	}

	if !t.isSeqNumValid(progress) {
		return NewOutOfOrderProgressError(t.TaskID(), progress.SequenceNum(), t.LastSequenceNum())
	}

	// If task is in pending state, transition to in progress.
	if t.status == TaskStatusPending {
		t.status = TaskStatusInProgress
		t.timeline.MarkStarted()
	}

	t.updateProgress(progress)
	return nil
}

func (t *Task) isSeqNumValid(progress Progress) bool {
	return progress.SequenceNum() > t.lastSequenceNum
}

// updateProgress applies a progress update to this task's state.
// It updates all monitoring metrics and preserves any checkpoint data.
func (t *Task) updateProgress(progress Progress) {
	// If task was previously stale, record recovery and reset stale-related fields.
	// TODO: Consider setting a threshold for recovery attempts.
	if t.status == TaskStatusStale {
		t.recoveryAttempts++
		t.status = TaskStatusInProgress
		t.ClearStall()
	}

	t.lastSequenceNum = progress.SequenceNum()
	t.timeline.UpdateLastUpdate()
	t.itemsProcessed += progress.ItemsProcessed()
	t.progressDetails = progress.ProgressDetails()

	if progress.Checkpoint() != nil {
		t.lastCheckpoint = progress.Checkpoint()
	}
}

// TaskInvalidStateError is an error type for indicating that a task is in an invalid state.
type TaskInvalidStateError struct {
	taskID uuid.UUID
	status TaskStatus
	reason TaskInvalidStateReason
}

// TaskInvalidStateReason represents the specific reason why a task state is invalid
type TaskInvalidStateReason string

const (
	// TaskInvalidStateReasonWrongStatus indicates the task is not in the correct status for the operation
	TaskInvalidStateReasonWrongStatus TaskInvalidStateReason = "WRONG_STATUS"

	// TaskInvalidStateReasonNoProgress indicates the task hasn't processed any items
	TaskInvalidStateReasonNoProgress TaskInvalidStateReason = "NO_PROGRESS"

	// TaskInvalidStateReasonNoReason indicates the task is in the STALE state but no reason is provided
	TaskInvalidStateReasonNoReason TaskInvalidStateReason = "NO_REASON"
)

// ReasonPtr returns a pointer to a StallReason.
func ReasonPtr(r StallReason) *StallReason { return &r }

// Error returns a string representation of the error.
func (e TaskInvalidStateError) Error() string {
	return fmt.Sprintf("task %s is in invalid state %s: %s", e.taskID, e.status, e.reason)
}

// Reason returns the specific reason for the invalid state
func (e TaskInvalidStateError) Reason() TaskInvalidStateReason { return e.reason }

// Complete marks a task as completed.
func (t *Task) Complete() error {
	if t.status == TaskStatusCompleted {
		return nil // Already completed, idempotent
	}

	// TODO: Figure out if we not include pending here.
	// It's included becaasue realy short scans never transition to IN_PROGRESS b/c we get not progress updates.
	// At leat not yet for Git based sources.
	if t.status != TaskStatusInProgress && t.status != TaskStatusStale && t.status != TaskStatusPending {
		return TaskInvalidStateError{
			taskID: t.ID,
			status: t.status,
			reason: TaskInvalidStateReasonWrongStatus,
		}
	}

	// t.ClearStall()

	// TODO: Uncomment once progress is tracked in source scanners.
	// if t.itemsProcessed == 0 {
	// 	return TaskInvalidStateError{
	// 		taskID: t.ID,
	// 		status: t.status,
	// 		reason: TaskInvalidStateReasonNoProgress,
	// 	}
	// }

	t.status = TaskStatusCompleted
	t.timeline.MarkCompleted()
	return nil
}

func (t *Task) ClearStall() {
	t.stallReason = nil
	t.stalledAt = time.Time{}
}

// Fail marks a task as failed.
func (t *Task) Fail() error {
	if t.status != TaskStatusInProgress && t.status != TaskStatusStale {
		return TaskInvalidStateError{
			taskID: t.ID,
			status: t.status,
			reason: TaskInvalidStateReasonWrongStatus,
		}
	}

	t.status = TaskStatusFailed
	t.timeline.MarkCompleted()
	return nil
}

// MarkStale transitions a task from IN_PROGRESS to STALE, storing a reason and time.
// The task must be in IN_PROGRESS state to be marked as STALE and a reason must be provided.
func (t *Task) MarkStale(reason *StallReason) error {
	if t.status != TaskStatusInProgress {
		return TaskInvalidStateError{
			taskID: t.ID,
			status: t.status,
			reason: TaskInvalidStateReasonWrongStatus,
		}
	}

	if reason == nil {
		return TaskInvalidStateError{
			taskID: t.ID,
			status: t.status,
			reason: TaskInvalidStateReasonNoReason,
		}
	}

	t.status = TaskStatusStale
	t.stallReason = reason
	t.stalledAt = time.Now()

	return nil
}

// GetSummary returns a TaskSummary containing the key metrics and status
// for this task's execution progress.
func (t *Task) GetSummary(duration time.Duration) TaskSummary {
	return TaskSummary{
		taskID:          t.ID,
		status:          t.status,
		itemsProcessed:  t.itemsProcessed,
		duration:        duration,
		lastUpdateTs:    t.timeline.LastUpdate(),
		progressDetails: t.progressDetails,
	}
}

// TaskSummary provides a concise view of task execution progress.
// It contains the key metrics needed for monitoring task health and completion.
type TaskSummary struct {
	taskID          uuid.UUID
	status          TaskStatus
	itemsProcessed  int64
	duration        time.Duration
	lastUpdateTs    time.Time
	progressDetails json.RawMessage
}

// GetTaskID returns the unique identifier for this scan task.
func (s TaskSummary) GetTaskID() uuid.UUID { return s.taskID }

// GetStatus returns the current execution status of the scan task.
func (s TaskSummary) GetStatus() TaskStatus { return s.status }

// GetLastUpdateTimestamp returns when this task last reported progress.
func (s TaskSummary) GetLastUpdateTimestamp() time.Time { return s.lastUpdateTs }
