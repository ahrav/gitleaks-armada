package scanning

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
)

// Progress represents a point-in-time status update from a scanner. It provides
// detailed metrics about the current scanning progress without maintaining task state.
type Progress struct {
	taskID          uuid.UUID
	jobID           uuid.UUID
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
	jobID uuid.UUID,
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
		jobID:           jobID,
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
	jobID uuid.UUID,
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
		jobID:           jobID,
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

// JobID returns the unique identifier for the job containing this task.
func (p Progress) JobID() uuid.UUID { return p.jobID }

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
	pausedAt         time.Time
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

	// TaskInvalidStateReasonProgressUpdateNotAllowed indicates the task is not in the correct state to accept progress updates
	TaskInvalidStateReasonProgressUpdateNotAllowed TaskInvalidStateReason = "PROGRESS_UPDATE_NOT_ALLOWED"
)

// ReasonPtr returns a pointer to a StallReason.
func ReasonPtr(r StallReason) *StallReason { return &r }

// Error returns a string representation of the error.
func (e TaskInvalidStateError) Error() string {
	return fmt.Sprintf("task %s is in invalid state %s: %s", e.taskID, e.status, e.reason)
}

// Reason returns the specific reason for the invalid state
func (e TaskInvalidStateError) Reason() TaskInvalidStateReason { return e.reason }

// NewScanTask creates a new ScanTask instance for tracking an individual scan operation.
// It establishes the task's relationship to its parent job and initializes monitoring state.
func NewScanTask(jobID uuid.UUID, sourceType shared.SourceType, taskID uuid.UUID, resourceURI string, opts ...TaskOption) *Task {
	task := &Task{
		CoreTask: shared.CoreTask{
			ID:         taskID,
			SourceType: sourceType,
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
	pausedAt time.Time,
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
		pausedAt:         pausedAt,
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

// PausedAt returns the time this task was paused.
func (t *Task) PausedAt() time.Time { return t.pausedAt }

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

// ----------------------------------------------------
// Domain-Specific Lifecycle Methods
// ----------------------------------------------------

// Start transitions from PENDING → IN_PROGRESS.
func (t *Task) Start() error { return t.UpdateStatus(TaskStatusInProgress) }

// Pause transitions from IN_PROGRESS → PAUSED.
func (t *Task) Pause() error {
	if t.status != TaskStatusInProgress {
		return TaskInvalidStateError{
			taskID: t.ID,
			status: t.status,
			reason: TaskInvalidStateReasonWrongStatus,
		}
	}
	// Domain side-effect: record pause time.
	t.pausedAt = time.Now()
	return t.UpdateStatus(TaskStatusPaused)
}

// Resume transitions from PAUSED → IN_PROGRESS.
func (t *Task) Resume() error {
	if t.status != TaskStatusPaused {
		return TaskInvalidStateError{
			taskID: t.ID,
			status: t.status,
			reason: TaskInvalidStateReasonWrongStatus,
		}
	}
	// Domain side-effect: clear pausedAt.
	t.pausedAt = time.Time{}
	return t.UpdateStatus(TaskStatusInProgress)
}

// MarkStale transitions from IN_PROGRESS → STALE.
func (t *Task) MarkStale(reason *StallReason) error {
	if reason == nil {
		return TaskInvalidStateError{
			taskID: t.ID,
			status: t.status,
			reason: TaskInvalidStateReasonNoReason,
		}
	}
	t.stallReason = reason
	t.stalledAt = time.Now()
	return t.UpdateStatus(TaskStatusStale)
}

// RecoverFromStale transitions from STALE → IN_PROGRESS.
func (t *Task) RecoverFromStale() error {
	if t.status != TaskStatusStale {
		return TaskInvalidStateError{
			taskID: t.ID,
			status: t.status,
			reason: TaskInvalidStateReasonWrongStatus,
		}
	}
	t.recoveryAttempts++
	t.clearStall()
	return t.UpdateStatus(TaskStatusInProgress)
}

// clearStall resets stall-specific fields but does not itself change the status.
func (t *Task) clearStall() {
	t.stallReason = nil
	t.stalledAt = time.Time{}
}

// Complete transitions from IN_PROGRESS (or maybe STALE) → COMPLETED.
func (t *Task) Complete() error {
	if t.status == TaskStatusCompleted {
		return nil // idempotent
	}
	// Example domain rule: must not complete if 0 items processed
	/*
		if t.itemsProcessed == 0 {
			return TaskInvalidStateError{
				taskID: t.ID,
				status: t.status,
				reason: TaskInvalidStateReasonNoProgress,
			}
		}
	*/
	return t.UpdateStatus(TaskStatusCompleted)
}

// Fail transitions from any non-terminal to FAILED.
func (t *Task) Fail() error {
	if t.status == TaskStatusFailed {
		return TaskInvalidStateError{
			taskID: t.ID,
			status: t.status,
			reason: TaskInvalidStateReasonWrongStatus,
		}
	}
	return t.UpdateStatus(TaskStatusFailed)
}

// ----------------------------------------------------
// The Single Gatekeeper for Status Transitions
// ----------------------------------------------------

// UpdateStatus changes the task's status after validating the transition.
// It runs the "gatekeeper" checks so we know if oldStatus→newStatus is allowed.
func (t *Task) UpdateStatus(newStatus TaskStatus) error {
	if err := t.status.validateTransition(newStatus); err != nil {
		return TaskInvalidStateError{
			taskID: t.ID,
			status: t.status,
			reason: TaskInvalidStateReasonWrongStatus,
		}
	}

	// Universal side effects for start/completion times:
	if t.status == TaskStatusPending && newStatus == TaskStatusInProgress {
		t.timeline.MarkStarted()
	}
	if newStatus == TaskStatusCompleted || newStatus == TaskStatusFailed {
		t.timeline.MarkCompleted()
	}

	t.status = newStatus
	return nil
}

// ----------------------------------------------------
// Progress Handling
// ----------------------------------------------------

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

// ApplyProgress updates the task's progress metrics and checkpoint data. The task must
// be in either IN_PROGRESS or PAUSED state to accept progress updates.
func (t *Task) ApplyProgress(progress Progress) error {
	// Validate task state - only allow progress updates in IN_PROGRESS or PAUSED state
	if !t.IsInProgress() && t.status != TaskStatusPaused {
		return &TaskInvalidStateError{
			taskID: t.ID,
			status: t.status,
			reason: TaskInvalidStateReasonProgressUpdateNotAllowed,
		}
	}

	// Validate sequence number
	if !t.isSeqNumValid(progress) {
		return NewOutOfOrderProgressError(t.ID, progress.SequenceNum(), t.lastSequenceNum)
	}

	// Update task metrics
	t.lastSequenceNum = progress.SequenceNum()
	t.itemsProcessed = progress.ItemsProcessed()
	t.progressDetails = progress.ProgressDetails()
	t.lastCheckpoint = progress.Checkpoint()

	// Update timeline
	t.timeline.UpdateLastUpdate()

	return nil
}

func (t *Task) isSeqNumValid(progress Progress) bool {
	return progress.SequenceNum() > t.lastSequenceNum
}

// StaleTaskInfo represents the minimal information needed for stale task processing.
type StaleTaskInfo struct {
	taskID       uuid.UUID
	jobID        uuid.UUID
	controllerID string
}

// NewStaleTaskInfo creates a new StaleTaskInfo instance.
func NewStaleTaskInfo(taskID, jobID uuid.UUID, controllerID string) StaleTaskInfo {
	return StaleTaskInfo{
		taskID:       taskID,
		jobID:        jobID,
		controllerID: controllerID,
	}
}

// ReconstructStaleTaskInfo reconstructs a StaleTaskInfo from a Task.
func ReconstructStaleTaskInfo(taskID uuid.UUID, jobID uuid.UUID, controllerID string) StaleTaskInfo {
	return StaleTaskInfo{
		taskID:       taskID,
		jobID:        jobID,
		controllerID: controllerID,
	}
}

// TaskID returns the unique identifier for this task.
func (s StaleTaskInfo) TaskID() uuid.UUID { return s.taskID }

// JobID returns the unique identifier for the job containing this task.
func (s StaleTaskInfo) JobID() uuid.UUID { return s.jobID }

// ControllerID returns the identifier of the controller responsible for this task.
func (s StaleTaskInfo) ControllerID() string { return s.controllerID }
