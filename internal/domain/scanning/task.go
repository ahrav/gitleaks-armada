package scanning

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
	"github.com/ahrav/gitleaks-armada/pkg/common/uuid"
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
	scannerID   *uuid.UUID // ID of the scanner assigned to this task (nullable)

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
// The scannerID is not required at creation time and can be set later using the WithScannerID
// option or by calling SetScannerID when a scanner is assigned to execute the task.
func NewScanTask(
	jobID uuid.UUID,
	sourceType shared.SourceType,
	taskID uuid.UUID,
	resourceURI string,
	opts ...TaskOption,
) *Task {
	task := &Task{
		CoreTask: shared.CoreTask{
			ID:         taskID,
			SourceType: sourceType,
		},
		jobID:           jobID,
		resourceURI:     resourceURI,
		scannerID:       nil, // Initially unassigned
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
	scannerID *uuid.UUID,
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
		scannerID:        scannerID,
	}
}

// JobID returns the identifier of the parent job containing this task.
func (t *Task) JobID() uuid.UUID { return t.jobID }

// Status returns the current execution status of the scan task.
func (t *Task) Status() TaskStatus { return t.status }

// ScannerID returns the ID of the scanner assigned to this task, or nil if unassigned.
func (t *Task) ScannerID() *uuid.UUID { return t.scannerID }

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

// Cancel transitions a task to CANCELLED status.
func (t *Task) Cancel() error {
	if t.status == TaskStatusCancelled {
		return nil // idempotent
	}

	if t.status != TaskStatusPending &&
		t.status != TaskStatusInProgress &&
		t.status != TaskStatusStale &&
		t.status != TaskStatusPaused {
		return TaskInvalidStateError{
			taskID: t.ID,
			status: t.status,
			reason: TaskInvalidStateReasonWrongStatus,
		}
	}

	return t.UpdateStatus(TaskStatusCancelled)
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

// TaskScannerAlreadyAssignedError is an error type for indicating that a scanner is already
// assigned to a task. This enforces the domain invariant that a task can only be assigned
// to one scanner at a time.
type TaskScannerAlreadyAssignedError struct {
	taskID         uuid.UUID
	currentScanner uuid.UUID
	newScanner     uuid.UUID
}

// Error returns a string representation of the error.
func (e TaskScannerAlreadyAssignedError) Error() string {
	return fmt.Sprintf("task %s already assigned to scanner %s, cannot reassign to %s",
		e.taskID, e.currentScanner, e.newScanner)
}

// HasScanner returns true if the task has been assigned to a scanner.
func (t *Task) HasScanner() bool { return t.scannerID != nil }

// SetScannerID assigns a scanner to this task. Returns an error if a scanner
// is already assigned to enforce the invariant that a task can only be
// assigned to one scanner at a time.
func (t *Task) SetScannerID(scannerID uuid.UUID) error {
	if t.scannerID != nil {
		return TaskScannerAlreadyAssignedError{
			taskID:         t.ID,
			currentScanner: *t.scannerID,
			newScanner:     scannerID,
		}
	}

	id := scannerID // Make a copy
	t.scannerID = &id
	return nil
}

// ClearScannerID removes the scanner assignment from this task.
func (t *Task) ClearScannerID() { t.scannerID = nil }

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
