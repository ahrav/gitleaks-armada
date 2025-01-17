package scanning

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
)

// TaskStatus represents the execution state of an individual scan task. It enables
// fine-grained tracking of task progress and error conditions.
type TaskStatus string

const (
	// TaskStatusInProgress indicates a task is actively scanning.
	TaskStatusInProgress TaskStatus = "IN_PROGRESS"

	// TaskStatusCompleted indicates a task finished successfully.
	TaskStatusCompleted TaskStatus = "COMPLETED"

	// TaskStatusFailed indicates a task encountered an unrecoverable error.
	TaskStatusFailed TaskStatus = "FAILED"

	// TaskStatusStale indicates a task stopped reporting progress and may need recovery.
	TaskStatusStale TaskStatus = "STALE"
)

// Progress represents a point-in-time status update from a scanner. It provides
// detailed metrics and state information to track scanning progress and enable
// task recovery.
type Progress struct {
	TaskID          uuid.UUID       `json:"task_id"`
	SequenceNum     int64           `json:"sequence_num"`
	Timestamp       time.Time       `json:"timestamp"`
	Status          TaskStatus      `json:"status"`
	ItemsProcessed  int64           `json:"items_processed"`
	ErrorCount      int32           `json:"error_count"`
	Message         string          `json:"message,omitempty"`
	ProgressDetails json.RawMessage `json:"progress_details,omitempty"`
	Checkpoint      *Checkpoint     `json:"checkpoint,omitempty"`
}

// ReconstructProgress creates a Progress instance from persisted data.
// This should only be used by repositories when reconstructing from storage.
func ReconstructProgress(
	taskID uuid.UUID,
	sequenceNum int64,
	timestamp time.Time,
	status TaskStatus,
	itemsProcessed int64,
	errorCount int32,
	message string,
	progressDetails json.RawMessage,
	checkpoint *Checkpoint,
) Progress {
	return Progress{
		TaskID:          taskID,
		SequenceNum:     sequenceNum,
		Timestamp:       timestamp,
		Status:          status,
		ItemsProcessed:  itemsProcessed,
		ErrorCount:      errorCount,
		Message:         message,
		ProgressDetails: progressDetails,
		Checkpoint:      checkpoint,
	}
}

// Checkpoint contains the state needed to resume a scan after interruption.
// This enables fault tolerance by preserving progress markers and context.
type Checkpoint struct {
	TaskID      uuid.UUID         `json:"task_id"`
	Timestamp   time.Time         `json:"timestamp"`
	ResumeToken []byte            `json:"resume_token"`
	Metadata    map[string]string `json:"metadata"`
}

// NewCheckpoint creates a new Checkpoint for tracking scan progress.
// It establishes initial state for resuming interrupted scans.
func NewCheckpoint(
	taskID uuid.UUID,
	resumeToken []byte,
	metadata map[string]string,
) *Checkpoint {
	return &Checkpoint{
		TaskID:      taskID,
		Timestamp:   time.Now(),
		ResumeToken: resumeToken,
		Metadata:    metadata,
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
		TaskID:      taskID,
		Timestamp:   timestamp,
		ResumeToken: resumeToken,
		Metadata:    metadata,
	}
}

// Task tracks the full lifecycle and state of an individual scanning operation.
// It maintains historical progress data and enables task recovery and monitoring.
type Task struct {
	shared.CoreTask
	jobID           uuid.UUID
	status          TaskStatus
	lastSequenceNum int64
	startTime       time.Time
	lastUpdate      time.Time
	itemsProcessed  int64
	progressDetails json.RawMessage
	lastCheckpoint  *Checkpoint
}

// ReconstructTask creates a Task instance from persisted data without enforcing
// creation-time invariants. This should only be used by repositories when
// reconstructing from storage.
func ReconstructTask(
	taskID uuid.UUID,
	jobID uuid.UUID,
	status TaskStatus,
	lastSequenceNum int64,
	startTime time.Time,
	lastUpdate time.Time,
	itemsProcessed int64,
	progressDetails json.RawMessage,
	lastCheckpoint *Checkpoint,
) *Task {
	return &Task{
		CoreTask: shared.CoreTask{
			ID: taskID,
		},
		jobID:           jobID,
		status:          status,
		lastSequenceNum: lastSequenceNum,
		startTime:       startTime,
		lastUpdate:      lastUpdate,
		itemsProcessed:  itemsProcessed,
		progressDetails: progressDetails,
		lastCheckpoint:  lastCheckpoint,
	}
}

// NewScanTask creates a new ScanTask instance for tracking an individual scan operation.
// It establishes the task's relationship to its parent job and initializes monitoring state.
func NewScanTask(jobID uuid.UUID, taskID uuid.UUID) *Task {
	return &Task{
		CoreTask: shared.CoreTask{
			ID: taskID,
		},
		jobID:     jobID,
		status:    TaskStatusInProgress,
		startTime: time.Now(),
	}
}

// JobID returns the identifier of the parent job containing this task.
func (t *Task) JobID() uuid.UUID { return t.jobID }

// Status returns the current execution status of the scan task.
func (t *Task) Status() TaskStatus { return t.status }

// LastSequenceNum returns the sequence number of the most recent progress update.
func (t *Task) LastSequenceNum() int64 { return t.lastSequenceNum }

// LastUpdateTime returns when this task last reported progress.
func (t *Task) LastUpdateTime() time.Time { return t.lastUpdate }

// ItemsProcessed returns the total number of items scanned by this task.
func (t *Task) ItemsProcessed() int64 { return t.itemsProcessed }

// TaskID returns the unique identifier for this scan task.
func (t *Task) TaskID() uuid.UUID { return t.ID }

func (t *Task) LastCheckpoint() *Checkpoint { return t.lastCheckpoint }

func (t *Task) ProgressDetails() []byte { return t.progressDetails }

func (t *Task) StartTime() time.Time { return t.startTime }

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
	if !t.canApplyProgress(progress) {
		return NewOutOfOrderProgressError(t.TaskID(), progress.SequenceNum, t.LastSequenceNum())
	}

	t.updateProgress(progress)
	return nil
}

func (t *Task) canApplyProgress(progress Progress) bool {
	return progress.SequenceNum > t.lastSequenceNum
}

// UpdateProgress applies a progress update to this task's state.
// It updates all monitoring metrics and preserves any checkpoint data.
func (t *Task) updateProgress(progress Progress) {
	t.lastSequenceNum = progress.SequenceNum
	t.status = progress.Status
	t.lastUpdate = progress.Timestamp
	t.itemsProcessed += progress.ItemsProcessed
	t.progressDetails = progress.ProgressDetails
	if progress.Checkpoint != nil {
		t.lastCheckpoint = progress.Checkpoint
	}
}

// GetSummary returns a TaskSummary containing the key metrics and status
// for this task's execution progress.
func (t *Task) GetSummary(duration time.Duration) TaskSummary {
	return TaskSummary{
		taskID:          t.ID,
		status:          t.status,
		itemsProcessed:  t.itemsProcessed,
		duration:        duration,
		lastUpdateTs:    t.lastUpdate,
		progressDetails: t.progressDetails,
	}
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

// StalledTask encapsulates a stalled scanning task and its recovery context. It provides
// the necessary information to diagnose issues and implement appropriate recovery mechanisms.
type StalledTask struct {
	JobID            uuid.UUID
	TaskID           uuid.UUID
	StallReason      StallReason
	StalledDuration  time.Duration
	RecoveryAttempts int
	LastUpdate       time.Time
	ProgressDetails  json.RawMessage
	LastCheckpoint   *Checkpoint
}

// ToStalledTask converts this task to a StalledTask representation.
// This enables tracking of stalled tasks for monitoring and recovery.
func (t *Task) ToStalledTask(reason StallReason, stallTime time.Time) *StalledTask {
	return &StalledTask{
		JobID:           t.jobID,
		TaskID:          t.ID,
		StallReason:     reason,
		StalledDuration: time.Since(stallTime),
		LastUpdate:      t.lastUpdate,
		ProgressDetails: t.progressDetails,
		LastCheckpoint:  t.lastCheckpoint,
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
