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
	taskID          uuid.UUID
	sequenceNum     int64
	timestamp       time.Time
	status          TaskStatus
	itemsProcessed  int64
	errorCount      int32
	message         string
	progressDetails json.RawMessage
	checkpoint      *Checkpoint
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
		taskID:          taskID,
		sequenceNum:     sequenceNum,
		timestamp:       timestamp,
		status:          status,
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

// Status returns the current execution status of the scan task.
func (p Progress) Status() TaskStatus { return p.status }

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
	return json.Marshal(&struct {
		TaskID      string            `json:"task_id"`
		Timestamp   time.Time         `json:"timestamp"`
		ResumeToken []byte            `json:"resume_token"`
		Metadata    map[string]string `json:"metadata"`
	}{
		TaskID:      c.taskID.String(),
		Timestamp:   c.timestamp,
		ResumeToken: c.resumeToken,
		Metadata:    c.metadata,
	})
}

// UnmarshalJSON deserializes JSON data into a Checkpoint object.
func (c *Checkpoint) UnmarshalJSON(data []byte) error {
	aux := &struct {
		TaskID      string            `json:"task_id"`
		Timestamp   time.Time         `json:"timestamp"`
		ResumeToken []byte            `json:"resume_token"`
		Metadata    map[string]string `json:"metadata"`
	}{}

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

// Task tracks the full lifecycle and state of an individual scanning operation.
// It maintains historical progress data and enables task recovery and monitoring.
type Task struct {
	shared.CoreTask
	jobID           uuid.UUID
	status          TaskStatus
	lastSequenceNum int64
	timeline        *Timeline
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
		timeline:        ReconstructTimeline(startTime, time.Time{}, lastUpdate),
		itemsProcessed:  itemsProcessed,
		progressDetails: progressDetails,
		lastCheckpoint:  lastCheckpoint,
	}
}

// TaskOption defines functional options for configuring a new Task.
type TaskOption func(*Task)

// WithTimeProvider sets a custom time provider for the task.
func WithTimeProvider(tp TimeProvider) TaskOption {
	return func(t *Task) { t.timeline = NewTimeline(tp) }
}

// NewScanTask creates a new ScanTask instance for tracking an individual scan operation.
// It establishes the task's relationship to its parent job and initializes monitoring state.
func NewScanTask(jobID uuid.UUID, taskID uuid.UUID, opts ...TaskOption) *Task {
	task := &Task{
		CoreTask: shared.CoreTask{
			ID: taskID,
		},
		jobID:    jobID,
		status:   TaskStatusInProgress,
		timeline: NewTimeline(new(realTimeProvider)),
	}

	for _, opt := range opts {
		opt(task)
	}

	return task
}

// JobID returns the identifier of the parent job containing this task.
func (t *Task) JobID() uuid.UUID { return t.jobID }

// Status returns the current execution status of the scan task.
func (t *Task) Status() TaskStatus { return t.status }

// LastSequenceNum returns the sequence number of the most recent progress update.
func (t *Task) LastSequenceNum() int64 { return t.lastSequenceNum }

// LastUpdateTime returns when this task last reported progress.
func (t *Task) LastUpdateTime() time.Time { return t.timeline.LastUpdate() }

// ItemsProcessed returns the total number of items scanned by this task.
func (t *Task) ItemsProcessed() int64 { return t.itemsProcessed }

// TaskID returns the unique identifier for this scan task.
func (t *Task) TaskID() uuid.UUID { return t.ID }

func (t *Task) LastCheckpoint() *Checkpoint { return t.lastCheckpoint }

func (t *Task) ProgressDetails() []byte { return t.progressDetails }

// StartTime returns the time the task was started.
func (t *Task) StartTime() time.Time { return t.timeline.StartedAt() }

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
	if !t.isSeqNumValid(progress) {
		return NewOutOfOrderProgressError(t.TaskID(), progress.SequenceNum(), t.LastSequenceNum())
	}

	t.updateProgress(progress)
	return nil
}

func (t *Task) isSeqNumValid(progress Progress) bool {
	return progress.SequenceNum() > t.lastSequenceNum
}

// UpdateProgress applies a progress update to this task's state.
// It updates all monitoring metrics and preserves any checkpoint data.
func (t *Task) updateProgress(progress Progress) {
	t.lastSequenceNum = progress.SequenceNum()
	t.status = progress.Status()
	t.timeline.UpdateLastUpdate()
	t.itemsProcessed += progress.ItemsProcessed()
	t.progressDetails = progress.ProgressDetails()
	if progress.Checkpoint() != nil {
		t.lastCheckpoint = progress.Checkpoint()
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
		lastUpdateTs:    t.timeline.LastUpdate(),
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
		LastUpdate:      t.timeline.LastUpdate(),
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
