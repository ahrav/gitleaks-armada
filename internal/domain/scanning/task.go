package scanning

import (
	"encoding/json"
	"time"

	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
)

// TaskStatus represents the execution state of an individual scan task. It enables
// fine-grained tracking of task progress and error conditions.
type TaskStatus string

const (
	// TaskStatusInitialized indicates a task is queued but not yet processing.
	TaskStatusInitialized TaskStatus = "INITIALIZED"

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
	TaskID          string          `json:"task_id"`
	JobID           string          `json:"job_id"`
	SequenceNum     int64           `json:"sequence_num"`
	Timestamp       time.Time       `json:"timestamp"`
	Status          TaskStatus      `json:"status"`
	ItemsProcessed  int64           `json:"items_processed"`
	ErrorCount      int32           `json:"error_count"`
	Message         string          `json:"message,omitempty"`
	ProgressDetails json.RawMessage `json:"progress_details,omitempty"`
	Checkpoint      *Checkpoint     `json:"checkpoint,omitempty"`
}

// Checkpoint contains the state needed to resume a scan after interruption.
// This enables fault tolerance by preserving progress markers and context.
type Checkpoint struct {
	TaskID      string            `json:"task_id"`
	JobID       string            `json:"job_id"`
	Timestamp   time.Time         `json:"timestamp"`
	ResumeToken []byte            `json:"resume_token"`
	Metadata    map[string]string `json:"metadata"`
}

// Task tracks the full lifecycle and state of an individual scanning operation.
// It maintains historical progress data and enables task recovery and monitoring.
type Task struct {
	shared.CoreTask
	jobID           string
	status          TaskStatus
	lastSequenceNum int64
	startTime       time.Time
	lastUpdate      time.Time
	itemsProcessed  int64
	progressDetails json.RawMessage
	lastCheckpoint  *Checkpoint
}

// NewScanTask creates a new ScanTask instance for tracking an individual scan operation.
// It establishes the task's relationship to its parent job and initializes monitoring state.
func NewScanTask(jobID, taskID string) *Task {
	return &Task{
		CoreTask: shared.CoreTask{
			TaskID: taskID,
		},
		jobID:     jobID,
		status:    TaskStatusInitialized,
		startTime: time.Now(),
	}
}

// UpdateProgress applies a progress update to this task's state.
// It updates all monitoring metrics and preserves any checkpoint data.
func (t *Task) UpdateProgress(progress Progress) {
	t.lastSequenceNum = progress.SequenceNum
	t.status = progress.Status
	t.lastUpdate = progress.Timestamp
	t.itemsProcessed = progress.ItemsProcessed
	t.progressDetails = progress.ProgressDetails
	if progress.Checkpoint != nil {
		t.lastCheckpoint = progress.Checkpoint
	}
}

// GetJobID returns the identifier of the parent job containing this task.
func (t *Task) GetJobID() string { return t.jobID }

// GetStatus returns the current execution status of the scan task.
func (t *Task) GetStatus() TaskStatus { return t.status }

// GetLastSequenceNum returns the sequence number of the most recent progress update.
func (t *Task) GetLastSequenceNum() int64 { return t.lastSequenceNum }

// GetLastUpdateTime returns when this task last reported progress.
func (t *Task) GetLastUpdateTime() time.Time { return t.lastUpdate }

// GetItemsProcessed returns the total number of items scanned by this task.
func (t *Task) GetItemsProcessed() int64 { return t.itemsProcessed }

// GetTaskID returns the unique identifier for this scan task.
func (t *Task) GetTaskID() string { return t.TaskID }

// GetSummary returns a TaskSummary containing the key metrics and status
// for this task's execution progress.
func (t *Task) GetSummary(duration time.Duration) TaskSummary {
	return TaskSummary{
		taskID:          t.TaskID,
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
	JobID            string
	TaskID           string
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
		TaskID:          t.TaskID,
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
	taskID          string
	status          TaskStatus
	itemsProcessed  int64
	duration        time.Duration
	lastUpdateTs    time.Time
	progressDetails json.RawMessage
}

// GetTaskID returns the unique identifier for this scan task.
func (s TaskSummary) GetTaskID() string { return s.taskID }

// GetStatus returns the current execution status of the scan task.
func (s TaskSummary) GetStatus() TaskStatus { return s.status }

// GetLastUpdateTimestamp returns when this task last reported progress.
func (s TaskSummary) GetLastUpdateTimestamp() time.Time { return s.lastUpdateTs }
