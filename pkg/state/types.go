// Package state provides types and interfaces for managing scan state and progress tracking.
// It defines the core data structures and status enums used to monitor and control
// scanning operations across the system.
package state

import (
	"encoding/json"
	"sync"
	"time"
)

// JobStatus represents the current state of a scan job. It enables tracking of
// job lifecycle from initialization through completion or failure.
type JobStatus string

const (
	// JobStatusInitialized indicates a job has been created but not yet started.
	JobStatusInitialized JobStatus = "INITIALIZED"
	// JobStatusInProgress indicates a job is actively processing tasks.
	JobStatusInProgress JobStatus = "IN_PROGRESS"
	// JobStatusCompleted indicates all job tasks finished successfully.
	JobStatusCompleted JobStatus = "COMPLETED"
	// JobStatusFailed indicates the job encountered an unrecoverable error.
	JobStatusFailed JobStatus = "FAILED"
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

// ScanProgress represents a point-in-time status update from a scanner. It provides
// detailed metrics and state information to track scanning progress and enable
// task recovery.
type ScanProgress struct {
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

// ScanTask tracks the full lifecycle and state of an individual scanning operation.
// It maintains historical progress data and enables task recovery and monitoring.
type ScanTask struct {
	TaskID           string
	JobID            string
	Status           TaskStatus
	LastSequenceNum  int64
	StartTime        time.Time
	LastUpdate       time.Time
	ItemsProcessed   int64
	ErrorCount       int32
	LastCheckpoint   *Checkpoint
	RecoveryAttempts int
	ProgressDetails  json.RawMessage
}

// ScanJob coordinates and tracks a collection of related scanning tasks.
// It provides aggregated status and progress tracking across all child tasks.
type ScanJob struct {
	JobID          string
	Status         JobStatus
	StartTime      time.Time
	LastUpdateTime time.Time
	Tasks          map[string]*ScanTask // Maps TaskID to task state
	TotalTasks     int
	CompletedTasks int
	FailedTasks    int
	mu             sync.RWMutex // Protects concurrent access to job state
}

// TaskSummary provides a concise view of task execution progress and status.
// It enables efficient monitoring without the full task state details.
type TaskSummary struct {
	TaskID          string
	Status          TaskStatus
	ItemsProcessed  int64
	ErrorCount      int32
	Duration        time.Duration
	LastUpdate      time.Time
	ProgressDetails json.RawMessage
}

// JobSummary provides an aggregated overview of job execution progress.
// It combines high-level job status with task-level summary information
// for monitoring multi-task scan operations.
type JobSummary struct {
	JobID          string
	Status         JobStatus
	StartTime      time.Time
	Duration       time.Duration
	TotalTasks     int
	CompletedTasks int
	FailedTasks    int
	TaskSummaries  []TaskSummary
}
