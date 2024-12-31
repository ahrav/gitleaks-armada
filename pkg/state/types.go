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
	mu              sync.RWMutex
	TaskID          string
	JobID           string
	Status          TaskStatus
	LastSequenceNum int64
	StartTime       time.Time
	LastUpdate      time.Time
	ItemsProcessed  int64
	ProgressDetails json.RawMessage
	LastCheckpoint  *Checkpoint
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

// ScanJob coordinates and tracks a collection of related scanning tasks.
// It provides aggregated status and progress tracking across all child tasks.
type ScanJob struct {
	mu             sync.RWMutex
	JobID          string
	Status         JobStatus
	StartTime      time.Time
	LastUpdateTime time.Time
	Tasks          map[string]*ScanTask
	TotalTasks     int
	CompletedTasks int
	FailedTasks    int
}

// NewScanJob creates a new ScanJob instance with initialized state tracking.
// It ensures proper initialization of internal maps and timestamps for job monitoring.
func NewScanJob(jobID string) *ScanJob {
	return &ScanJob{
		JobID:     jobID,
		Status:    JobStatusInitialized,
		StartTime: time.Now(),
		Tasks:     make(map[string]*ScanTask),
	}
}

// NewScanTask creates a new ScanTask instance for tracking an individual scan operation.
// It establishes the task's relationship to its parent job and initializes monitoring state.
func NewScanTask(jobID, taskID string) *ScanTask {
	return &ScanTask{
		TaskID:    taskID,
		JobID:     jobID,
		Status:    TaskStatusInitialized,
		StartTime: time.Now(),
	}
}

// GetJobID returns the unique identifier for this scan job.
// Access is synchronized to ensure thread-safe reads.
func (j *ScanJob) GetJobID() string {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return j.JobID
}

// GetStatus returns the current execution status of the scan job.
// Access is synchronized to ensure thread-safe reads.
func (j *ScanJob) GetStatus() JobStatus {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return j.Status
}

// GetStartTime returns when this scan job was initialized.
// Access is synchronized to ensure thread-safe reads.
func (j *ScanJob) GetStartTime() time.Time {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return j.StartTime
}

// GetLastUpdateTime returns when this job's state was last modified.
// Access is synchronized to ensure thread-safe reads.
func (j *ScanJob) GetLastUpdateTime() time.Time {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return j.LastUpdateTime
}

// GetTaskID returns the unique identifier for this scan task.
func (t *ScanTask) GetTaskID() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.TaskID
}

// GetJobID returns the identifier of the parent job containing this task.
func (t *ScanTask) GetJobID() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.JobID
}

// GetStatus returns the current execution status of the scan task.
func (t *ScanTask) GetStatus() TaskStatus {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.Status
}

// GetLastSequenceNum returns the sequence number of the most recent progress update.
func (t *ScanTask) GetLastSequenceNum() int64 {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.LastSequenceNum
}

// GetLastUpdateTime returns when this task last reported progress.
func (t *ScanTask) GetLastUpdateTime() time.Time {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.LastUpdate
}

// GetItemsProcessed returns the total number of items scanned by this task.
func (t *ScanTask) GetItemsProcessed() int64 {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.ItemsProcessed
}

// AddTask registers a new scan task with this job and updates task counters.
// Access is synchronized to ensure thread-safe modifications.
func (j *ScanJob) AddTask(task *ScanTask) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.Tasks[task.TaskID] = task
	j.TotalTasks = len(j.Tasks)
}

// UpdateTask applies changes to a task's state via the provided update function.
// It returns false if the task doesn't exist, true if the update was successful.
// Access is synchronized to ensure thread-safe modifications.
func (j *ScanJob) UpdateTask(taskID string, updateFn func(*ScanTask)) bool {
	j.mu.Lock()
	defer j.mu.Unlock()

	task, exists := j.Tasks[taskID]
	if !exists {
		return false
	}

	updateFn(task)
	j.updateStatusCounters()
	j.LastUpdateTime = time.Now()
	return true
}

// updateStatusCounters recalculates task completion metrics and overall job status.
// This should be called after any task state changes to maintain consistency.
func (j *ScanJob) updateStatusCounters() {
	// Reset counters for recalculation
	completed := 0
	failed := 0
	inProgress := 0

	for _, task := range j.Tasks {
		switch task.Status {
		case TaskStatusCompleted:
			completed++
		case TaskStatusFailed:
			failed++
		case TaskStatusInProgress, TaskStatusStale:
			inProgress++
		}
	}

	j.CompletedTasks = completed
	j.FailedTasks = failed

	// Derive job status from task states
	switch {
	case completed+failed == len(j.Tasks) && len(j.Tasks) > 0:
		if failed == len(j.Tasks) {
			j.Status = JobStatusFailed
		} else {
			j.Status = JobStatusCompleted
		}
	case inProgress > 0 || completed > 0 || failed > 0:
		j.Status = JobStatusInProgress
	default:
		j.Status = JobStatusInitialized
	}
}

// UpdateProgress applies a progress update to this task's state.
// It updates all monitoring metrics and preserves any checkpoint data.
func (t *ScanTask) UpdateProgress(progress ScanProgress) {
	t.LastSequenceNum = progress.SequenceNum
	t.Status = progress.Status
	t.LastUpdate = progress.Timestamp
	t.ItemsProcessed = progress.ItemsProcessed
	t.ProgressDetails = progress.ProgressDetails
	if progress.Checkpoint != nil {
		t.LastCheckpoint = progress.Checkpoint
	}
}

// GetSummary returns a TaskSummary containing the key metrics and status
// for this task's execution progress.
func (t *ScanTask) GetSummary() TaskSummary {
	return TaskSummary{
		TaskID:          t.TaskID,
		Status:          t.Status,
		ItemsProcessed:  t.ItemsProcessed,
		Duration:        time.Since(t.StartTime),
		LastUpdate:      t.LastUpdate,
		ProgressDetails: t.ProgressDetails,
	}
}

// GetAllTaskSummaries returns summaries for all tasks in this job.
// Access is synchronized to ensure thread-safe reads.
func (j *ScanJob) GetAllTaskSummaries() []TaskSummary {
	j.mu.RLock()
	defer j.mu.RUnlock()

	summaries := make([]TaskSummary, 0, len(j.Tasks))
	for _, task := range j.Tasks {
		summaries = append(summaries, task.GetSummary())
	}
	return summaries
}

// ToStalledTask converts this task to a StalledTask representation.
// This enables tracking of stalled tasks for monitoring and recovery.
func (t *ScanTask) ToStalledTask(reason StallReason, stallTime time.Time) *StalledTask {
	return &StalledTask{
		JobID:           t.JobID,
		TaskID:          t.TaskID,
		StallReason:     reason,
		StalledDuration: time.Since(stallTime),
		LastUpdate:      t.LastUpdate,
		ProgressDetails: t.ProgressDetails,
		LastCheckpoint:  t.LastCheckpoint,
	}
}

// TaskSummary provides a concise view of task execution progress.
// It contains the key metrics needed for monitoring task health and completion.
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
// It combines overall job status with task-level metrics to enable job monitoring.
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
