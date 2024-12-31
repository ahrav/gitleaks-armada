// Package state provides types and interfaces for managing scan state and progress tracking.
// It defines the core data structures and status enums used to monitor and control
// scanning operations across the system.
package state

import (
	"encoding/json"
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
	taskID          string
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
func NewScanTask(jobID, taskID string) *ScanTask {
	return &ScanTask{
		taskID:    taskID,
		jobID:     jobID,
		status:    TaskStatusInitialized,
		startTime: time.Now(),
	}
}

// UpdateProgress applies a progress update to this task's state.
// It updates all monitoring metrics and preserves any checkpoint data.
func (t *ScanTask) UpdateProgress(progress ScanProgress) {
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
func (t *ScanTask) GetJobID() string { return t.jobID }

// GetStatus returns the current execution status of the scan task.
func (t *ScanTask) GetStatus() TaskStatus { return t.status }

// GetLastSequenceNum returns the sequence number of the most recent progress update.
func (t *ScanTask) GetLastSequenceNum() int64 { return t.lastSequenceNum }

// GetLastUpdateTime returns when this task last reported progress.
func (t *ScanTask) GetLastUpdateTime() time.Time { return t.lastUpdate }

// GetItemsProcessed returns the total number of items scanned by this task.
func (t *ScanTask) GetItemsProcessed() int64 { return t.itemsProcessed }

// GetTaskID returns the unique identifier for this scan task.
func (t *ScanTask) GetTaskID() string { return t.taskID }

// ScanJob coordinates and tracks a collection of related scanning tasks.
// It provides aggregated status and progress tracking across all child tasks.
type ScanJob struct {
	jobID          string
	status         JobStatus
	startTime      time.Time
	lastUpdateTime time.Time
	tasks          map[string]*ScanTask
	totalTasks     int
	completedTasks int
	failedTasks    int
}

// NewScanJob creates a new ScanJob instance with initialized state tracking.
// It ensures proper initialization of internal maps and timestamps for job monitoring.
func NewScanJob(jobID string) *ScanJob {
	return &ScanJob{
		jobID:     jobID,
		status:    JobStatusInitialized,
		startTime: time.Now(),
		tasks:     make(map[string]*ScanTask),
	}
}

// GetJobID returns the unique identifier for this scan job.
// Access is synchronized to ensure thread-safe reads.
func (j *ScanJob) GetJobID() string { return j.jobID }

// GetStatus returns the current execution status of the scan job.
// Access is synchronized to ensure thread-safe reads.
func (j *ScanJob) GetStatus() JobStatus { return j.status }

// GetStartTime returns when this scan job was initialized.
// Access is synchronized to ensure thread-safe reads.
func (j *ScanJob) GetStartTime() time.Time { return j.startTime }

// GetLastUpdateTime returns when this job's state was last modified.
// Access is synchronized to ensure thread-safe reads.
func (j *ScanJob) GetLastUpdateTime() time.Time { return j.lastUpdateTime }

// AddTask registers a new scan task with this job and updates task counters.
func (j *ScanJob) AddTask(task *ScanTask) {
	j.tasks[task.taskID] = task
	j.totalTasks = len(j.tasks)
	j.updateStatusCounters()
	j.lastUpdateTime = time.Now()
}

// UpdateTask applies changes to a task's state via the provided update function.
// It returns false if the task doesn't exist, true if the update was successful.
func (j *ScanJob) UpdateTask(taskID string, updateFn func(*ScanTask)) bool {
	task, exists := j.tasks[taskID]
	if !exists {
		return false
	}

	updateFn(task)
	j.updateStatusCounters()
	j.lastUpdateTime = time.Now()
	return true
}

// updateStatusCounters recalculates task completion metrics and overall job status.
// This should be called after any task state changes to maintain consistency.
func (j *ScanJob) updateStatusCounters() {
	completed := 0
	failed := 0
	inProgress := 0

	for _, task := range j.tasks {
		switch task.status {
		case TaskStatusCompleted:
			completed++
		case TaskStatusFailed:
			failed++
		case TaskStatusInProgress, TaskStatusStale:
			inProgress++
		}
	}

	j.completedTasks = completed
	j.failedTasks = failed

	switch {
	case completed+failed == len(j.tasks) && len(j.tasks) > 0:
		if failed == len(j.tasks) {
			j.status = JobStatusFailed
		} else {
			j.status = JobStatusCompleted
		}
	case inProgress > 0 || completed > 0 || failed > 0:
		j.status = JobStatusInProgress
	default:
		j.status = JobStatusInitialized
	}
}

// GetAllTaskSummaries returns summaries for all tasks in this job.
func (j *ScanJob) GetAllTaskSummaries() []TaskSummary {
	duration := time.Since(j.startTime)
	summaries := make([]TaskSummary, 0, len(j.tasks))
	for _, task := range j.tasks {
		summaries = append(summaries, task.GetSummary(duration))
	}
	return summaries
}

// GetSummary returns a TaskSummary containing the key metrics and status
// for this task's execution progress.
func (t *ScanTask) GetSummary(duration time.Duration) TaskSummary {
	return TaskSummary{
		taskID:          t.taskID,
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
func (t *ScanTask) ToStalledTask(reason StallReason, stallTime time.Time) *StalledTask {
	return &StalledTask{
		JobID:           t.jobID,
		TaskID:          t.taskID,
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
