package scanning

import "time"

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
	j.tasks[task.TaskID] = task
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

// JobSummary provides an aggregated overview of job execution progress.
// It combines overall job status with task-level metrics to enable job monitoring.
// TODO: Do something with this eventually..
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
