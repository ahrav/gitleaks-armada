package scanning

import (
	"context"
)

// ExecutionTracker manages the lifecycle and progress monitoring of scanning tasks within jobs.
// It acts as a coordinator between the scanning workers and the job service, ensuring task
// state transitions are properly tracked and job status is accurately maintained. The tracker
// processes domain events related to task execution (start, progress, completion, failure) and
// maintains real-time progress metrics that can be queried at both the task and job level.
type ExecutionTracker interface {
	// HandleTaskStart initializes tracking for a new task by registering it with the job service
	// and setting up initial progress metrics. If this is the first task in a job, it will
	// transition the job from QUEUED to RUNNING status.
	HandleTaskStart(ctx context.Context, evt TaskStartedEvent) error

	// HandleTaskProgress handles task progress events during scanning, updating metrics like
	// items processed, processing rate, and error counts. This data is used to detect
	// stalled tasks and calculate overall job progress.
	HandleTaskProgress(ctx context.Context, evt TaskProgressedEvent) error

	// HandleTaskCompletion handles successful task completion by updating job metrics,
	// transitioning task status to COMPLETED, and potentially marking the job
	// as COMPLETED if all tasks are done.
	HandleTaskCompletion(ctx context.Context, evt TaskCompletedEvent) error

	// HandleTaskFailure handles task failure scenarios by transitioning the task to FAILED status
	// and updating job metrics. If all tasks in a job fail, the job will be marked as FAILED.
	HandleTaskFailure(ctx context.Context, evt TaskFailedEvent) error

	// HandleTaskStale marks a task as stale, indicating it has stopped reporting progress.
	HandleTaskStale(ctx context.Context, evt TaskStaleEvent) error

	// // GetJobProgress returns consolidated metrics for all tasks in a job, including
	// // total tasks, completed tasks, failed tasks, and overall progress percentage.
	// // This provides the data needed for job-level monitoring and reporting.
	// GetJobProgress(ctx context.Context, jobID uuid.UUID) (*scanning.Progress, error)

	// // GetTaskProgress returns detailed execution metrics for a specific task,
	// // including items processed, processing rate, error counts, and duration.
	// // This enables fine-grained monitoring of individual scanning operations.
	// GetTaskProgress(ctx context.Context, taskID uuid.UUID) (*scanning.Progress, error)
}
