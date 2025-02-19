// Package scanning provides domain types and interfaces for managing distributed scanning operations.
package scanning

import (
	"context"

	"github.com/google/uuid"
)

// Execution tracking manages the lifecycle and progress of scanning tasks as they
// move through the system. It provides the interfaces needed to monitor task
// execution, handle state transitions, and maintain accurate progress information.
// This component ensures reliable task execution and provides visibility into
// scanning operations across the distributed system.

// ExecutionTracker manages the lifecycle and progress monitoring of scanning tasks
// within jobs. It processes task-related domain events and coordinates with the
// job service to maintain accurate system state and progress information.
type ExecutionTracker interface {
	// CreateJobForTarget creates a new job for the given target and publishes a JobCreatedEvent.
	// This serves as the entry point for a new scan job and all tasks associated with the target.
	CreateJobForTarget(ctx context.Context, target Target) error

	// HandleEnumeratedScanTask processes a task discovered during enumeration and publishes a
	// TaskCreatedEvent to initiate scanning. The event contains essential task details including:
	// - Task identity and resource location
	// - Authentication credentials for accessing the target
	// - Contextual metadata to guide scanning behavior
	// This serves as the bridge between enumeration and scanning phases, enabling distributed task execution.
	HandleEnumeratedScanTask(
		ctx context.Context,
		jobID uuid.UUID,
		task *Task,
		auth Auth,
		metadata map[string]string,
	) error

	// AssociateEnumeratedTargetsToJob links discovered scan targets to a job.
	// This provides the scanning domain a way to track all the enumerated targets
	// that will be scanned as part of a scan job.
	AssociateEnumeratedTargetsToJob(ctx context.Context, jobID uuid.UUID, scanTargetIDs []uuid.UUID) error

	// SignalEnumerationComplete signals that the enumeration phase is complete for a job.
	// It retrieves the job metrics and publishes an EnumerationCompleteEvent.
	// This allows for accurate job metrics tracking.
	SignalEnumerationComplete(ctx context.Context, job *Job) error

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
