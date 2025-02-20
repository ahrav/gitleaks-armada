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

// TranslationResult represents a single translated enumeration task in scanning-domain form.
// It contains the resulting scanning Task, any associated authentication configuration (Auth),
// and a set of metadata key/value pairs. This structure is typically produced by an ACL
// translator that bridges the enumeration and scanning domains.
type TranslationResult struct {
	Task     *Task
	Auth     Auth
	Metadata map[string]string
}

// ScanningResult encapsulates the scanning-domain equivalents of enumerated data, exposing
// channels of scanning-oriented objects. These channels emit:
//
//   - ScanTargetsCh: Discovered scan target IDs (UUIDs) that need to be linked to a job.
//   - TasksCh:       TranslationResult objects, which include the scanning Task, credentials,
//     and metadata derived from enumeration tasks.
//   - ErrCh:         Errors encountered during enumeration or translation.
//
// By providing scanning-domain channels (instead of enumeration-domain types), this structure
// avoids cross-domain dependencies and allows the scanning domain to consume data in its
// native format without referencing enumeration logic.
type ScanningResult struct {
	ScanTargetsCh <-chan []uuid.UUID
	TasksCh       <-chan TranslationResult
	ErrCh         <-chan error
}

// ExecutionTracker manages the lifecycle and progress monitoring of scanning tasks
// within jobs. It processes task-related domain events and coordinates with the
// job service to maintain accurate system state and progress information.
type ExecutionTracker interface {
	// CreateJobForTarget creates a new job with the given job ID and target, and publishes a JobCreatedEvent.
	// This serves as the entry point for a new scan job and all tasks associated with the target.
	CreateJobForTarget(ctx context.Context, jobID uuid.UUID, target Target) error

	// ProcessEnumerationStream consumes a stream of enumerated scan targets and tasks,
	// converting them into scanning-domain entities, associating them with the specified
	// job, and publishing the necessary domain events. Specifically, it:
	//
	//   • Reads discovered target IDs and links them to the job while tracking the total
	//     number of tasks for progress monitoring.
	//   • Translates enumerated tasks into scanning tasks (including any authorization or
	//     metadata) and persists them in the scanning domain.
	//   • Continuously listens for errors in the enumeration process, surfacing them as
	//     appropriate.
	//   • Signals the end of enumeration once all channels are exhausted, updating job
	//     status and publishing a completion event.
	//
	// This method blocks until the incoming channels are closed (or until the context is
	// canceled), ensuring all enumerated items are processed and the scanning domain’s job
	// lifecycle is accurately updated.
	ProcessEnumerationStream(
		ctx context.Context,
		jobID uuid.UUID,
		result *ScanningResult,
	) error

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
