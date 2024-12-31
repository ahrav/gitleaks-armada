package state

import "context"

// Manager coordinates the lifecycle and state tracking of scan jobs and their tasks.
// It provides a central interface for monitoring scan progress, detecting stalled operations,
// and retrieving execution status across distributed scanning components.
type Manager interface {
	// HandleProgressUpdate processes status updates from scanners to track job execution.
	// Updates include metrics, state transitions, and checkpoints to enable task recovery.
	// Returns an error if the update is invalid or state tracking fails.
	HandleProgressUpdate(ctx context.Context, progress ScanProgress) error

	// GetJob retrieves the full execution state and progress metrics for a scan job.
	// This provides visibility into overall job status and constituent task states.
	// Returns nil if no job exists with the given ID.
	GetJob(ctx context.Context, jobID string) (*ScanJob, error)

	// GetTask retrieves detailed execution state for a specific task within a job.
	// This enables granular monitoring of individual scan operations.
	// Returns nil if either the job or task ID is not found.
	GetTask(ctx context.Context, jobID, taskID string) (*ScanTask, error)

	// GetJobSummary provides an aggregated view of job execution progress and task states.
	// This enables efficient monitoring of large jobs without full execution details.
	// Returns an error if the job cannot be found or the summary cannot be generated.
	GetJobSummary(ctx context.Context, jobID string) (*JobSummary, error)

	// DetectStaleTasks identifies tasks that have stopped reporting progress updates.
	// This enables automated detection of failed or hung tasks that require intervention.
	// The detection window is based on the manager's configured timeout settings.
	DetectStaleTasks(ctx context.Context) ([]*StalledTask, error)
}
