package state

import "context"

// Store provides persistent storage and retrieval of scan job execution state.
// It enables reliable tracking of long-running scan operations by maintaining
// progress updates, checkpoints, and job status across system restarts.
type Store interface {
	// SaveProgress persists a scanner's progress update to maintain execution history
	// and enable monitoring of task health. Progress updates include metrics, status
	// changes, and optional checkpointing data.
	SaveProgress(ctx context.Context, progress ScanProgress) error

	// GetJob retrieves the full execution state and metadata for a scan job.
	// This provides visibility into overall job status and constituent task states.
	GetJob(ctx context.Context, jobID string) (*ScanJob, error)

	// SaveJob atomically persists the complete state of a scan job and its tasks.
	// This ensures consistency when updating aggregate job status and task states.
	SaveJob(ctx context.Context, job *ScanJob) error

	// SaveCheckpoint durably stores a task's resumption state to enable recovery
	// after interruption. Checkpoints capture the progress markers and context
	// needed to resume scanning.
	SaveCheckpoint(ctx context.Context, checkpoint Checkpoint) error

	// GetCheckpoint retrieves the most recent checkpoint for a specific task.
	// This enables scan tasks to resume from their last known good state.
	GetCheckpoint(ctx context.Context, jobID, taskID string) (*Checkpoint, error)

	// ListActiveJobs returns all jobs that have not reached a terminal status
	// (completed/failed). This enables monitoring of in-flight scan operations
	// and detection of stalled jobs.
	ListActiveJobs(ctx context.Context) ([]*ScanJob, error)
}
