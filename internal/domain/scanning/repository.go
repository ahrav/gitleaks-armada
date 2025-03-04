// Package scanning provides domain types and interfaces for managing scan jobs and tasks.
// It defines the core abstractions needed to coordinate distributed scanning operations,
// track progress, and handle failure recovery.
package scanning

import (
	"context"
	"errors"
	"time"

	"github.com/ahrav/gitleaks-armada/pkg/common/uuid"
)

var (
	// ErrJobNotFound indicates the requested job was not found in storage.
	ErrJobNotFound = errors.New("job not found")
	// ErrNoJobMetricsUpdated indicates that no job metrics were updated.
	ErrNoJobMetricsUpdated = errors.New("no job metrics updated")
	// ErrNoJobMetricsFound indicates that no job metrics were found.
	ErrNoJobMetricsFound = errors.New("no job metrics found")
	// ErrNoCheckpointsFound indicates that no checkpoints were found.
	ErrNoCheckpointsFound = errors.New("no checkpoints found")
)

// JobRepository defines the persistence operations for scan jobs.
// It provides an abstraction layer over the storage mechanism used to maintain
// job state and history.
type JobRepository interface {
	// CreateJob inserts a new job record, setting status and initial timestamps.
	CreateJob(ctx context.Context, job *Job) error

	// IncrementTotalTasks increments the total tasks count for a job.
	IncrementTotalTasks(ctx context.Context, jobID uuid.UUID, amount int) error

	// UpdateJob modifies an existing job's fields (status, end_time, etc.).
	UpdateJob(ctx context.Context, job *Job) error

	// AssociateTargets associates scan targets with a job.
	AssociateTargets(ctx context.Context, jobID uuid.UUID, targetIDs []uuid.UUID) error

	// GetJob retrieves a job's state (including associated tasks if needed).
	GetJob(ctx context.Context, jobID uuid.UUID) (*Job, error)

	// GetJobMetrics retrieves the metrics for a job.
	GetJobMetrics(ctx context.Context, jobID uuid.UUID) (*JobMetrics, error)

	// BulkUpdateJobMetrics updates metrics for multiple jobs in a single operation.
	BulkUpdateJobMetrics(ctx context.Context, updates map[uuid.UUID]*JobMetrics) (int64, error)

	// GetCheckpoints retrieves all checkpoints for a job's metrics.
	GetCheckpoints(ctx context.Context, jobID uuid.UUID) (map[int32]int64, error)

	// UpdateMetricsAndCheckpoint atomically updates both the metrics and checkpoint for a job.
	UpdateMetricsAndCheckpoint(
		ctx context.Context,
		jobID uuid.UUID,
		metrics *JobMetrics,
		partitionID int32,
		offset int64,
	) error

	// GetJobSourceTypeConfig retrieves just the source type and configuration for a job.
	// This provides a lightweight way to access job configuration without loading the full job.
	// This is primarily used for resuming tasks for a job and need the source type
	// and auth information in the config.
	GetJobConfigInfo(ctx context.Context, jobID uuid.UUID) (*JobConfigInfo, error)
}

// ScanJobQueryRepository defines read-only operations for retrieving scan job information.
// It provides a specialized interface for retrieving job data for display and reporting purposes.
type ScanJobQueryRepository interface {
	// GetJobByID retrieves a scan job by its identifier, including its current state and metrics.
	// This method is optimized for API query operations and aggregates all needed job data.
	GetJobByID(ctx context.Context, jobID uuid.UUID) (*JobDetail, error)
}

// ErrTaskNotFound indicates the requested task was not found in storage.
var ErrTaskNotFound = errors.New("task not found")

// TaskRepository defines the persistence operations for scan tasks.
// It provides an abstraction layer over the storage mechanism used to maintain
// task state and progress data.
type TaskRepository interface {
	// CreateTask persists a new task's initial state.
	CreateTask(ctx context.Context, task *Task, controllerID string) error

	// GetTask retrieves a task's current state.
	GetTask(ctx context.Context, taskID uuid.UUID) (*Task, error)

	// UpdateTask persists changes to an existing task's state.
	UpdateTask(ctx context.Context, task *Task) error

	// FindStaleTasks retrieves tasks that have not sent a heartbeat since the given cutoff time
	// and belong to the specified controller.
	FindStaleTasks(ctx context.Context, controllerID string, cutoff time.Time) ([]StaleTaskInfo, error)

	// BatchUpdateHeartbeats updates each task's last_heartbeat_at timestamp.
	BatchUpdateHeartbeats(ctx context.Context, heartbeats map[uuid.UUID]time.Time) (int64, error)

	// GetTasksToResume efficiently retrieves the minimal data needed for resuming tasks
	// from a paused job in a single database query, joining with the jobs table to get
	// the source_type without additional queries.
	GetTasksToResume(ctx context.Context, jobID uuid.UUID) ([]ResumeTaskInfo, error)
}

var (
	// ErrScannerNotFound indicates that the requested scanner was not found.
	ErrScannerNotFound = errors.New("scanner not found")
	// ErrScannerGroupNotFound indicates that the requested scanner group was not found.
	ErrScannerGroupNotFound = errors.New("scanner group not found")
	// ErrScannerGroupAlreadyExists indicates that a scanner group
	// with the same identifier or name already exists.
	ErrScannerGroupAlreadyExists = errors.New("scanner group already exists")
)

// ScannerRepository defines the persistence operations for scanner groups and scanners.
// It provides methods to manage the lifecycle and state of scanner resources in the system.
type ScannerRepository interface {
	// CreateScannerGroup creates a new scanner group.
	CreateScannerGroup(ctx context.Context, group *ScannerGroup) error

	// CreateScanner registers a new scanner in the system.
	CreateScanner(ctx context.Context, scanner *Scanner) error
}
