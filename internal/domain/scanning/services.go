package scanning

import (
	"context"
	"time"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
	"github.com/ahrav/gitleaks-armada/pkg/common/uuid"
)

// JobScheduler coordinates the creation and orchestration of new jobs within the scanning
// domain. It ensures consistent job setup while allowing other parts of the system to
// react to newly scheduled work.
type JobScheduler interface {
	// Schedule creates a new job with the provided jobID and targets, then publishes
	// domain events to notify external services that the job was scheduled.
	Schedule(ctx context.Context, jobID uuid.UUID, targets []Target) error

	// Pause initiates the pausing of a job by transitioning it to the PAUSING state
	// and publishing a JobPausingEvent. The actual pause operation is handled asynchronously
	// by the job coordinator.
	Pause(ctx context.Context, jobID uuid.UUID, requestedBy string) error

	// Resume initiates the resumption of a job by transitioning it from the PAUSED state
	// to the RUNNING state and publishing TaskResumeEvents for each paused task. This allows
	// tasks to continue from their last checkpoint.
	Resume(ctx context.Context, jobID uuid.UUID, requestedBy string) error

	// Cancel initiates the cancellation of a job by transitioning it to the CANCELLING state
	// and publishing a JobCancelledEvent. The actual cancellation is handled asynchronously
	// by the JobMetricsTracker.
	Cancel(ctx context.Context, jobID uuid.UUID, requestedBy string) error
}

// JobTaskService provides the primary interface for managing scan operations in our distributed
// scanning system. It manages the lifecycle and relationships between jobs and their constituent
// tasks, providing core abstractions for maintaining consistency, handling state transitions,
// and ensuring reliable execution. The service handles both job-level coordination and task
// lifecycle management while maintaining consistency between distributed components.
type JobTaskService interface {
	// ---------------------------
	// Job-level operations
	// ---------------------------

	// CreateJob initializes a new scanning operation in the system.
	// It uses a command object to encapsulate all required information.
	CreateJob(ctx context.Context, cmd CreateJobCommand) error

	// AssociateEnumeratedTargets links the provided scan targets to the specified job
	// and updates the job's total task count in a single atomic operation. This ensures
	// newly discovered targets are both associated for scanning and reflected in the
	// job's overall task tally, preserving data consistency if any step fails.
	AssociateEnumeratedTargets(ctx context.Context, jobID uuid.UUID, targetIDs []uuid.UUID) error

	// GetJobConfigInfo retrieves just the source type and configuration for a job.
	// This is useful for lightweight access to job configuration without loading the full job.
	GetJobConfigInfo(ctx context.Context, jobID uuid.UUID) (*JobConfigInfo, error)

	// UpdateJobStatus updates the status of a job.
	UpdateJobStatus(ctx context.Context, jobID uuid.UUID, status JobStatus) error

	// CompleteEnumeration finalizes the enumeration phase of a job and transitions it
	// to the appropriate next state based on whether any tasks were created.
	CompleteEnumeration(ctx context.Context, jobID uuid.UUID) (*JobMetrics, error)

	// ---------------------------
	// Task-level operations
	// ---------------------------

	// CreateTask creates a new scanning task.
	CreateTask(ctx context.Context, task *Task) error

	// StartTask begins a new scanning task.
	StartTask(ctx context.Context, taskID uuid.UUID, resourceURI string) error

	// UpdateTaskProgress handles incremental updates from running scanners.
	// Updates are cached in memory and periodically persisted to reduce database load
	// while maintaining reasonable consistency guarantees.
	UpdateTaskProgress(ctx context.Context, progress Progress) (*Task, error)

	// CompleteTask marks a task as successful.
	CompleteTask(ctx context.Context, taskID uuid.UUID) (*Task, error)

	// FailTask handles task failure scenarios.
	FailTask(ctx context.Context, taskID uuid.UUID) (*Task, error)

	// MarkTaskStale flags a task that has become unresponsive or stopped reporting progress.
	// This enables automated detection and recovery of failed tasks that require intervention.
	MarkTaskStale(ctx context.Context, taskID uuid.UUID, reason StallReason) (*Task, error)

	// PauseTask transitions a task to PAUSED status and stores its final progress checkpoint.
	// The task can later be resumed from this checkpoint.
	PauseTask(ctx context.Context, taskID uuid.UUID, progress Progress, requestedBy string) (*Task, error)

	// CancelTask transitions a task to CANCELLED status, preventing further work on it.
	// This is a terminal state from which a task cannot be resumed.
	CancelTask(ctx context.Context, taskID uuid.UUID, requestedBy string) (*Task, error)

	// GetTaskSourceType retrieves the source type of a task.
	// This is needed for task resume operations.
	GetTaskSourceType(ctx context.Context, taskID uuid.UUID) (shared.SourceType, error)

	// UpdateHeartbeats updates the last_heartbeat_at timestamp for a list of tasks.
	UpdateHeartbeats(ctx context.Context, heartbeats map[uuid.UUID]time.Time) (int64, error)

	// FindStaleTasks retrieves tasks that have not sent a heartbeat since the given cutoff time.
	FindStaleTasks(ctx context.Context, controllerID string, cutoff time.Time) ([]StaleTaskInfo, error)

	// GetTasksToResume retrieves all PAUSED tasks for a job that need to be resumed.
	// This is used when resuming a job that was previously paused.
	GetTasksToResume(ctx context.Context, jobID uuid.UUID) ([]ResumeTaskInfo, error)

	// // RecoverTask attempts to resume execution of a previously stalled task.
	// // It uses the last recorded checkpoint to restart the task from its last known good state.
	// RecoverTask(ctx context.Context, jobID, taskID uuid.UUID) error

	// // GetJob retrieves the current state and task details for a specific scan job.
	// // This enables external components to monitor job progress and handle failures.
	// GetJob(ctx context.Context, jobID uuid.UUID) (*domain.Job, error)

	// // ListJobs retrieves a paginated list of jobs filtered by their status.
	// // This supports system-wide job monitoring and management capabilities.
	// ListJobs(ctx context.Context, status []domain.JobStatus, limit, offset int) ([]*domain.Job, error)

	// TODO: BulkUpdateMetricsAndCheckpoint.
}

// TODO: Figure out how to make sure this maps to the correct topic.
const (
	JobLifecycleStreamType events.StreamType = "job-lifecycle"
)

// Metrics tracking provides real-time visibility into scanning operations across
// the distributed system. It handles the collection, aggregation, and persistence
// of metrics data for both individual tasks and overall jobs. The metrics system
// balances the need for real-time updates with storage efficiency through periodic
// persistence and in-memory caching.

// JobMetricsAggregator handles aggregation and persistence of job-level metrics
// across distributed task processing. It maintains in-memory state for real-time
// updates while ensuring durability through periodic persistence.
type JobMetricsAggregator interface {
	// LaunchMetricsFlusher runs a metrics flushing loop that periodically persists
	// metrics to storage. It blocks until the context is canceled or an error occurs.
	// Callers typically run this in a separate goroutine:
	//     go tracker.LaunchMetricsFlusher(10*time.Second)
	// This allows us to batch updates to storage and reduce the number of round trips.
	LaunchMetricsFlusher(interval time.Duration)

	// HandleJobMetrics processes task-related events to update job metrics.
	// It maintains both task status and aggregated job metrics in memory.
	// The ack function is used to acknowledge the latest offset for the job's partition.
	// This is handled manually to ensure we only commit the latest offset once the metrics
	// have been successfully persisted.
	HandleJobMetrics(ctx context.Context, evt events.EventEnvelope, ack events.AckFunc) error

	// HandleEnumerationCompleted processes a JobEnumerationCompletedEvent, which signals
	// that enumeration of tasks has finished for a specific job. The event conveys the
	// total number of tasks discovered.
	HandleEnumerationCompleted(ctx context.Context, evt events.EventEnvelope, ack events.AckFunc) error

	// FlushMetrics persists the current state of job metrics to the backing store.
	// This is typically called periodically to ensure durability of metrics.
	FlushMetrics(ctx context.Context) error

	// Stop stops the background goroutines and waits for them to finish.
	Stop(ctx context.Context)
}

// MetricsRepository defines the persistence operations for job metrics tracking.
// It provides efficient access to metrics data without requiring full entity loads,
// supporting both real-time updates and historical queries.
type MetricsRepository interface {
	// GetJobMetrics retrieves the metrics for a specific job.
	// Returns ErrJobNotFound if the job doesn't exist.
	GetJobMetrics(ctx context.Context, jobID uuid.UUID) (*JobMetrics, error)

	// GetTask retrieves a task's current state.
	GetTask(ctx context.Context, taskID uuid.UUID) (*Task, error)

	// GetCheckpoints retrieves all checkpoints for a job's metrics.
	GetCheckpoints(ctx context.Context, jobID uuid.UUID) (map[int32]int64, error)

	// UpdateJobStatus updates the status of a job.
	UpdateJobStatus(ctx context.Context, jobID uuid.UUID, status JobStatus) error

	// UpdateMetricsAndCheckpoint updates the metrics and checkpoint for a job.
	UpdateMetricsAndCheckpoint(
		ctx context.Context,
		jobID uuid.UUID,
		metrics *JobMetrics,
		partition int32,
		offset int64,
	) error

	// TODO: BulkUpdateMetricsAndCheckpoint.
}

// Health monitoring is a critical component of our distributed scanning system.
// It ensures tasks remain responsive and enables automatic detection and recovery
// of failed operations. The interfaces defined here establish the contract for
// monitoring task health through heartbeats, detecting stale tasks, and managing
// task state transitions when health issues are detected.

// TaskHealthMonitor manages the health and liveness of distributed scanning tasks.
// It provides heartbeat tracking and stale task detection to ensure reliable
// operation of the distributed scanning system. When tasks become unresponsive
// or fail silently, the monitor enables early detection and recovery.
type TaskHealthMonitor interface {
	// Start starts the health monitor.
	Start(ctx context.Context)
	// HandleHeartbeat handles a heartbeat event.
	HandleHeartbeat(ctx context.Context, evt TaskHeartbeatEvent)
	// Stop stops the health monitor.
	Stop()
}

// TaskHealthService defines the persistence operations needed for health monitoring.
// It abstracts the storage layer for task health data, allowing efficient tracking
// and querying of task heartbeats without coupling to specific storage implementations.
type TaskHealthService interface {
	// UpdateHeartbeats updates the last_heartbeat_at timestamp for a list of tasks.
	UpdateHeartbeats(ctx context.Context, heartbeats map[uuid.UUID]time.Time) (int64, error)

	// FindStaleTasks retrieves tasks that have not sent a heartbeat since the given cutoff time.
	FindStaleTasks(ctx context.Context, controllerID string, cutoff time.Time) ([]StaleTaskInfo, error)
}

// TaskStateHandler defines how the system reacts to task state changes,
// particularly when tasks become unresponsive. It separates state change
// detection from handling, enabling flexible recovery strategies and
// consistent system responses to task health issues.
type TaskStateHandler interface {
	// HandleTaskStale handles a task that has become unresponsive or stopped reporting progress.
	HandleTaskStale(ctx context.Context, evt TaskStaleEvent) error
}

// Execution tracking manages the lifecycle and progress of scanning tasks as they
// move through the system. It provides the interfaces needed to monitor task
// execution, handle state transitions, and maintain accurate progress information.
// This component ensures reliable task execution and provides visibility into
// scanning operations across the distributed system.

// TranslationResult represents a single translated enumeration task in scanning-domain form.
// It contains the resulting scanning Task.
// This structure is typically produced by an ACL translator that bridges the enumeration
// and scanning domains.
type TranslationResult struct {
	Task *Task
}

// ScanningResult encapsulates the scanning-domain equivalents of enumerated data, exposing
// channels of scanning-oriented objects and job-level context. These channels emit:
//
//   - ScanTargetsCh: Discovered scan target IDs (UUIDs) that need to be linked to a job.
//   - TasksCh:       TranslationResult objects, which include the scanning Task, credentials,
//     and metadata derived from enumeration tasks.
//   - ErrCh:         Errors encountered during enumeration or translation.
//
// Additionally, it provides job-level context that applies to all tasks:
//
//   - Auth:     Authentication configuration shared across all tasks in the job.
//   - Metadata: Key-value pairs containing job-wide information that may influence
//     task execution or provide context for result interpretation.
//
// By providing scanning-domain channels (instead of enumeration-domain types), this structure
// avoids cross-domain dependencies and allows the scanning domain to consume data in its
// native format without referencing enumeration logic. The job-level context fields enable
// efficient sharing of common configuration across all tasks without duplicating this
// information in each task.
type ScanningResult struct {
	ScanTargetsCh <-chan []uuid.UUID
	TasksCh       <-chan TranslationResult
	ErrCh         <-chan error

	// Job-level context. (applies to all tasks)
	Auth     Auth
	Metadata map[string]string
}

// ExecutionTracker manages the lifecycle and progress monitoring of scanning tasks
// within jobs. It processes task-related domain events and coordinates with the
// job service to maintain accurate system state and progress information.
type ExecutionTracker interface {
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
	// canceled), ensuring all enumerated items are processed and the scanning domain's job
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

	// HandleTaskPaused handles task pause events, transitioning the task to PAUSED status
	// and storing the final progress checkpoint for later resumption.
	HandleTaskPaused(ctx context.Context, evt TaskPausedEvent) error

	// HandleTaskCancelled handles task cancellation events, transitioning the task to CANCELLED status
	// and preventing further work on it.
	// This allows for explicit termination of tasks before completion.
	HandleTaskCancelled(ctx context.Context, evt TaskCancelledEvent) error

	// // GetJobProgress returns consolidated metrics for all tasks in a job, including
	// // total tasks, completed tasks, failed tasks, and overall progress percentage.
	// // This provides the data needed for job-level monitoring and reporting.
	// GetJobProgress(ctx context.Context, jobID uuid.UUID) (*scanning.Progress, error)

	// // GetTaskProgress returns detailed execution metrics for a specific task,
	// // including items processed, processing rate, error counts, and duration.
	// // This enables fine-grained monitoring of individual scanning operations.
	// GetTaskProgress(ctx context.Context, taskID uuid.UUID) (*scanning.Progress, error)
}
