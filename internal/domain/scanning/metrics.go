package scanning

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
)

// JobMetricsTracker handles aggregation and persistence of job-level metrics
// across distributed task processing. It maintains in-memory state of task
// statuses and job metrics, with periodic persistence to a backing store.
type JobMetricsTracker interface {
	// LaunchMetricsFlusher starts a background goroutine that periodically flushes metrics to storage.
	// This allows us to batch updates to storage and reduce the number of round trips.
	LaunchMetricsFlusher(interval time.Duration)

	// HandleJobMetrics processes task-related events to update job metrics.
	// It maintains both task status and aggregated job metrics in memory.
	HandleJobMetrics(ctx context.Context, evt events.EventEnvelope) error

	// FlushMetrics persists the current state of job metrics to the backing store.
	// This is typically called periodically to ensure durability of metrics.
	FlushMetrics(ctx context.Context) error

	// Stop stops the background goroutines and waits for them to finish.
	Stop(ctx context.Context)
}

// MetricsRepository defines the minimal persistence requirements for job metrics tracking.
// This interface is designed to be implemented by adapting existing job and task repositories,
// allowing for efficient access to metrics-specific data without requiring full entity loads.
type MetricsRepository interface {
	// GetJobMetrics retrieves the metrics for a specific job.
	// Returns ErrJobNotFound if the job doesn't exist.
	GetJobMetrics(ctx context.Context, jobID uuid.UUID) (*JobMetrics, error)

	// UpdateJobMetrics atomically updates the metrics for a job.
	// Returns ErrJobNotFound if the job doesn't exist or ErrInvalidMetrics if the metrics are invalid.
	UpdateJobMetrics(ctx context.Context, jobID uuid.UUID, metrics *JobMetrics) error

	// GetTaskStatus efficiently retrieves just the status of a task.
	// Returns ErrTaskNotFound if the task doesn't exist.
	GetTaskStatus(ctx context.Context, taskID uuid.UUID) (TaskStatus, error)
}
