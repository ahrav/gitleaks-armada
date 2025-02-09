// Package scanning provides domain types and interfaces for managing distributed scanning operations.
package scanning

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
)

// TODO: Figure out how to make sure this maps to the correct topic.
const (
	JobMetricsStreamType events.StreamType = "job-metrics"
)

// Metrics tracking provides real-time visibility into scanning operations across
// the distributed system. It handles the collection, aggregation, and persistence
// of metrics data for both individual tasks and overall jobs. The metrics system
// balances the need for real-time updates with storage efficiency through periodic
// persistence and in-memory caching.

// JobMetricsTracker handles aggregation and persistence of job-level metrics
// across distributed task processing. It maintains in-memory state for real-time
// updates while ensuring durability through periodic persistence.
type JobMetricsTracker interface {
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
