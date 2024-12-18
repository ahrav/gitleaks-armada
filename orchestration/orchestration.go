// Package orchestration provides interfaces and types for distributed work coordination.
package orchestration

import (
	"context"
)

// Coordinator manages the distributed system's control plane through leader election,
// ensuring only one instance actively coordinates work distribution at a time.
type Coordinator interface {
	// Start initiates coordination activities and leader election. It blocks until
	// the context is canceled or an error occurs.
	Start(ctx context.Context) error
	// Stop gracefully terminates coordination activities and releases leadership.
	Stop() error
}

// Supervisor manages worker nodes and distributes work across the cluster.
type Supervisor interface {
	// Start begins worker management and work distribution.
	Start(ctx context.Context) error
	// Stop gracefully shuts down worker management.
	Stop() error

	// AddWorker registers a new worker node in the cluster.
	AddWorker(ctx context.Context, worker Worker) error
	// RemoveWorker deregisters a worker node from the cluster.
	RemoveWorker(ctx context.Context, workerID string) error
	// GetWorkers returns all registered worker nodes.
	GetWorkers(ctx context.Context) ([]Worker, error)

	// AssignWork allocates a work item to a specific worker.
	AssignWork(ctx context.Context, workerID string, workID string) error
	// GetWorkerLoad returns the current work allocation status of a worker.
	GetWorkerLoad(ctx context.Context, workerID string) (WorkLoad, error)
}

// WorkLoad represents a worker's current capacity utilization.
type WorkLoad struct {
	ActiveJobs int // Number of jobs currently being processed
	QueueDepth int // Number of jobs waiting to be processed
}

// WorkerStatus indicates the operational state of a worker node.
type WorkerStatus string

const (
	WorkerStatusAvailable WorkerStatus = "available" // Ready to accept new work
	WorkerStatusBusy      WorkerStatus = "busy"      // At capacity
	WorkerStatusDraining  WorkerStatus = "draining"  // Preparing for shutdown
	WorkerStatusOffline   WorkerStatus = "offline"   // Not accepting work
)

// Worker represents a node in the cluster capable of processing work items.
type Worker struct {
	ID       string       // Unique identifier
	Endpoint string       // Network address for communication
	Status   WorkerStatus // Current operational state
}
