package orchestration

import (
	"context"
)

// Coordinator represents the central orchestration point
// Only one coordinator should be active at a time
type Coordinator interface {
	// Start begins coordination activities, including leader election
	Start(ctx context.Context) error
	// Stop gracefully shuts down coordination
	Stop() error
}

// Supervisor handles worker lifecycle and work distribution
type Supervisor interface {
	// Lifecycle
	Start(ctx context.Context) error
	Stop() error

	// Worker lifecycle
	AddWorker(ctx context.Context, worker Worker) error
	RemoveWorker(ctx context.Context, workerID string) error
	GetWorkers(ctx context.Context) ([]Worker, error)

	// Work distribution
	AssignWork(ctx context.Context, workerID string, workID string) error
	GetWorkerLoad(ctx context.Context, workerID string) (WorkLoad, error)
}

type WorkLoad struct {
	ActiveJobs int
	QueueDepth int
}

type WorkerStatus string

const (
	WorkerStatusAvailable WorkerStatus = "available"
	WorkerStatusBusy      WorkerStatus = "busy"
	WorkerStatusDraining  WorkerStatus = "draining"
	WorkerStatusOffline   WorkerStatus = "offline"
)

// Worker represents a single worker node in the cluster.
type Worker struct {
	ID       string
	Endpoint string
	Status   WorkerStatus
}
