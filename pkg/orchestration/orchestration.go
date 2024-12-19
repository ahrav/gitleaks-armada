// Package orchestration provides interfaces and types for distributed work coordination.
package orchestration

import (
	"context"
)

// Coordinator manages leader election to ensure only one instance actively coordinates work.
type Coordinator interface {
	// Start initiates coordination and blocks until context cancellation or error.
	Start(ctx context.Context) error
	// Stop gracefully terminates coordination.
	Stop() error
	// OnLeadershipChange registers a callback for leadership status changes.
	OnLeadershipChange(cb func(isLeader bool))
}

// Supervisor manages a pool of worker nodes, handling scaling and monitoring.
type Supervisor interface {
	Start(ctx context.Context) error
	Stop() error
	ScaleWorkers(ctx context.Context, desired int) error
	GetWorkers(ctx context.Context) ([]Worker, error)
}

// Chunk represents a unit of work to be processed.
type Chunk struct{}

// ScanTarget represents a data source to be scanned, broken into processable chunks.
type ScanTarget struct {
	ID     string
	Type   string  // e.g., "filesystem", "git-repo"
	Size   int64   // estimated size in bytes
	Chunks []Chunk // subdivided work units
}

// WorkerStatus indicates the operational state of a worker node.
type WorkerStatus string

const (
	WorkerStatusAvailable WorkerStatus = "available"
	WorkerStatusBusy      WorkerStatus = "busy"
	WorkerStatusDraining  WorkerStatus = "draining"
	WorkerStatusOffline   WorkerStatus = "offline"
)

// Worker represents a processing node in the cluster.
type Worker struct {
	ID       string
	Endpoint string
	Status   WorkerStatus
}
