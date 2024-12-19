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

type WorkerMonitor interface {
	Start(ctx context.Context) error
	Stop() error
	GetWorkers(ctx context.Context) ([]Worker, error)
}

// ScanResult represents the outcome of scanning a chunk.
type ScanResult struct {
	ChunkID string
	// Additional result metadata...
}

// Broker handles task distribution and result collection via message queue
type Broker interface {
	// Task publishing (used by orchestrator)
	PublishTask(ctx context.Context, chunk Chunk) error
	PublishTasks(ctx context.Context, chunks []Chunk) error

	// Result publishing (used by scanner)
	PublishResult(ctx context.Context, result ScanResult) error

	// Task subscription (used by scanner)
	SubscribeTasks(ctx context.Context, handler func(Chunk) error) error

	// Result subscription (used by orchestrator)
	SubscribeResults(ctx context.Context, handler func(ScanResult) error) error
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
