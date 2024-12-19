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

// WorkerMonitor is an optional interface for monitoring worker nodes.
type WorkerMonitor interface {
	// Start initializes the worker monitoring service.
	Start(ctx context.Context) error
	// Stop gracefully terminates the worker monitoring service.
	Stop() error
	// GetWorkers retrieves the current list of worker nodes.
	GetWorkers(ctx context.Context) ([]Worker, error)
}

// Broker handles task distribution and result collection via message queue.
type Broker interface {
	// Task publishing (used by orchestrator).
	PublishTask(ctx context.Context, task Task) error
	// PublishTasks publishes multiple tasks in a batch.
	PublishTasks(ctx context.Context, tasks []Task) error
	// Result publishing (used by scanner).
	PublishResult(ctx context.Context, result ScanResult) error
	// PublishProgress publishes progress updates for a scan task.
	PublishProgress(ctx context.Context, progress ScanProgress) error

	// Task subscription (used by scanner).
	SubscribeTasks(ctx context.Context, handler func(Task) error) error
	// Result subscription (used by orchestrator).
	SubscribeResults(ctx context.Context, handler func(ScanResult) error) error
	// Progress subscription (used by scanner).
	SubscribeProgress(ctx context.Context, handler func(ScanProgress) error) error
}

// Task represents a unit of scanning work to be processed by workers.
// It contains the necessary information to locate and scan a resource.
type Task struct {
	TaskID      string            // Unique identifier for the task
	ResourceURI string            // Location of the resource to scan
	Metadata    map[string]string // Additional context for task processing
	// SourceType handling is omitted for brevity, assume a separate enum/field
}

// Finding represents a single secret or sensitive data match discovered during scanning.
type Finding struct {
	Location   string  // Where the secret was found (e.g., file path)
	LineNumber int32   // Line number in the source file
	SecretType string  // Category of secret (e.g., "API Key", "Password")
	Match      string  // The actual text that matched
	Confidence float64 // Probability that this is a true positive
}

// ScanStatus represents the completion state of a scan operation.
type ScanStatus string

const (
	ScanStatusUnspecified ScanStatus = "UNSPECIFIED" // Initial or unknown state
	ScanStatusSuccess     ScanStatus = "SUCCESS"     // Scan completed successfully
	ScanStatusError       ScanStatus = "ERROR"       // Scan failed
)

// ScanResult contains the findings and status from a completed scan task.
type ScanResult struct {
	TaskID   string    // References the original Task
	Findings []Finding // List of discovered secrets
	Status   ScanStatus
	Error    string // Description of failure if Status is ERROR
}

// ScanProgress provides information about an ongoing scan operation.
type ScanProgress struct {
	TaskID          string
	PercentComplete float32           // Overall scan progress (0-100)
	ItemsProcessed  int64             // Number of items (e.g., files) processed
	TotalItems      int64             // Total number of items to process
	Metadata        map[string]string // Additional progress information
}

// ScanTarget represents a data source to be scanned, broken into processable chunks.
type ScanTarget struct {
	ID     string
	Type   string // Type of data source (e.g., "filesystem", "git-repo")
	Size   int64  // Estimated size in bytes
	Chunks []Task // Subdivided work units for parallel processing
}

// WorkerStatus indicates the operational state of a worker node.
type WorkerStatus string

const (
	WorkerStatusAvailable WorkerStatus = "available" // Ready to accept new tasks
	WorkerStatusBusy      WorkerStatus = "busy"      // Currently processing a task
	WorkerStatusDraining  WorkerStatus = "draining"  // Completing current work before shutdown
	WorkerStatusOffline   WorkerStatus = "offline"   // Not accepting new work
)

// Worker represents a processing node in the scanning cluster.
type Worker struct {
	ID       string       // Unique identifier for the worker
	Endpoint string       // Network address for communication
	Status   WorkerStatus // Current operational state
}
