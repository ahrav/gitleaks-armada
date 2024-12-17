package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

type HealthStatus int

const (
	HealthUnknown HealthStatus = iota
	HealthHealthy
	HealthUnhealthy
)

func (h HealthStatus) String() string {
	switch h {
	case HealthHealthy:
		return "HEALTHY"
	case HealthUnhealthy:
		return "UNHEALTHY"
	default:
		return "UNKNOWN"
	}
}

// NodeInfo represents a generic cluster node (could be orchestrator candidates or other nodes).
type NodeInfo struct {
	ID       string
	Endpoint string            // e.g., "host:port"
	Metadata map[string]string // Arbitrary metadata for platform-specific info
}

// WorkerCapacity may describe how many tasks a worker can handle concurrently.
type WorkerCapacity struct {
	MaxConcurrentTasks int
}

// WorkerInfo represents a worker node that can process scanning tasks.
type WorkerInfo struct {
	ID       string
	Endpoint string
	Metadata map[string]string
	Capacity WorkerCapacity
}

// WorkerStatus provides current state details about a worker.
type WorkerStatus struct {
	WorkerID string
	Status   HealthStatus
	// Additional optional fields: LastHeartbeatTime, CurrentTasksCount, etc.
}

// TaskFilter helps query tasks by status or other criteria.
type TaskFilter struct {
	StatusIn []string // e.g., ["pending", "in_progress", "complete"]
	// You might add other fields like date ranges, repository filters, etc.
}

// ScanTask represents a unit of work to be scanned (e.g., a repo or a specific commit).
type ScanTask struct {
	TaskID    string
	RepoURL   string
	CommitSHA string
	// Add fields as needed, such as which scanning rules to apply, chunk info, etc.
}

// Finding contains information about strings that
// have been captured by a tree-sitter query.
// TODO: Adjust this since this is from Gitleaks.
type Finding struct {
	Description string
	StartLine   int
	EndLine     int
	StartColumn int
	EndColumn   int

	Line string `json:"-"`

	Match string

	// Secret contains the full content of what is matched in
	// the tree-sitter query.
	Secret string

	// File is the name of the file containing the finding
	File        string
	SymlinkFile string
	Commit      string

	// Entropy is the shannon entropy of Value
	Entropy float32

	Author  string
	Email   string
	Date    string
	Message string
	Tags    []string

	// Rule is the name of the rule that was matched
	RuleID string

	// unique identifier
	Fingerprint string
}

type ClusterManager interface {
	ElectLeader(ctx context.Context) (bool, error)
	IsLeader(ctx context.Context) (bool, error)
	GetLeader(ctx context.Context) (*NodeInfo, error)
}

type NodeRegistry interface {
	RegisterNode(ctx context.Context, node NodeInfo) error
	UnregisterNode(ctx context.Context, nodeID string) error
	GetNodes(ctx context.Context) ([]NodeInfo, error)
	ReportHealth(ctx context.Context, nodeID string, status HealthStatus) error
	GetNodeHealth(ctx context.Context, nodeID string) (HealthStatus, error)

	RegisterWorker(ctx context.Context, worker WorkerInfo) error
	UnregisterWorker(ctx context.Context, workerID string) error
	GetAvailableWorkers(ctx context.Context) ([]WorkerInfo, error)
	UpdateWorkerStatus(ctx context.Context, status WorkerStatus) error
	GetWorkerStatus(ctx context.Context, workerID string) (WorkerStatus, error)
}

type StorageProvider interface {
	SaveTask(ctx context.Context, task *ScanTask) error
	GetTask(ctx context.Context, taskID string) (*ScanTask, error)
	ListTasks(ctx context.Context, filter TaskFilter) ([]*ScanTask, error)
	SaveFindings(ctx context.Context, taskID string, findings []Finding) error
	GetFindings(ctx context.Context, taskID string) ([]Finding, error)
	SaveState(ctx context.Context, key string, value []byte) error
	GetState(ctx context.Context, key string) ([]byte, error)
}

func main() {
	fmt.Println("Starting server...")

	// Setup gRPC server blah blah....

	exitChan := make(chan os.Signal, 1)
	signal.Notify(exitChan, os.Interrupt, syscall.SIGTERM)

	<-exitChan
	fmt.Println("Shutting down server...")
}
