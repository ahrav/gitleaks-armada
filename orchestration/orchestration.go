// Package orchestration provides interfaces and types for distributed work coordination.
package orchestration

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

type WorkService interface {
	GetNextChunk(ctx context.Context, workerID string) (Chunk, bool, error) // bool for noMoreWork
	CompleteChunk(ctx context.Context, workerID, chunkID string) error
}

// Coordinator manages leader election to ensure only one instance actively coordinates work.
type Coordinator interface {
	// Start initiates coordination and blocks until context cancellation or error.
	Start(ctx context.Context) error
	// Stop gracefully terminates coordination.
	Stop() error
	// OnLeadershipChange registers a callback for leadership status changes.
	OnLeadershipChange(cb func(isLeader bool))
}

// WorkQueue manages the distribution of work chunks to workers.
type WorkQueue interface {
	Enqueue(chunk Chunk) error
	Dequeue() (Chunk, error)
	Acknowledge(chunkID string) error
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

// WorkStatus provides metrics about the current work progress.
type WorkStatus struct {
	TotalChunks     int
	CompletedChunks int
	ActiveWorkers   int
	PendingWork     int
}

// WorkLoad represents a worker's current capacity utilization.
type WorkLoad struct {
	ActiveJobs int
	QueueDepth int
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

// Orchestrator coordinates work distribution across a cluster of workers.
type Orchestrator struct {
	coordinator Coordinator
	supervisor  Supervisor
	workQueue   WorkQueue

	mu       sync.Mutex
	running  bool
	cancelFn context.CancelFunc

	currentTarget  *ScanTarget
	desiredWorkers int
}

// NewOrchestrator creates an orchestrator with the given components and registers leadership callbacks.
func NewOrchestrator(coord Coordinator, sup Supervisor, queue WorkQueue) *Orchestrator {
	o := &Orchestrator{
		coordinator: coord,
		supervisor:  sup,
		workQueue:   queue,
	}
	o.coordinator.OnLeadershipChange(o.handleLeadershipChange)
	return o
}

// Start initializes the orchestrator and begins monitoring workers.
func (o *Orchestrator) Start(ctx context.Context) error {
	o.mu.Lock()
	if o.running {
		o.mu.Unlock()
		return fmt.Errorf("orchestrator already running")
	}
	o.running = true
	ctx, o.cancelFn = context.WithCancel(ctx)
	o.mu.Unlock()

	log.Println("[Orchestrator] Starting supervisor...")
	if err := o.supervisor.Start(ctx); err != nil {
		return fmt.Errorf("failed to start supervisor: %w", err)
	}

	go o.monitorWorkers(ctx)

	log.Println("[Orchestrator] Started successfully.")
	return nil
}

// Stop gracefully shuts down the orchestrator and its components.
func (o *Orchestrator) Stop() error {
	o.mu.Lock()
	if !o.running {
		o.mu.Unlock()
		return nil
	}
	o.running = false
	if o.cancelFn != nil {
		o.cancelFn()
	}
	o.mu.Unlock()

	log.Println("[Orchestrator] Stopping supervisor...")
	if err := o.supervisor.Stop(); err != nil {
		log.Printf("error stopping supervisor: %v", err)
	}
	log.Println("[Orchestrator] Stopped.")
	return nil
}

// ProcessTarget breaks down a target into chunks and enqueues them for processing.
func (o *Orchestrator) ProcessTarget(ctx context.Context, target ScanTarget) error {
	// Calculate chunks based on target size
	chunkCount := int(target.Size / 1024 / 1024)
	if chunkCount == 0 {
		chunkCount = 1
	}

	for i := 0; i < chunkCount; i++ {
		chunk := Chunk{}
		if err := o.workQueue.Enqueue(chunk); err != nil {
			return fmt.Errorf("enqueue chunk: %w", err)
		}
	}

	o.mu.Lock()
	o.currentTarget = &target
	o.mu.Unlock()

	// Scale workers based on chunk count
	desired := chunkCount / 100
	if desired < 1 {
		desired = 1
	}
	o.setDesiredWorkers(desired)

	return nil
}

// NextChunk returns the next available chunk for a worker to process.
func (o *Orchestrator) NextChunk(ctx context.Context, workerID string) (Chunk, error) {
	chunk, err := o.workQueue.Dequeue()
	if err != nil {
		return Chunk{}, fmt.Errorf("no chunks available: %w", err)
	}
	return chunk, nil
}

// CompleteChunk marks a chunk as successfully processed.
func (o *Orchestrator) CompleteChunk(ctx context.Context, workerID, chunkID string) error {
	return o.workQueue.Acknowledge(chunkID)
}

func (o *Orchestrator) handleLeadershipChange(isLeader bool) {
	if isLeader {
		ctx := context.Background()
		if err := o.Start(ctx); err != nil {
			log.Printf("[Orchestrator] Error starting as leader: %v", err)
		}
	} else {
		if err := o.Stop(); err != nil {
			log.Printf("[Orchestrator] Error stopping after losing leadership: %v", err)
		}
	}
}

func (o *Orchestrator) monitorWorkers(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			workers, err := o.supervisor.GetWorkers(ctx)
			if err != nil {
				log.Printf("error getting workers: %v", err)
				continue
			}

			availableCount := 0
			for _, w := range workers {
				if w.Status == WorkerStatusAvailable {
					availableCount++
				}
			}

			o.mu.Lock()
			desired := o.desiredWorkers
			o.mu.Unlock()

			if availableCount != desired {
				if err := o.supervisor.ScaleWorkers(ctx, desired); err != nil {
					log.Printf("failed to scale workers: %v", err)
				}
			}
		}
	}
}

func (o *Orchestrator) setDesiredWorkers(n int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.desiredWorkers = n
}
