package orchestration

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

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

// Run initiates the orchestrator's leadership election process and component initialization.
// It returns a channel that is closed once leadership is acquired and initialization completes,
// allowing callers to coordinate startup dependencies. The orchestrator will run until the
// context is canceled or leadership is lost.
func (o *Orchestrator) Run(ctx context.Context) (<-chan struct{}, error) {
	ready := make(chan struct{})

	// Create buffered channel to prevent blocking
	leaderCh := make(chan bool, 1)

	// Start goroutine to handle leadership **before** registering callback.
	go func() {
		defer close(ready)
		log.Println("Waiting for leadership signal...")
		select {
		case isLeader := <-leaderCh:
			log.Printf("Received leadership signal: isLeader=%v", isLeader)
			if !isLeader {
				log.Println("Not elected as leader, running in standby mode")
				<-ctx.Done()
				return
			}
			log.Println("Leadership acquired, proceeding with orchestrator start")
		case <-ctx.Done():
			log.Println("Context cancelled while waiting for leadership")
			return
		}

		// Only the leader continues past this point.
		log.Println("Elected as leader, initializing components...")
		if err := o.Start(ctx); err != nil {
			log.Printf("Failed to start orchestrator: %v", err)
			return
		}
		log.Println("Orchestrator components initialized successfully")
	}()

	o.coordinator.OnLeadershipChange(func(isLeader bool) {
		log.Printf("Leadership change: isLeader=%v", isLeader)
		select {
		case leaderCh <- isLeader:
			log.Printf("Sent leadership status: %v", isLeader)
		default:
			log.Printf("Warning: leadership channel full, skipping update")
		}
	})

	log.Println("Starting coordinator...")
	if err := o.coordinator.Start(ctx); err != nil {
		return nil, fmt.Errorf("failed to start coordinator: %v", err)
	}

	log.Println("Run method completed, returning ready channel")
	return ready, nil
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

func (o *Orchestrator) setDesiredWorkers(n int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.desiredWorkers = n
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
