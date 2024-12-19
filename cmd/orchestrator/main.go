package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/ahrav/gitleaks-armada/orchestration"
	"github.com/ahrav/gitleaks-armada/orchestration/kubernetes"
	orchestrationpb "github.com/ahrav/gitleaks-armada/proto/orchestration"
)

// InMemoryQueue is a simple WorkQueue example (not fully implemented).
type InMemoryQueue struct {
	// ... fields for a queue
}

// Implement WorkQueue methods for InMemoryQueue
func (q *InMemoryQueue) Enqueue(chunk orchestration.Chunk) error { return nil }
func (q *InMemoryQueue) Dequeue() (orchestration.Chunk, error) {
	return orchestration.Chunk{}, fmt.Errorf("empty")
}
func (q *InMemoryQueue) Acknowledge(chunkID string) error { return nil }

// GRPCWorkService implements the gRPC orchestrator server interface.
// It calls into the Orchestrator to handle requests.
type GRPCWorkService struct {
	orchestrator orchestration.Orchestrator
	orchestrationpb.UnimplementedOrchestratorServiceServer
}

// Make sure GRPCWorkService satisfies the generated interface.
var _ orchestrationpb.OrchestratorServiceServer = (*GRPCWorkService)(nil)

func (g *GRPCWorkService) GetNextChunk(ctx context.Context, req *orchestrationpb.GetNextChunkRequest) (*orchestrationpb.GetNextChunkResponse, error) {
	_, err := g.orchestrator.NextChunk(ctx, req.WorkerId)
	if err != nil {
		// If no chunks are available, return no_more_work = true
		return &orchestrationpb.GetNextChunkResponse{NoMoreWork: true}, nil
	}
	return &orchestrationpb.GetNextChunkResponse{
		Chunk: &orchestrationpb.Chunk{
			// ChunkId: chunk.ID,
			// Data:    chunk.Data, // assuming chunk has a Data field
		},
		NoMoreWork: false,
	}, nil
}

func (g *GRPCWorkService) CompleteChunk(ctx context.Context, req *orchestrationpb.CompleteChunkRequest) (*orchestrationpb.CompleteChunkResponse, error) {
	err := g.orchestrator.CompleteChunk(ctx, req.WorkerId, req.ChunkId)
	if err != nil {
		return &orchestrationpb.CompleteChunkResponse{Success: false}, nil
	}
	return &orchestrationpb.CompleteChunkResponse{Success: true}, nil
}

func main() {
	// This is all k8s specific for now, once this works correctly i'll adjust this to be more generic.
	podName := os.Getenv("POD_NAME")
	if podName == "" {
		log.Fatal("POD_NAME environment variable must be set")
	}

	namespace := os.Getenv("POD_NAMESPACE")
	if namespace == "" {
		log.Fatal("POD_NAMESPACE environment variable must be set")
	}

	cfg := &kubernetes.K8sConfig{
		Namespace:    namespace,
		LeaderLockID: "scanner-leader-lock",
		Identity:     podName,
		Name:         "orchestrator",
	}

	coordinator, err := kubernetes.NewCoordinator(cfg)
	if err != nil {
		log.Fatalf("failed to create coordinator: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		log.Printf("received signal %s, initiating shutdown", sig)
		cancel()
	}()

	log.Printf("starting coordinator")
	if err := coordinator.Start(ctx); err != nil {
		log.Fatalf("coordinator failed: %v", err)
	}
}
