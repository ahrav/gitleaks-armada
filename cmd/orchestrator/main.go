package main

import (
	"context"
	"log"
	"net"
	"os"

	"github.com/ahrav/gitleaks-armada/pkg/orchestration"
	"github.com/ahrav/gitleaks-armada/pkg/orchestration/kubernetes"
	"github.com/ahrav/gitleaks-armada/pkg/server"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
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
		Name:         "scanner-orchestrator",
		WorkerName:   "scanner-worker",
	}

	coord, err := kubernetes.NewCoordinator(cfg)
	if err != nil {
		log.Fatalf("failed to create coordinator: %v", err)
	}
	defer coord.Stop()

	log.Println("Coordinator created successfully")

	sup, err := kubernetes.NewSupervisor(cfg)
	if err != nil {
		log.Fatalf("failed to create supervisor: %v", err)
	}
	defer sup.Stop()
	log.Println("Supervisor created successfully")

	queue := new(orchestration.InMemoryQueue)
	orch := orchestration.NewOrchestrator(coord, sup, queue)

	// Run orchestrator and wait for leadership.
	log.Println("Starting orchestrator...")
	ready, err := orch.Run(ctx)
	if err != nil {
		log.Fatalf("failed to run orchestrator: %v", err)
	}

	log.Println("Waiting for leadership...")
	select {
	case <-ready:
		log.Println("Leadership acquired, starting gRPC server...")
		// Only the leader will get here.
		lis, err := net.Listen("tcp", ":50051")
		if err != nil {
			log.Fatalf("failed to listen: %v", err)
		}

		workService := server.New(orch)
		log.Println("Starting gRPC server on :50051")
		if err := workService.Serve(lis); err != nil {
			log.Fatalf("failed to serve gRPC: %v", err)
		}
	case <-ctx.Done():
		return
	}
}
