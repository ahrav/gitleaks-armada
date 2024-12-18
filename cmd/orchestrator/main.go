package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/ahrav/gitleaks-armada/orchestration/kubernetes"
)

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
