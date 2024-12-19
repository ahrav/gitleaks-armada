// Package kubernetes provides Kubernetes-specific implementations of the orchestration interfaces.
package kubernetes

import (
	"context"
	"fmt"
	"log"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"

	"github.com/ahrav/gitleaks-armada/orchestration"
)

// Compile-time check to verify that Coordinator implements the Coordinator interface.
var _ orchestration.Coordinator = new(Coordinator)

// Coordinator manages high availability and leader election for the orchestration system
// using Kubernetes primitives. Only one coordinator is active at a time to prevent
// split-brain scenarios.
type Coordinator struct {
	client        kubernetes.Interface
	config        *K8sConfig
	leaderElector *leaderelection.LeaderElector
	supervisor    *Supervisor
	// Called when leadership status changes
	leadershipChangeCB func(isLeader bool)
}

// NewCoordinator creates a new coordinator with the given configuration.
// It sets up leader election using Kubernetes lease locks.
func NewCoordinator(cfg *K8sConfig) (*Coordinator, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}

	client, err := getKubernetesClient()
	if err != nil {
		return nil, fmt.Errorf("creating kubernetes client: %w", err)
	}

	supervisor := NewSupervisor(client, cfg)

	coordinator := &Coordinator{
		client:     client,
		config:     cfg,
		supervisor: supervisor,
	}

	// Configure lease-based leader election lock
	lock := &resourcelock.LeaseLock{
		LeaseMeta: metav1.ObjectMeta{
			Name:      cfg.LeaderLockID,
			Namespace: cfg.Namespace,
		},
		Client: client.CoordinationV1(),
		LockConfig: resourcelock.ResourceLockConfig{
			Identity: cfg.Identity,
		},
	}

	leaderConfig := leaderelection.LeaderElectionConfig{
		Lock:            lock,
		LeaseDuration:   15 * time.Second,
		RenewDeadline:   10 * time.Second,
		RetryPeriod:     2 * time.Second,
		ReleaseOnCancel: true,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: coordinator.onStartedLeading,
			OnStoppedLeading: coordinator.onStoppedLeading,
		},
	}

	elector, err := leaderelection.NewLeaderElector(leaderConfig)
	if err != nil {
		return nil, fmt.Errorf("creating leader elector: %w", err)
	}

	coordinator.leaderElector = elector
	return coordinator, nil
}

// Start begins the leader election process and blocks until the context is canceled.
func (c *Coordinator) Start(ctx context.Context) error {
	go func() {
		c.leaderElector.Run(ctx)
	}()
	<-ctx.Done()
	return nil
}

// Stop gracefully shuts down the coordinator.
func (c *Coordinator) Stop() error {
	return nil
}

// OnLeadershipChange registers a callback that will be invoked when this instance
// gains or loses leadership.
func (c *Coordinator) OnLeadershipChange(cb func(isLeader bool)) {
	c.leadershipChangeCB = cb
}

func (c *Coordinator) onStartedLeading(ctx context.Context) {
	log.Println("became leader, starting supervisor")
	if err := c.supervisor.Start(ctx); err != nil {
		log.Printf("failed to start supervisor: %v", err)
	}

	if c.leadershipChangeCB != nil {
		c.leadershipChangeCB(true)
	}
}

func (c *Coordinator) onStoppedLeading() {
	log.Println("stopped being leader, cleaning up")
	c.supervisor.Stop()

	if c.leadershipChangeCB != nil {
		c.leadershipChangeCB(false)
	}
}
