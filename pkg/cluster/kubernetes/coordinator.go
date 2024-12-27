// Package kubernetes provides Kubernetes-specific implementations of the orchestration interfaces.
package kubernetes

import (
	"context"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"

	"github.com/ahrav/gitleaks-armada/pkg/cluster"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

// Compile-time check to verify that Coordinator implements the Coordinator interface.
var _ cluster.Coordinator = new(Coordinator)

// Coordinator manages high availability and leader election for the orchestration system
// using Kubernetes primitives. Only one coordinator is active at a time to prevent
// split-brain scenarios.
type Coordinator struct {
	client kubernetes.Interface
	config *K8sConfig

	logger *logger.Logger

	leaderElector *leaderelection.LeaderElector
	// Called when leadership status changes.
	leadershipChangeCB func(isLeader bool)
}

// NewCoordinator creates a new coordinator with the given configuration.
// It sets up leader election using Kubernetes lease locks.
func NewCoordinator(cfg *K8sConfig, logger *logger.Logger) (*Coordinator, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}

	client, err := getKubernetesClient()
	if err != nil {
		return nil, fmt.Errorf("creating kubernetes client for coordinator: %w", err)
	}

	coordinator := &Coordinator{client: client, config: cfg, logger: logger}

	// Configure lease-based leader election lock.
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
	go c.leaderElector.Run(ctx)
	<-ctx.Done()
	return nil
}

// Stop gracefully shuts down the coordinator.
func (c *Coordinator) Stop() error { return nil }

// OnLeadershipChange registers a callback that will be invoked when this instance
// gains or loses leadership.
func (c *Coordinator) OnLeadershipChange(cb func(isLeader bool)) { c.leadershipChangeCB = cb }

func (c *Coordinator) onStartedLeading(ctx context.Context) {
	c.logger.Info(ctx, "became leader")
	if c.leadershipChangeCB != nil {
		c.leadershipChangeCB(true)
	}
}

func (c *Coordinator) onStoppedLeading() {
	c.logger.Info(context.Background(), "stopped being leader")
	if c.leadershipChangeCB != nil {
		c.leadershipChangeCB(false)
	}
}
