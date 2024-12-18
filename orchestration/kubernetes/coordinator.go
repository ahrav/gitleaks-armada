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
)

// Coordinator implements the Coordinator interface using Kubernetes primitives.
// It ensures high availability by using leader election to designate a single active coordinator.
type Coordinator struct {
	client        kubernetes.Interface
	config        *K8sConfig
	leaderElector *leaderelection.LeaderElector

	// supervisor is used to manage worker pods and distribute work.
	supervisor *Supervisor
}

// NewCoordinator creates a new K8sCoordinator with the provided configuration.
// It initializes the Kubernetes client and sets up leader election using lease locks.
func NewCoordinator(cfg *K8sConfig) (*Coordinator, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}

	client, err := getKubernetesClient()
	if err != nil {
		return nil, fmt.Errorf("creating kubernetes client: %w", err)
	}

	supervisor := NewK8sSupervisor(client, cfg)

	coordinator := &Coordinator{
		client:     client,
		config:     cfg,
		supervisor: supervisor,
	}

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
		LeaseDuration:   time.Second * 15,
		RenewDeadline:   time.Second * 10,
		RetryPeriod:     time.Second * 2,
		ReleaseOnCancel: true,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: coordinator.onStartedLeading,
			OnStoppedLeading: coordinator.onStoppedLeading,
		},
		// TODO: Add a watch dog.
	}

	elector, err := leaderelection.NewLeaderElector(leaderConfig)
	if err != nil {
		return nil, fmt.Errorf("creating leader elector: %w", err)
	}

	coordinator.leaderElector = elector
	return coordinator, nil
}

// Start begins the leader election process. Only one coordinator in the cluster
// will become the leader and actively manage work distribution.
func (c *Coordinator) Start(ctx context.Context) error {
	go func() {
		c.leaderElector.Run(ctx)
		// If we get here, leadership was lost or context cancelled.
		// TODO: Handle shutdown.
		// c.handleShutdown()
	}()

	<-ctx.Done()
	return nil
}

// onStartedLeading is called when this coordinator instance becomes the leader.
// It initializes the supervisor and begins work distribution.
func (c *Coordinator) onStartedLeading(ctx context.Context) {
	log.Println("became leader, starting supervisor")
	if err := c.supervisor.Start(ctx); err != nil {
		log.Printf("failed to start supervisor: %v", err)
		// Maybe trigger pod restart?
	}
}

// onStoppedLeading is called when this coordinator instance loses leadership.
// It cleans up resources and stops the supervisor.
func (c *Coordinator) onStoppedLeading() {
	log.Println("stopped being leader, cleaning up")
	c.supervisor.Stop()
}
