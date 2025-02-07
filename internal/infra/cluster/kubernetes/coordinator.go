// Package kubernetes provides Kubernetes-specific implementations of the orchestration interfaces.
package kubernetes

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"

	"github.com/ahrav/gitleaks-armada/internal/app/cluster"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

// Compile-time check to verify that Coordinator implements the Coordinator interface.
var _ cluster.Coordinator = new(Coordinator)

// Coordinator manages high availability and leader election for the orchestration system
// using Kubernetes primitives. Only one coordinator is active at a time to prevent
// split-brain scenarios.
type Coordinator struct {
	controllerID string

	client kubernetes.Interface
	config *K8sConfig

	leaderElector *leaderelection.LeaderElector
	// Called when leadership status changes.
	leadershipChangeCB func(isLeader bool)

	logger *logger.Logger
	tracer trace.Tracer
}

// NewCoordinator creates a new coordinator with the given configuration.
// It sets up leader election using Kubernetes lease locks.
func NewCoordinator(controllerID string, cfg *K8sConfig, logger *logger.Logger, tracer trace.Tracer) (*Coordinator, error) {
	_, span := tracer.Start(context.Background(), "kubernetes_coordinator.new",
		trace.WithAttributes(
			attribute.String("controller_id", controllerID),
		),
	)
	defer span.End()

	if cfg == nil {
		span.RecordError(fmt.Errorf("config is required"))
		span.SetStatus(codes.Error, "config is required")
		return nil, fmt.Errorf("config is required")
	}

	logger = logger.With(
		"component", "kubernetes_coordinator",
		"namespace", cfg.Namespace,
		"leader_lock_id", cfg.LeaderLockID,
		"identity", cfg.Identity,
	)

	client, err := getKubernetesClient()
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to create kubernetes client")
		return nil, fmt.Errorf("creating kubernetes client for coordinator: %w", err)
	}
	span.AddEvent("kubernetes_client_created")

	coordinator := &Coordinator{
		controllerID: controllerID,
		client:       client,
		config:       cfg,
		logger:       logger,
		tracer:       tracer,
	}

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
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to create leader elector")
		return nil, fmt.Errorf("creating leader elector: %w", err)
	}
	coordinator.leaderElector = elector
	span.AddEvent("leader_elector_created")
	logger.Info(context.Background(), "Leader elector created")

	return coordinator, nil
}

// Start begins the leader election process and blocks until the context is canceled.
func (c *Coordinator) Start(ctx context.Context) error {
	ctx, span := c.tracer.Start(ctx, "kubernetes_coordinator.start",
		trace.WithAttributes(
			attribute.String("controller_id", c.controllerID),
		),
	)
	logger := c.logger.With("operation", "start")

	go c.leaderElector.Run(ctx)
	logger.Info(ctx, "Starting leader elector")
	span.AddEvent("leader_elector_started")
	span.End()

	<-ctx.Done()
	return nil
}

// Stop gracefully shuts down the coordinator.
func (c *Coordinator) Stop() error {
	c.logger.Info(context.Background(), "Stopping leader elector")
	return nil
}

// OnLeadershipChange registers a callback that will be invoked when this instance
// gains or loses leadership.
func (c *Coordinator) OnLeadershipChange(cb func(isLeader bool)) {
	ctx, span := c.tracer.Start(context.Background(), "kubernetes_coordinator.on_leadership_change",
		trace.WithAttributes(
			attribute.String("controller_id", c.controllerID),
		),
	)
	defer span.End()

	c.logger.Info(ctx, "Registering leadership change callback")
	c.leadershipChangeCB = cb
	span.AddEvent("leadership_change_callback_registered")
}

func (c *Coordinator) onStartedLeading(ctx context.Context) {
	ctx, span := c.tracer.Start(ctx, "kubernetes_coordinator.on_started_leading",
		trace.WithAttributes(
			attribute.String("controller_id", c.controllerID),
		),
	)
	defer span.End()

	c.logger.Info(ctx, "became leader")
	span.AddEvent("became_leader")
	if c.leadershipChangeCB != nil {
		c.leadershipChangeCB(true)
	}
}

func (c *Coordinator) onStoppedLeading() {
	ctx, span := c.tracer.Start(context.Background(), "kubernetes_coordinator.on_stopped_leading",
		trace.WithAttributes(
			attribute.String("controller_id", c.controllerID),
		),
	)
	defer span.End()

	c.logger.Info(ctx, "lost leadership")
	if c.leadershipChangeCB != nil {
		span.AddEvent("leadership_change_callback_invoked")
		c.leadershipChangeCB(false)
	}
}
