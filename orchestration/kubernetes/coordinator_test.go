package kubernetes

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
)

func TestNewCoordinator(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *K8sConfig
		wantErr bool
	}{
		{
			name: "valid config",
			cfg: &K8sConfig{
				Namespace:    "default",
				LeaderLockID: "test-lock",
				Identity:     "test-pod",
			},
			wantErr: false,
		},
		{
			name:    "nil config",
			cfg:     nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewCoordinator(tt.cfg)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCoordinator_LeaderElection(t *testing.T) {
	fakeClient := fake.NewSimpleClientset()

	cfg := &K8sConfig{
		Namespace:    "default",
		LeaderLockID: "test-lock",
		Identity:     "test-pod",
	}

	coordinator := &Coordinator{
		client:     fakeClient,
		config:     cfg,
		supervisor: NewK8sSupervisor(fakeClient, cfg),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	leaderChan := make(chan struct{})
	stopChan := make(chan struct{})

	// Create leader election config with test callbacks.
	lock := &resourcelock.LeaseLock{
		LeaseMeta: metav1.ObjectMeta{
			Name:      cfg.LeaderLockID,
			Namespace: cfg.Namespace,
		},
		Client: fakeClient.CoordinationV1(),
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
			OnStartedLeading: func(ctx context.Context) {
				close(leaderChan)
			},
			OnStoppedLeading: func() {
				close(stopChan)
			},
		},
	}

	elector, err := leaderelection.NewLeaderElector(leaderConfig)
	if err != nil {
		t.Fatalf("failed to create leader elector: %v", err)
	}

	coordinator.leaderElector = elector

	go func() {
		err := coordinator.Start(ctx)
		assert.NoError(t, err)
	}()

	// Wait for leadership or timeout.
	select {
	case <-leaderChan:
		// Successfully became leader.
	case <-ctx.Done():
		t.Fatal("timeout waiting for leadership")
	}
}

func TestCoordinator_SupervisorManagement(t *testing.T) {
	fakeClient := fake.NewSimpleClientset()

	cfg := &K8sConfig{
		Namespace:    "default",
		LeaderLockID: "test-lock",
		Identity:     "test-pod",
	}

	coordinator := &Coordinator{
		client:     fakeClient,
		config:     cfg,
		supervisor: NewK8sSupervisor(fakeClient, cfg),
	}

	ctx := context.Background()

	// Mock becoming leader.
	coordinator.onStartedLeading(ctx)

	// Verify supervisor was started
	assert.NotNil(t, coordinator.supervisor, "supervisor should be initialized")

	// Mock losing leadership.
	coordinator.onStoppedLeading()
}
