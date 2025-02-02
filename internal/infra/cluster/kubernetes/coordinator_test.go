package kubernetes

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
)

func TestCoordinator_LeaderElection(t *testing.T) {
	fakeClient := fake.NewSimpleClientset()

	cfg := &K8sConfig{
		Namespace:    "default",
		LeaderLockID: "test-lock",
		Identity:     "test-pod",
	}

	coordinator := &Coordinator{
		client: fakeClient,
		config: cfg,
		logger: logger.New(io.Discard, logger.LevelDebug, "test", nil),
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
