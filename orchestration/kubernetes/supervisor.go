package kubernetes

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/ahrav/gitleaks-armada/orchestration"
)

// K8sSupervisor implements the Supervisor interface using Kubernetes primitives.
// It manages worker pods and handles work distribution in a Kubernetes cluster.
type K8sSupervisor struct {
	client kubernetes.Interface
	config *K8sConfig
	active bool // Tracks if supervisor is currently running
}

// NewK8sSupervisor creates a new supervisor instance with the given Kubernetes client and config.
func NewK8sSupervisor(client kubernetes.Interface, cfg *K8sConfig) *K8sSupervisor {
	return &K8sSupervisor{client: client, config: cfg}
}

// Start initializes the supervisor and begins monitoring workers.
// Currently a no-op but will be expanded to handle worker lifecycle management.
func (s *K8sSupervisor) Start(ctx context.Context) error {
	s.active = true
	return nil
}

// Stop gracefully shuts down the supervisor and cleans up resources.
func (s *K8sSupervisor) Stop() error {
	s.active = false
	return nil
}

// AddWorker registers a new worker pod with the supervisor.
// Currently a no-op as pods are tracked automatically via labels.
func (s *K8sSupervisor) AddWorker(ctx context.Context, worker orchestration.Worker) error {
	return nil
}

// RemoveWorker deregisters a worker pod from the supervisor.
// Currently a no-op as pod lifecycle is managed by Kubernetes.
func (s *K8sSupervisor) RemoveWorker(ctx context.Context, workerID string) error {
	return nil
}

// GetWorkers returns a list of all worker pods in the cluster.
// Workers are identified by the "app=scanner-worker" label.
func (s *K8sSupervisor) GetWorkers(ctx context.Context) ([]orchestration.Worker, error) {
	pods, err := s.client.CoreV1().Pods(s.config.Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: "app=scanner-worker",
	})
	if err != nil {
		return nil, fmt.Errorf("listing worker pods: %w", err)
	}

	var workers []orchestration.Worker
	for _, pod := range pods.Items {
		workers = append(workers, orchestration.Worker{
			ID:       pod.Name,
			Endpoint: pod.Status.PodIP,
			Status:   translatePodStatus(pod.Status.Phase),
		})
	}

	return workers, nil
}

// AssignWork assigns a specific work item to a worker pod.
func (s *K8sSupervisor) AssignWork(ctx context.Context, workerID string, workID string) error {
	// Here we'd need to decide how to track work assignments
	// Could be:
	// 1. Update pod annotations/labels
	// 2. Create a Custom Resource for work tracking
	// 3. Use a separate data store
	return nil
}

// GetWorkerLoad returns the current workload metrics for a specific worker pod.
func (s *K8sSupervisor) GetWorkerLoad(ctx context.Context, workerID string) (orchestration.WorkLoad, error) {
	// This would need to check:
	// 1. Pod metrics
	// 2. Current work assignments
	// 3. Any queued work
	return orchestration.WorkLoad{}, nil
}

func translatePodStatus(phase corev1.PodPhase) orchestration.WorkerStatus {
	switch phase {
	case corev1.PodRunning:
		return orchestration.WorkerStatusAvailable
	case corev1.PodPending:
		return orchestration.WorkerStatusOffline
	default:
		return orchestration.WorkerStatusOffline
	}
}
