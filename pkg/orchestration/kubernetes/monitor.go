package kubernetes

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/ahrav/gitleaks-armada/pkg/orchestration"
)

// Compile-time check to verify that WorkerMonitor implements the WorkerMonitor interface.
var _ orchestration.WorkerMonitor = new(WorkerMonitor)

// WorkerMonitor is used to monitor the worker pods in a Kubernetes cluster.
type WorkerMonitor struct {
	client kubernetes.Interface
	config *K8sConfig
	active bool // tracks if monitor is running
}

// NewWorkerMonitor creates a new Kubernetes monitor with the given config.
func NewWorkerMonitor(cfg *K8sConfig) (*WorkerMonitor, error) {
	client, err := getKubernetesClient()
	if err != nil {
		return nil, fmt.Errorf("creating kubernetes client for monitor: %w", err)
	}
	return &WorkerMonitor{client: client, config: cfg}, nil
}

// Start activates the monitor. Currently a no-op but allows for future initialization.
func (m *WorkerMonitor) Start(ctx context.Context) error {
	m.active = true
	return nil
}

// Stop deactivates the monitor. Currently a no-op but allows for future cleanup.
func (m *WorkerMonitor) Stop() error {
	m.active = false
	return nil
}

// GetWorkers returns all worker pods in the cluster, identified by the "app=scanner-worker" label.
// This provides visibility into the current worker pool state for scheduling and monitoring.
func (m *WorkerMonitor) GetWorkers(ctx context.Context) ([]orchestration.Worker, error) {
	pods, err := m.client.CoreV1().Pods(m.config.Namespace).List(ctx, metav1.ListOptions{
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

// translatePodStatus converts Kubernetes pod phases to internal worker status values.
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
