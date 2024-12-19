package kubernetes

import (
	"context"
	"fmt"
	"log"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/ahrav/gitleaks-armada/pkg/orchestration"
)

// Compile-time check to verify that Supervisor implements the Supervisor interface.
var _ orchestration.Supervisor = new(Supervisor)

// Supervisor manages worker pods in a Kubernetes cluster, handling scaling and status monitoring.
type Supervisor struct {
	client kubernetes.Interface
	config *K8sConfig
	active bool // tracks if supervisor is running
}

// NewSupervisor creates a new Kubernetes supervisor with the given config.
func NewSupervisor(cfg *K8sConfig) (*Supervisor, error) {
	client, err := getKubernetesClient()
	if err != nil {
		return nil, fmt.Errorf("creating kubernetes client for supervisor: %w", err)
	}
	return &Supervisor{client: client, config: cfg}, nil
}

// Start activates the supervisor. Currently a no-op but allows for future initialization.
func (s *Supervisor) Start(ctx context.Context) error {
	s.active = true
	return nil
}

// Stop deactivates the supervisor. Currently a no-op but allows for future cleanup.
func (s *Supervisor) Stop() error {
	s.active = false
	return nil
}

// ScaleWorkers adjusts the number of worker pods by updating the deployment's replica count.
// This enables dynamic scaling of the worker pool based on workload demands.
func (s *Supervisor) ScaleWorkers(ctx context.Context, desired int) error {
	depClient := s.client.AppsV1().Deployments(s.config.Namespace)
	dep, err := depClient.Get(ctx, s.config.WorkerName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("getting worker deployment: %w", err)
	}

	replicas := int32(desired)
	dep.Spec.Replicas = &replicas

	if _, err := depClient.Update(ctx, dep, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("updating worker deployment replicas: %w", err)
	}

	log.Printf("Scaled worker deployment %s to %d replicas.", s.config.WorkerName, desired)
	return nil
}

// GetWorkers returns all worker pods in the cluster, identified by the "app=scanner-worker" label.
// This provides visibility into the current worker pool state for scheduling and monitoring.
func (s *Supervisor) GetWorkers(ctx context.Context) ([]orchestration.Worker, error) {
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
