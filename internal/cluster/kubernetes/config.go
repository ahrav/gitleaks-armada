package kubernetes

type K8sConfig struct {
	Type         string            `json:"type"` // e.g., "kubernetes", "standalone"
	Name         string            `json:"name"` // Name of this orchestration instance
	Tags         map[string]string `json:"tags"`
	Namespace    string            `json:"namespace"`
	LeaderLockID string            `json:"leaderLockId"`
	Identity     string            `json:"identity"`
	WorkerName   string            `json:"workerName"`
	KubeConfig   string            `json:"kubeConfig,omitempty"`
	Context      string            `json:"context,omitempty"`
}
