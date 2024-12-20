package orchestration

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"

	"github.com/ahrav/gitleaks-armada/pkg/config"
)

// Orchestrator coordinates work distribution across a cluster of workers.
type Orchestrator struct {
	coordinator Coordinator
	workQueue   Broker
	credStore   *CredentialStore

	mu            sync.Mutex
	running       bool
	cancelFn      context.CancelFunc
	currentTarget *config.TargetSpec
}

// NewOrchestrator creates an Orchestrator instance that coordinates work distribution
// using the provided coordinator for leader election and broker for task queuing.
func NewOrchestrator(coord Coordinator, queue Broker) *Orchestrator {
	return &Orchestrator{
		coordinator: coord,
		workQueue:   queue,
	}
}

// Run starts the orchestrator's leadership election process and target processing loop.
// Returns a channel that is closed when initialization is complete and any startup error.
func (o *Orchestrator) Run(ctx context.Context) (<-chan struct{}, error) {
	ready := make(chan struct{})
	leaderCh := make(chan bool, 1)

	o.coordinator.OnLeadershipChange(func(isLeader bool) {
		log.Printf("Leadership change: isLeader=%v", isLeader)

		o.mu.Lock()
		o.running = isLeader
		if !isLeader && o.cancelFn != nil {
			o.cancelFn()
			o.cancelFn = nil
		}
		o.mu.Unlock()

		select {
		case leaderCh <- isLeader:
			log.Printf("Sent leadership status: %v", isLeader)
		default:
			log.Printf("Warning: leadership channel full, skipping update")
		}
	})

	go func() {
		readyClosed := false
		log.Println("Waiting for leadership signal...")

		for {
			select {
			case isLeader := <-leaderCh:
				if !isLeader {
					log.Println("Not leader, waiting...")
					continue
				}

				log.Println("Leadership acquired, processing targets...")
				if err := o.ProcessTarget(ctx); err != nil {
					log.Printf("Failed to process targets: %v", err)
				}

				if !readyClosed {
					close(ready)
					readyClosed = true
				}

			case <-ctx.Done():
				log.Println("Context cancelled, shutting down")
				if !readyClosed {
					close(ready)
				}
				return
			}
		}
	}()

	// Start the coordinator after after the leadership channel is ready.
	log.Println("Starting coordinator...")
	if err := o.coordinator.Start(ctx); err != nil {
		return nil, fmt.Errorf("failed to start coordinator: %v", err)
	}

	return ready, nil
}

// Stop gracefully shuts down the orchestrator if it is running.
// Safe to call multiple times.
func (o *Orchestrator) Stop() error {
	o.mu.Lock()
	if !o.running {
		o.mu.Unlock()
		return nil
	}
	o.running = false
	if o.cancelFn != nil {
		o.cancelFn()
	}
	o.mu.Unlock()

	log.Println("[Orchestrator] Stopped.")
	return nil
}

// ProcessTarget reads the configuration file and creates scan tasks for each target.
// It handles authentication, creates appropriate tasks based on source type (GitHub/S3),
// and publishes them to the work queue for processing.
func (o *Orchestrator) ProcessTarget(ctx context.Context) error {
	const configPath = "/etc/scanner/config/config.yaml"

	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg config.Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("failed to parse config: %w", err)
	}

	credStore, err := NewCredentialStore(cfg.Auth)
	if err != nil {
		return fmt.Errorf("failed to initialize credential store: %w", err)
	}
	o.credStore = credStore
	log.Println("Credential store initialized successfully.")

	for _, target := range cfg.Targets {
		creds, err := o.credStore.GetCredentials(target.AuthRef)
		if err != nil {
			return fmt.Errorf("failed to get credentials for target: %w", err)
		}

		var tasks []Task

		switch target.SourceType {
		case config.SourceTypeGitHub:
			if target.GitHub == nil {
				return fmt.Errorf("github target configuration is missing")
			}

			// Create task for scanning entire org if specified.
			if target.GitHub.Org != "" {
				tasks = append(tasks, Task{
					TaskID:      generateTaskID(),
					ResourceURI: buildResourceURI(target.SourceType, "org/"+target.GitHub.Org),
					Metadata:    target.GitHub.Metadata,
					Credentials: creds,
				})
			}

			// Create tasks for individual repos.
			for _, repo := range target.GitHub.RepoList {
				tasks = append(tasks, Task{
					TaskID:      generateTaskID(),
					ResourceURI: buildResourceURI(target.SourceType, "repo/"+repo),
					Metadata:    target.GitHub.Metadata,
					Credentials: creds,
				})
			}

		case config.SourceTypeS3:
			if target.S3 == nil {
				return fmt.Errorf("s3 target configuration is missing")
			}

			resource := target.S3.Bucket
			if target.S3.Prefix != "" {
				resource = resource + "/" + target.S3.Prefix
			}

			tasks = append(tasks, Task{
				TaskID:      generateTaskID(),
				ResourceURI: buildResourceURI(target.SourceType, resource),
				Metadata:    target.S3.Metadata,
				Credentials: creds,
			})
		}

		if err := o.workQueue.PublishTasks(ctx, tasks); err != nil {
			return fmt.Errorf("failed to publish tasks: %w", err)
		}
	}

	return nil
}

// generateTaskID creates a unique identifier for each scan task.
func generateTaskID() string { return uuid.New().String() }

// buildResourceURI creates a standardized URI for scan targets in the format "type://resource".
func buildResourceURI(sourceType config.SourceType, resource string) string {
	return fmt.Sprintf("%s://%s", sourceType, resource)
}
