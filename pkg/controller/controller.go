package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/ahrav/gitleaks-armada/pkg/cluster"
	"github.com/ahrav/gitleaks-armada/pkg/config"
	"github.com/ahrav/gitleaks-armada/pkg/messaging"
	"github.com/ahrav/gitleaks-armada/pkg/metrics"
	"github.com/ahrav/gitleaks-armada/pkg/storage"
)

// Controller coordinates work distribution across a cluster of workers.
type Controller struct {
	coordinator  cluster.Coordinator
	workQueue    messaging.Broker
	configLoader config.Loader
	credStore    *CredentialStore

	// Storage for enumeration state and checkpoints.
	enumerationStateStorage storage.EnumerationStateStorage
	checkpointStorage       storage.CheckpointStorage

	// State and control for the controller.
	mu       sync.Mutex
	running  bool
	cancelFn context.CancelFunc

	httpClient *http.Client

	metrics metrics.ControllerMetrics

	// TODO(ahrav): This is a temporary store for rules.
	rules *atomic.Value
}

// NewController creates a Controller instance that coordinates work distribution
// using the provided coordinator for leader election and broker for task queuing.
func NewController(
	coord cluster.Coordinator,
	queue messaging.Broker,
	enumerationStateStorage storage.EnumerationStateStorage,
	checkpointStorage storage.CheckpointStorage,
	configLoader config.Loader,
	metrics metrics.ControllerMetrics,
) *Controller {
	credStore, err := NewCredentialStore(make(map[string]config.AuthConfig))
	if err != nil {
		log.Printf("Warning: failed to initialize empty credential store: %v", err)
	}

	return &Controller{
		coordinator:             coord,
		workQueue:               queue,
		credStore:               credStore,
		enumerationStateStorage: enumerationStateStorage,
		checkpointStorage:       checkpointStorage,
		configLoader:            configLoader,
		httpClient:              new(http.Client),
		metrics:                 metrics,
		rules:                   new(atomic.Value),
	}
}

// Run starts the controller's leadership election process and target processing loop.
// It participates in leader election and, when elected leader, processes scan targets.
// The controller will resume any in-progress enumerations if they exist, otherwise
// it starts fresh from the configuration.
//
// Returns a channel that is closed when initialization is complete and any startup error.
// The channel allows callers to wait for the controller to be ready before proceeding.
func (o *Controller) Run(ctx context.Context) (<-chan struct{}, error) {
	ready := make(chan struct{})
	leaderCh := make(chan bool, 1)

	if err := o.workQueue.SubscribeRules(ctx, o.handleRules); err != nil {
		return nil, fmt.Errorf("failed to subscribe to rules: %v", err)
	}

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

				// Try to resume any in-progress enumeration.
				activeStates, err := o.enumerationStateStorage.GetActiveStates(ctx)
				if err != nil {
					log.Printf("Error loading enumeration state: %v", err)
				}
				log.Printf("Loaded %d active enumeration states", len(activeStates))

				if len(activeStates) == 0 {
					// No existing state, start fresh from config.
					if err := o.ProcessTarget(ctx); err != nil {
						log.Printf("Failed to process targets: %v", err)
					}
				} else {
					// Resume from existing state.
					for _, state := range activeStates {
						if err := o.doEnumeration(ctx, state); err != nil {
							log.Printf("Failed to resume enumeration: %v", err)
						}
					}
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

	log.Println("Starting coordinator...")
	if err := o.coordinator.Start(ctx); err != nil {
		return nil, fmt.Errorf("failed to start coordinator: %v", err)
	}

	return ready, nil
}

// Stop gracefully shuts down the controller if it is running.
// It is safe to call multiple times.
func (o *Controller) Stop() error {
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

	log.Println("[Controller] Stopped.")
	return nil
}

// ProcessTarget reads the configuration file and starts the enumeration process
// for each target defined in the configuration. For each target, it creates a new
// enumeration state and begins processing it. This is the entry point for starting
// fresh target scans.
func (o *Controller) ProcessTarget(ctx context.Context) error {
	cfg, err := o.configLoader.Load(ctx)
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Create new credential store with loaded config
	credStore, err := NewCredentialStore(cfg.Auth)
	if err != nil {
		return fmt.Errorf("failed to initialize credential store: %w", err)
	}
	o.credStore = credStore
	log.Println("Credential store updated successfully.")

	for _, target := range cfg.Targets {
		enumState := &storage.EnumerationState{
			SessionID:      generateSessionID(),
			SourceType:     string(target.SourceType),
			Config:         marshalConfig(target, cfg.Auth),
			LastCheckpoint: nil, // No checkpoint initially
			LastUpdated:    time.Now(),
			Status:         storage.StatusInitialized,
		}

		if err := o.enumerationStateStorage.Save(ctx, enumState); err != nil {
			return fmt.Errorf("failed to save initial enumeration state: %w", err)
		}

		if err := o.doEnumeration(ctx, enumState); err != nil {
			log.Printf("Failed to enumerate target: %v", err)
		}

	}

	return nil
}

// doEnumeration handles the core enumeration logic for a single target.
// It manages the enumeration lifecycle including state transitions and checkpoint handling.
// The function coordinates between the enumerator that produces tasks and the work queue
// that distributes them to workers.
func (o *Controller) doEnumeration(ctx context.Context, state *storage.EnumerationState) error {
	// We need the target config and the auth config to initialize the credential store.
	var combined struct {
		config.TargetSpec
		Auth config.AuthConfig `json:"auth,omitempty"`
	}

	if err := json.Unmarshal(state.Config, &combined); err != nil {
		return fmt.Errorf("failed to unmarshal target config: %w", err)
	}

	// Initialize credential store with the embedded auth config.
	if combined.Auth.Type != "" {
		credStore, err := NewCredentialStore(map[string]config.AuthConfig{
			combined.AuthRef: combined.Auth,
		})
		if err != nil {
			return fmt.Errorf("failed to initialize credential store: %w", err)
		}
		o.credStore = credStore
	}

	enumerator, err := o.createEnumerator(combined.TargetSpec)
	if err != nil {
		return err
	}

	if state.Status == storage.StatusInitialized {
		state.UpdateStatus(storage.StatusInProgress)
		if saveErr := o.enumerationStateStorage.Save(ctx, state); saveErr != nil {
			return fmt.Errorf("failed to mark enumeration state InProgress: %w", saveErr)
		}
	}

	taskCh := make(chan []messaging.Task)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for tasks := range taskCh {
			if err := o.workQueue.PublishTasks(ctx, tasks); err != nil {
				log.Printf("Failed to publish tasks: %v", err)
				return
			}
			log.Printf("Published batch of %d tasks", len(tasks))
		}
	}()

	if err := enumerator.Enumerate(ctx, state, taskCh); err != nil {
		state.UpdateStatus(storage.StatusFailed)
		if saveErr := o.enumerationStateStorage.Save(ctx, state); saveErr != nil {
			log.Printf("Failed to save enumeration state after error: %v", saveErr)
		}
		close(taskCh)
		wg.Wait()
		return fmt.Errorf("enumeration failed: %w", err)
	}

	state.UpdateStatus(storage.StatusCompleted)
	if err := o.enumerationStateStorage.Save(ctx, state); err != nil {
		close(taskCh)
		wg.Wait()
		return fmt.Errorf("failed to save enumeration state: %w", err)
	}

	close(taskCh)
	wg.Wait()
	return nil
}

// createEnumerator constructs the appropriate target enumerator based on the source type.
// It handles credential setup and validation for the target type.
func (o *Controller) createEnumerator(target config.TargetSpec) (storage.TargetEnumerator, error) {
	if o.credStore == nil {
		return nil, fmt.Errorf("credential store not initialized")
	}

	creds, err := o.credStore.GetCredentials(target.AuthRef)
	if err != nil {
		return nil, fmt.Errorf("failed to get credentials: %w", err)
	}

	var enumerator storage.TargetEnumerator
	switch target.SourceType {
	case config.SourceTypeGitHub:
		if target.GitHub == nil {
			return nil, fmt.Errorf("github target configuration is missing")
		}
		ghClient, err := NewGitHubClient(o.httpClient, creds)
		if err != nil {
			return nil, fmt.Errorf("failed to create GitHub client: %w", err)
		}
		enumerator = NewGitHubEnumerator(ghClient, creds, o.enumerationStateStorage, target.GitHub)

	case config.SourceTypeS3:
		return nil, fmt.Errorf("S3 enumerator not implemented yet")

	default:
		return nil, fmt.Errorf("unsupported source type: %s", target.SourceType)
	}

	return enumerator, nil
}

// generateSessionID creates a unique identifier for each enumeration session.
// This allows tracking and correlating all tasks and results from a single enumeration run.
func generateSessionID() string { return uuid.New().String() }

// marshalConfig serializes the target configuration into a JSON raw message.
// This allows storing the complete target configuration with the enumeration state.
func marshalConfig(target config.TargetSpec, auth map[string]config.AuthConfig) json.RawMessage {
	// Create a complete config that includes both target and its auth
	completeConfig := struct {
		config.TargetSpec
		Auth config.AuthConfig `json:"auth,omitempty"`
	}{
		TargetSpec: target,
	}

	// Include auth config if there's an auth reference.
	if auth, ok := auth[target.AuthRef]; ok {
		completeConfig.Auth = auth
	}

	data, err := json.Marshal(completeConfig)
	if err != nil {
		log.Printf("Failed to marshal target config: %v", err)
		return nil
	}
	return data
}

// generateTaskID creates a unique identifier for each scan task.
// This allows tracking individual tasks through the processing pipeline.
func generateTaskID() string { return uuid.New().String() }

func (c *Controller) handleRules(rules messaging.GitleaksRuleSet) error {
	// Store rules in memory for immediate use
	c.rules.Store(rules)

	// TODO: Persist rules to database
	// This would involve:
	// 1. Converting rules to database format
	// 2. Storing in database
	// 3. Handling any conflicts or versioning

	log.Printf("Received and stored new ruleset with %d rules", len(rules.Rules))
	for _, rule := range rules.Rules {
		log.Printf("Rule: %+v", rule)
	}
	return nil
}
