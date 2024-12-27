package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/pkg/cluster"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
	"github.com/ahrav/gitleaks-armada/pkg/config"
	"github.com/ahrav/gitleaks-armada/pkg/messaging"
	"github.com/ahrav/gitleaks-armada/pkg/metrics"
	"github.com/ahrav/gitleaks-armada/pkg/storage"
)

// Controller coordinates work distribution across a cluster of workers.
type Controller struct {
	id string

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

	logger  *logger.Logger
	metrics metrics.ControllerMetrics

	// TODO(ahrav): This is a temporary store for rules.
	rules *atomic.Value

	tracer trace.Tracer
}

// NewController creates a Controller instance that coordinates work distribution
// using the provided coordinator for leader election and broker for task queuing.
func NewController(
	id string,
	coord cluster.Coordinator,
	queue messaging.Broker,
	enumerationStateStorage storage.EnumerationStateStorage,
	checkpointStorage storage.CheckpointStorage,
	configLoader config.Loader,
	logger *logger.Logger,
	metrics metrics.ControllerMetrics,
	tracer trace.Tracer,
) *Controller {
	credStore, err := NewCredentialStore(make(map[string]config.AuthConfig))
	if err != nil {
		logger.Error(context.Background(), "Warning: failed to initialize empty credential store", "error", err)
	}

	return &Controller{
		id:                      id,
		coordinator:             coord,
		workQueue:               queue,
		credStore:               credStore,
		enumerationStateStorage: enumerationStateStorage,
		checkpointStorage:       checkpointStorage,
		configLoader:            configLoader,
		httpClient:              new(http.Client),
		metrics:                 metrics,
		rules:                   new(atomic.Value),
		logger:                  logger,
		tracer:                  tracer,
	}
}

// Run starts the controller's leadership election process and target processing loop.
// It participates in leader election and, when elected leader, processes scan targets.
// The controller will resume any in-progress enumerations if they exist, otherwise
// it starts fresh from the configuration.
//
// Returns a channel that is closed when initialization is complete and any startup error.
// The channel allows callers to wait for the controller to be ready before proceeding.
func (c *Controller) Run(ctx context.Context) (<-chan struct{}, error) {
	ready := make(chan struct{})
	leaderCh := make(chan bool, 1)

	if err := c.workQueue.SubscribeRules(ctx, c.handleRules); err != nil {
		return nil, fmt.Errorf("[%s] failed to subscribe to rules: %v", c.id, err)
	}

	c.coordinator.OnLeadershipChange(func(isLeader bool) {
		c.logger.Info(ctx, "[%s] Leadership change: isLeader=%v", c.id, isLeader)

		c.mu.Lock()
		c.running = isLeader
		if !isLeader && c.cancelFn != nil {
			c.cancelFn()
			c.cancelFn = nil
		}
		c.mu.Unlock()

		select {
		case leaderCh <- isLeader:
			c.logger.Info(ctx, "[%s] Sent leadership status: %v", c.id, isLeader)
		default:
			c.logger.Info(ctx, "[%s] Warning: leadership channel full, skipping update", c.id)
		}
	})

	go func() {
		readyClosed := false
		c.logger.Info(ctx, "Waiting for leadership signal...")

		for {
			select {
			case isLeader := <-leaderCh:
				if !isLeader {
					c.logger.Info(ctx, "[%s] Not leader, waiting...", c.id)
					continue
				}

				c.logger.Info(ctx, "[%s] Leadership acquired, processing targets...", c.id)

				// Try to resume any in-progress enumeration.
				activeStates, err := c.enumerationStateStorage.GetActiveStates(ctx)
				if err != nil {
					c.logger.Error(ctx, "[%s] Error loading enumeration state", c.id, "error", err)
				}
				c.logger.Info(ctx, "[%s] Loaded %d active enumeration states", c.id, len(activeStates))

				if len(activeStates) == 0 {
					// No existing state, start fresh from config.
					if err := c.ProcessTarget(ctx); err != nil {
						c.logger.Error(ctx, "[%s] Failed to process targets", c.id, "error", err)
					}
				} else {
					// Resume from existing state.
					for _, state := range activeStates {
						if err := c.doEnumeration(ctx, state); err != nil {
							c.logger.Error(ctx, "[%s] Failed to resume enumeration", c.id, "error", err)
						}
					}
				}

				if !readyClosed {
					close(ready)
					readyClosed = true
				}

			case <-ctx.Done():
				c.logger.Info(ctx, "[%s] Context cancelled, shutting down", c.id)
				if !readyClosed {
					close(ready)
				}
				return
			}
		}
	}()

	c.logger.Info(ctx, "Starting coordinator...")
	if err := c.coordinator.Start(ctx); err != nil {
		return nil, fmt.Errorf("[%s] failed to start coordinator: %v", c.id, err)
	}

	return ready, nil
}

// Stop gracefully shuts down the controller if it is running.
// It is safe to call multiple times.
func (c *Controller) Stop(ctx context.Context) error {
	c.mu.Lock()
	if !c.running {
		c.mu.Unlock()
		return nil
	}
	c.running = false
	if c.cancelFn != nil {
		c.cancelFn()
	}
	c.mu.Unlock()

	c.logger.Info(ctx, "[%s] Stopped.", c.id)
	return nil
}

// ProcessTarget reads the configuration file and starts the enumeration process
// for each target defined in the configuration. For each target, it creates a new
// enumeration state and begins processing it. This is the entry point for starting
// fresh target scans.
func (c *Controller) ProcessTarget(ctx context.Context) error {
	cfg, err := c.configLoader.Load(ctx)
	if err != nil {
		return fmt.Errorf("[%s] failed to load configuration: %w", c.id, err)
	}

	// Create new credential store with loaded config
	credStore, err := NewCredentialStore(cfg.Auth)
	if err != nil {
		return fmt.Errorf("[%s] failed to initialize credential store: %w", c.id, err)
	}
	c.credStore = credStore
	c.logger.Info(ctx, "[%s] Credential store updated successfully.", c.id)

	for _, target := range cfg.Targets {
		enumState := &storage.EnumerationState{
			SessionID:      generateSessionID(),
			SourceType:     string(target.SourceType),
			Config:         c.marshalConfig(ctx, target, cfg.Auth),
			LastCheckpoint: nil, // No checkpoint initially
			LastUpdated:    time.Now(),
			Status:         storage.StatusInitialized,
		}

		if err := c.enumerationStateStorage.Save(ctx, enumState); err != nil {
			return fmt.Errorf("[%s] failed to save initial enumeration state: %w", c.id, err)
		}

		if err := c.doEnumeration(ctx, enumState); err != nil {
			c.logger.Error(ctx, "[%s] Failed to enumerate target", c.id, "error", err)
		}

	}

	return nil
}

// doEnumeration handles the core enumeration logic for a single target.
// It manages the enumeration lifecycle including state transitions and checkpoint handling.
// The function coordinates between the enumerator that produces tasks and the work queue
// that distributes them to workers.
func (c *Controller) doEnumeration(ctx context.Context, state *storage.EnumerationState) error {
	// We need the target config and the auth config to initialize the credential store.
	var combined struct {
		config.TargetSpec
		Auth config.AuthConfig `json:"auth,omitempty"`
	}

	if err := json.Unmarshal(state.Config, &combined); err != nil {
		return fmt.Errorf("[%s] failed to unmarshal target config: %w", c.id, err)
	}

	// Initialize credential store with the embedded auth config.
	if combined.Auth.Type != "" {
		credStore, err := NewCredentialStore(map[string]config.AuthConfig{
			combined.AuthRef: combined.Auth,
		})
		if err != nil {
			return fmt.Errorf("[%s] failed to initialize credential store: %w", c.id, err)
		}
		c.credStore = credStore
	}

	enumerator, err := c.createEnumerator(combined.TargetSpec)
	if err != nil {
		return err
	}

	if state.Status == storage.StatusInitialized {
		state.UpdateStatus(storage.StatusInProgress)
		if saveErr := c.enumerationStateStorage.Save(ctx, state); saveErr != nil {
			return fmt.Errorf("[%s] failed to mark enumeration state InProgress: %w", c.id, saveErr)
		}
	}

	taskCh := make(chan []messaging.Task)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for tasks := range taskCh {
			if err := c.workQueue.PublishTasks(ctx, tasks); err != nil {
				c.logger.Error(ctx, "[%s] Failed to publish tasks", c.id, "error", err)
				return
			}
			c.logger.Info(ctx, "[%s] Published batch of %d tasks", c.id, len(tasks))
		}
	}()

	if err := enumerator.Enumerate(ctx, state, taskCh); err != nil {
		state.UpdateStatus(storage.StatusFailed)
		if saveErr := c.enumerationStateStorage.Save(ctx, state); saveErr != nil {
			c.logger.Error(ctx, "[%s] Failed to save enumeration state after error", c.id, "error", saveErr)
		}
		close(taskCh)
		wg.Wait()
		return fmt.Errorf("[%s] enumeration failed: %w", c.id, err)
	}

	state.UpdateStatus(storage.StatusCompleted)
	if err := c.enumerationStateStorage.Save(ctx, state); err != nil {
		close(taskCh)
		wg.Wait()
		return fmt.Errorf("[%s] failed to save enumeration state: %w", c.id, err)
	}

	close(taskCh)
	wg.Wait()
	return nil
}

// createEnumerator constructs the appropriate target enumerator based on the source type.
// It handles credential setup and validation for the target type.
func (c *Controller) createEnumerator(target config.TargetSpec) (storage.TargetEnumerator, error) {
	if c.credStore == nil {
		return nil, fmt.Errorf("[%s] credential store not initialized", c.id)
	}

	creds, err := c.credStore.GetCredentials(target.AuthRef)
	if err != nil {
		return nil, fmt.Errorf("[%s] failed to get credentials: %w", c.id, err)
	}

	var enumerator storage.TargetEnumerator
	switch target.SourceType {
	case config.SourceTypeGitHub:
		if target.GitHub == nil {
			return nil, fmt.Errorf("[%s] github target configuration is missing", c.id)
		}
		ghClient, err := NewGitHubClient(c.httpClient, creds)
		if err != nil {
			return nil, fmt.Errorf("[%s] failed to create GitHub client: %w", c.id, err)
		}
		enumerator = NewGitHubEnumerator(
			ghClient,
			creds,
			c.enumerationStateStorage,
			target.GitHub,
			c.tracer,
		)

	case config.SourceTypeS3:
		return nil, fmt.Errorf("[%s] S3 enumerator not implemented yet", c.id)

	default:
		return nil, fmt.Errorf("[%s] unsupported source type: %s", c.id, target.SourceType)
	}

	return enumerator, nil
}

// generateSessionID creates a unique identifier for each enumeration session.
// This allows tracking and correlating all tasks and results from a single enumeration run.
func generateSessionID() string { return uuid.New().String() }

// marshalConfig serializes the target configuration into a JSON raw message.
// This allows storing the complete target configuration with the enumeration state.
func (c *Controller) marshalConfig(ctx context.Context, target config.TargetSpec, auth map[string]config.AuthConfig) json.RawMessage {
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
		c.logger.Error(ctx, "[%s] Failed to marshal target config", c.id, "error", err)
		return nil
	}
	return data
}

// generateTaskID creates a unique identifier for each scan task.
// This allows tracking individual tasks through the processing pipeline.
func generateTaskID() string { return uuid.New().String() }

func (c *Controller) handleRules(ctx context.Context, rules messaging.GitleaksRuleSet) error {
	// Store rules in memory for immediate use
	c.rules.Store(rules)

	// TODO: Persist rules to database
	// This would involve:
	// 1. Converting rules to database format
	// 2. Storing in database
	// 3. Handling any conflicts or versioning

	c.logger.Info(ctx, "[%s] Received and stored new ruleset with %d rules", c.id, len(rules.Rules))
	for _, rule := range rules.Rules {
		c.logger.Info(ctx, "[%s] Rule: %+v", c.id, rule)
	}
	return nil
}
