package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/pkg/cluster"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
	"github.com/ahrav/gitleaks-armada/pkg/config"
	"github.com/ahrav/gitleaks-armada/pkg/controller/metrics"
	"github.com/ahrav/gitleaks-armada/pkg/messaging"
	"github.com/ahrav/gitleaks-armada/pkg/storage"
)

// Controller coordinates work distribution across a cluster of workers.
type Controller struct {
	id string

	coordinator  cluster.Coordinator
	workQueue    messaging.Broker
	configLoader config.Loader
	credStore    *CredentialStore

	// Storage for enumeration state, checkpoints, and rules.
	enumerationStateStorage storage.EnumerationStateStorage
	checkpointStorage       storage.CheckpointStorage
	rulesStorage            storage.RulesStorage

	// State and control for the controller.
	mu       sync.Mutex
	running  bool
	cancelFn context.CancelFunc

	httpClient *http.Client

	logger  *logger.Logger
	metrics metrics.ControllerMetrics

	tracer trace.Tracer

	// TODO: Use a ttl cache, or move this into its own pkg.
	processedRules map[string]time.Time // Map to track processed rule hashes
	rulesMutex     sync.RWMutex
}

// NewController creates a Controller instance that coordinates work distribution
// using the provided coordinator for leader election and broker for task queuing.
func NewController(
	id string,
	coord cluster.Coordinator,
	queue messaging.Broker,
	enumerationStateStorage storage.EnumerationStateStorage,
	checkpointStorage storage.CheckpointStorage,
	rulesStorage storage.RulesStorage,
	configLoader config.Loader,
	logger *logger.Logger,
	metrics metrics.ControllerMetrics,
	tracer trace.Tracer,
) *Controller {
	credStore, err := NewCredentialStore(make(map[string]config.AuthConfig))
	if err != nil {
		logger.Error(context.Background(), "Warning: failed to initialize empty credential store", "controller_id", id, "error", err)
	}

	return &Controller{
		id:                      id,
		coordinator:             coord,
		workQueue:               queue,
		credStore:               credStore,
		enumerationStateStorage: enumerationStateStorage,
		checkpointStorage:       checkpointStorage,
		rulesStorage:            rulesStorage,
		configLoader:            configLoader,
		httpClient:              new(http.Client),
		metrics:                 metrics,
		logger:                  logger,
		tracer:                  tracer,
		processedRules:          make(map[string]time.Time),
		rulesMutex:              sync.RWMutex{},
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

	if err := c.workQueue.SubscribeRules(ctx, c.handleRule); err != nil {
		return nil, fmt.Errorf("controller[%s]: failed to subscribe to rules: %v", c.id, err)
	}

	c.coordinator.OnLeadershipChange(func(isLeader bool) {
		c.logger.Info(ctx, "Leadership change", "controller_id", c.id, "is_leader", isLeader)
		c.metrics.SetLeaderStatus(isLeader)

		c.mu.Lock()
		c.running = isLeader
		if !isLeader && c.cancelFn != nil {
			c.cancelFn()
			c.cancelFn = nil
		}
		c.mu.Unlock()

		select {
		case leaderCh <- isLeader:
			c.logger.Info(ctx, "Sent leadership status", "controller_id", c.id, "is_leader", isLeader)
		default:
			c.logger.Info(ctx, "Warning: leadership channel full, skipping update", "controller_id", c.id)
		}
	})

	go func() {
		readyClosed := false
		c.logger.Info(ctx, "Waiting for leadership signal...", "controller_id", c.id)

		for {
			select {
			case isLeader := <-leaderCh:
				if !isLeader {
					c.logger.Info(ctx, "Not leader, waiting...", "controller_id", c.id)
					continue
				}

				c.logger.Info(ctx, "Leadership acquired, processing targets...", "controller_id", c.id)

				// Try to resume any in-progress enumeration.
				activeStates, err := c.enumerationStateStorage.GetActiveStates(ctx)
				if err != nil {
					c.logger.Error(ctx, "Error loading enumeration state", "controller_id", c.id, "error", err)
				}
				c.logger.Info(ctx, "Loaded active enumeration states", "controller_id", c.id, "num_states", len(activeStates))

				if len(activeStates) == 0 {
					// No existing state, start fresh from config.
					if err := c.ProcessTarget(ctx); err != nil {
						c.logger.Error(ctx, "Failed to process targets", "controller_id", c.id, "error", err)
					}
				} else {
					// Resume from existing state.
					for _, state := range activeStates {
						if err := c.doEnumeration(ctx, state); err != nil {
							c.logger.Error(ctx, "Failed to resume enumeration", "controller_id", c.id, "error", err)
						}
					}
				}

				if !readyClosed {
					close(ready)
					readyClosed = true
				}

			case <-ctx.Done():
				c.logger.Info(ctx, "Context cancelled, shutting down", "controller_id", c.id)
				if !readyClosed {
					close(ready)
				}
				return
			}
		}
	}()

	c.logger.Info(ctx, "Starting coordinator...", "controller_id", c.id)
	if err := c.coordinator.Start(ctx); err != nil {
		return nil, fmt.Errorf("controller[%s]: failed to start coordinator: %v", c.id, err)
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

	c.logger.Info(ctx, "Stopped.", "controller_id", c.id)
	return nil
}

// ProcessTarget reads the configuration file and starts the enumeration process
// for each target defined in the configuration. For each target, it creates a new
// enumeration state and begins processing it. This is the entry point for starting
// fresh target scans.
func (c *Controller) ProcessTarget(ctx context.Context) error {
	cfg, err := c.configLoader.Load(ctx)
	if err != nil {
		c.metrics.IncConfigReloadErrors()
		return fmt.Errorf("controller[%s]: failed to load configuration: %w", c.id, err)
	}
	c.metrics.IncConfigReloads()

	// Create new credential store with loaded config
	credStore, err := NewCredentialStore(cfg.Auth)
	if err != nil {
		return fmt.Errorf("controller[%s]: failed to initialize credential store: %w", c.id, err)
	}
	c.credStore = credStore
	c.logger.Info(ctx, "Credential store updated successfully.", "controller_id", c.id)

	for _, target := range cfg.Targets {
		start := time.Now()

		enumState := &storage.EnumerationState{
			SessionID:      generateSessionID(),
			SourceType:     string(target.SourceType),
			Config:         c.marshalConfig(ctx, target, cfg.Auth),
			LastCheckpoint: nil, // No checkpoint initially
			LastUpdated:    time.Now(),
			Status:         storage.StatusInitialized,
		}

		if err := c.enumerationStateStorage.Save(ctx, enumState); err != nil {
			return fmt.Errorf("controller[%s]: failed to save initial enumeration state: %w", c.id, err)
		}

		if err := c.doEnumeration(ctx, enumState); err != nil {
			c.logger.Error(ctx, "Failed to enumerate target", "controller_id", c.id, "error", err)
			continue
		}

		// Only record success metrics if target was processed without error.
		c.metrics.ObserveTargetProcessingTime(time.Since(start))
		c.metrics.IncTargetsProcessed()
	}

	return nil
}

// doEnumeration handles the core enumeration logic for a single target.
// It manages the enumeration lifecycle including state transitions and checkpoint handling.
// The function coordinates between the enumerator that produces tasks and the work queue
// that distributes them to workers.
func (c *Controller) doEnumeration(ctx context.Context, state *storage.EnumerationState) error {
	return c.metrics.TrackEnumeration(func() error {
		// We need the target config and the auth config to initialize the credential store.
		var combined struct {
			config.TargetSpec
			Auth config.AuthConfig `json:"auth,omitempty"`
		}

		if err := json.Unmarshal(state.Config, &combined); err != nil {
			return fmt.Errorf("controller[%s]: failed to unmarshal target config: %w", c.id, err)
		}

		// Initialize credential store with the embedded auth config.
		if combined.Auth.Type != "" {
			credStore, err := NewCredentialStore(map[string]config.AuthConfig{
				combined.AuthRef: combined.Auth,
			})
			if err != nil {
				return fmt.Errorf("controller[%s]: failed to initialize credential store: %w", c.id, err)
			}
			c.credStore = credStore
		}

		enumerator, err := c.createEnumerator(combined.TargetSpec)
		if err != nil {
			return fmt.Errorf("controller[%s]: %w", c.id, err)
		}

		if state.Status == storage.StatusInitialized {
			state.UpdateStatus(storage.StatusInProgress)
			if saveErr := c.enumerationStateStorage.Save(ctx, state); saveErr != nil {
				return fmt.Errorf("controller[%s]: failed to mark enumeration state InProgress: %w", c.id, saveErr)
			}
		}

		taskCh := make(chan []messaging.Task)
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			for tasks := range taskCh {
				if err := c.workQueue.PublishTasks(ctx, tasks); err != nil {
					c.logger.Error(ctx, "Failed to publish tasks", "controller_id", c.id, "error", err)
					return
				}
				c.logger.Info(ctx, "Published batch of tasks", "controller_id", c.id, "num_tasks", len(tasks))
			}
		}()

		if err := enumerator.Enumerate(ctx, state, taskCh); err != nil {
			state.UpdateStatus(storage.StatusFailed)
			if saveErr := c.enumerationStateStorage.Save(ctx, state); saveErr != nil {
				c.logger.Error(ctx, "Failed to save enumeration state after error", "controller_id", c.id, "error", saveErr)
			}
			close(taskCh)
			wg.Wait()
			return fmt.Errorf("controller[%s]: enumeration failed: %w", c.id, err)
		}

		state.UpdateStatus(storage.StatusCompleted)
		if err := c.enumerationStateStorage.Save(ctx, state); err != nil {
			close(taskCh)
			wg.Wait()
			return fmt.Errorf("controller[%s]: failed to save enumeration state: %w", c.id, err)
		}

		close(taskCh)
		wg.Wait()
		return nil
	})
}

// createEnumerator constructs the appropriate target enumerator based on the source type.
// It handles credential setup and validation for the target type.
func (c *Controller) createEnumerator(target config.TargetSpec) (storage.TargetEnumerator, error) {
	if c.credStore == nil {
		return nil, fmt.Errorf("controller[%s]: credential store not initialized", c.id)
	}

	creds, err := c.credStore.GetCredentials(target.AuthRef)
	if err != nil {
		return nil, fmt.Errorf("controller[%s]: failed to get credentials: %w", c.id, err)
	}

	var enumerator storage.TargetEnumerator
	switch target.SourceType {
	case config.SourceTypeGitHub:
		if target.GitHub == nil {
			return nil, fmt.Errorf("controller[%s]: github target configuration is missing", c.id)
		}
		ghClient, err := NewGitHubClient(c.httpClient, creds)
		if err != nil {
			return nil, fmt.Errorf("controller[%s]: failed to create GitHub client: %w", c.id, err)
		}
		enumerator = NewGitHubEnumerator(
			ghClient,
			creds,
			c.enumerationStateStorage,
			target.GitHub,
			c.tracer,
		)

	case config.SourceTypeS3:
		return nil, fmt.Errorf("controller[%s]: S3 enumerator not implemented yet", c.id)

	default:
		return nil, fmt.Errorf("controller[%s]: unsupported source type: %s", c.id, target.SourceType)
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
		c.logger.Error(ctx, "Failed to marshal target config", "controller_id", c.id, "error", err)
		return nil
	}
	return data
}

// generateTaskID creates a unique identifier for each scan task.
// This allows tracking individual tasks through the processing pipeline.
func generateTaskID() string { return uuid.New().String() }

func (c *Controller) handleRule(ctx context.Context, ruleMsg messaging.GitleaksRuleMessage) error {
	ctx, span := c.tracer.Start(ctx, "controller.handleRule")
	defer span.End()

	// Check if we've recently processed this rule.
	c.rulesMutex.RLock()
	lastProcessed, exists := c.processedRules[ruleMsg.Hash]
	c.rulesMutex.RUnlock()

	const (
		ttlDuration = 5 * time.Minute
		purgeAfter  = 10 * time.Minute
	)

	if exists && time.Since(lastProcessed) < ttlDuration {
		c.logger.Info(ctx, "Skipping duplicate rule",
			"controller_id", c.id,
			"rule_id", ruleMsg.Rule.RuleID,
			"hash", ruleMsg.Hash)
		return nil
	}

	if err := c.rulesStorage.SaveRule(ctx, ruleMsg.Rule); err != nil {
		span.RecordError(err)
		return fmt.Errorf("controller[%s]: failed to save rule: %w", c.id, err)
	}

	c.rulesMutex.Lock()
	c.processedRules[ruleMsg.Hash] = time.Now()
	// Clean up old entries.
	for hash, t := range c.processedRules {
		if time.Since(t) > purgeAfter {
			delete(c.processedRules, hash)
		}
	}
	c.rulesMutex.Unlock()

	c.logger.Info(ctx, "Received and stored new rule",
		"controller_id", c.id,
		"rule_id", ruleMsg.Rule.RuleID,
		"hash", ruleMsg.Hash)
	return nil
}
