package controller

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/app/cluster"
	"github.com/ahrav/gitleaks-armada/internal/app/controller/metrics"
	"github.com/ahrav/gitleaks-armada/internal/app/enumeration"
	rulessvc "github.com/ahrav/gitleaks-armada/internal/app/rules"
	"github.com/ahrav/gitleaks-armada/internal/config/loaders"
	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/domain/rules"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

// Controller coordinates work distribution across a cluster of workers. It manages
// leader election, rule processing, and target enumeration to ensure efficient
// scanning across the cluster. Only one controller is active at a time to prevent
// duplicate work.
type Controller struct {
	id string

	coordinator    cluster.Coordinator
	workQueue      events.EventBus
	eventPublisher events.DomainEventPublisher

	enumerationService enumeration.Coordinator
	rulesService       rulessvc.Service

	// mu protects running and cancelFn state
	mu       sync.Mutex
	running  bool
	cancelFn context.CancelFunc

	logger  *logger.Logger
	metrics metrics.ControllerMetrics

	tracer trace.Tracer

	// TODO: Use a ttl cache, or move this into its own pkg.
	processedRules map[string]time.Time // Map to track processed rule hashes
	rulesMutex     sync.RWMutex
}

// NewController creates a Controller instance that coordinates work distribution
// using the provided coordinator for leader election and broker for task queuing.
// It requires several dependencies to handle different aspects of the system:
//   - coordinator: Manages leader election across the cluster
//   - queue: Distributes work items to workers
//   - eventPublisher: Broadcasts domain events
//   - enumerationService: Handles target scanning logic
//   - rulesService: Manages scanning rules
//   - configLoader: Loads system configuration
//   - logger: Structured logging
//   - metrics: Runtime metrics collection
//   - tracer: Distributed tracing
func NewController(
	id string,
	coord cluster.Coordinator,
	queue events.EventBus,
	eventPublisher events.DomainEventPublisher,
	enumerationService enumeration.Coordinator,
	rulesService rulessvc.Service,
	configLoader loaders.Loader,
	logger *logger.Logger,
	metrics metrics.ControllerMetrics,
	tracer trace.Tracer,
) *Controller {
	return &Controller{
		id:                 id,
		coordinator:        coord,
		workQueue:          queue,
		eventPublisher:     eventPublisher,
		enumerationService: enumerationService,
		rulesService:       rulesService,
		metrics:            metrics,
		logger:             logger,
		tracer:             tracer,
		processedRules:     make(map[string]time.Time),
		rulesMutex:         sync.RWMutex{},
	}
}

// Run starts the controller's leadership election process and target processing loop.
// It participates in leader election and, when elected leader, processes scan targets.
// The controller will resume any in-progress enumerations if they exist, otherwise
// it starts fresh from the configuration.
//
// It returns a channel that is closed when initialization is complete and any startup error.
// The channel allows callers to wait for the controller to be ready before proceeding.
func (c *Controller) Run(ctx context.Context) (<-chan struct{}, error) {
	ready := make(chan struct{})
	leaderCh := make(chan bool, 1)

	if err := c.workQueue.Subscribe(ctx, []events.EventType{rules.EventTypeRuleUpdated}, c.handleRule); err != nil {
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

				if err := c.enumerationService.ExecuteEnumeration(ctx); err != nil {
					c.logger.Error(ctx, "Failed to run enumeration process", "controller_id", c.id, "error", err)
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

// handleRule processes incoming rule update events. It deduplicates rules based on their hash
// to prevent unnecessary processing of duplicate rules within a short time window.
func (c *Controller) handleRule(ctx context.Context, evt events.EventEnvelope) error {
	ruleEvent, ok := evt.Payload.(rules.RuleUpdatedEvent)
	if !ok {
		return fmt.Errorf("handleRule: payload is not RuleUpdatedEvent, got %T", evt.Payload)
	}

	// Check ephemeral duplicate skip (controller-level).
	c.rulesMutex.RLock()
	lastProcessed, exists := c.processedRules[ruleEvent.Rule.Hash]
	c.rulesMutex.RUnlock()

	if exists && time.Since(lastProcessed) < time.Minute*5 {
		c.logger.Info(ctx, "Skipping duplicate rule",
			"rule_id", ruleEvent.Rule.RuleID,
			"hash", ruleEvent.Rule.Hash,
			"occurred_at", ruleEvent.OccurredAt())
		return nil
	}

	// Delegate to domain-level service for real domain logic (persisting rule).
	if err := c.rulesService.SaveRule(ctx, ruleEvent.Rule.GitleaksRule); err != nil {
		return fmt.Errorf("failed to persist rule: %w", err)
	}

	// Mark processed, do some ephemeral cleanup.
	c.rulesMutex.Lock()
	c.processedRules[ruleEvent.Rule.Hash] = time.Now()
	c.rulesMutex.Unlock()

	c.logger.Info(ctx, "Stored new rule",
		"rule_id", ruleEvent.Rule.RuleID,
		"hash", ruleEvent.Rule.Hash,
		"occurred_at", ruleEvent.OccurredAt())
	return nil
}
