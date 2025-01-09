package orchestration

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/app/cluster"
	enumCoordinator "github.com/ahrav/gitleaks-armada/internal/app/enumeration"
	rulessvc "github.com/ahrav/gitleaks-armada/internal/app/rules"
	"github.com/ahrav/gitleaks-armada/internal/app/scanning"
	"github.com/ahrav/gitleaks-armada/internal/config"
	"github.com/ahrav/gitleaks-armada/internal/config/loaders"
	"github.com/ahrav/gitleaks-armada/internal/domain/enumeration"
	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/domain/rules"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

// Orchestrator coordinates work distribution across a cluster of workers. It manages
// leader election, rule processing, and target enumeration to ensure efficient
// scanning across the cluster. Only one controller is active at a time to prevent
// duplicate work.
type Orchestrator struct {
	id string

	coordinator    cluster.Coordinator
	workQueue      events.EventBus
	eventPublisher events.DomainEventPublisher

	cfgLoader loaders.Loader

	enumerationService enumCoordinator.Coordinator
	rulesService       rulessvc.Service
	scanningSvc        scanning.ScanJobService
	stateRepo          enumeration.StateRepository

	// mu protects running and cancelFn state
	mu       sync.Mutex
	running  bool
	cancelFn context.CancelFunc

	logger  *logger.Logger
	metrics ControllerMetrics

	tracer trace.Tracer

	// TODO: Use a ttl cache, or move this into its own pkg.
	processedRules map[string]time.Time // Map to track processed rule hashes
	rulesMutex     sync.RWMutex
}

// NewOrchestrator creates a Orchestrator instance that coordinates work distribution
// using the provided coordinator for leader election and broker for task queuing.
// It requires several dependencies to handle different aspects of the system:
//   - coordinator: Manages leader election across the cluster
//   - queue: Distributes work items to workers
//   - eventPublisher: Broadcasts domain events
//   - enumerationService: Handles target scanning logic
//   - rulesService: Manages scanning rules
//   - stateRepo: Manages enumeration state
//   - configLoader: Loads system configuration
//   - logger: Structured logging
//   - metrics: Runtime metrics collection
//   - tracer: Distributed tracing
func NewOrchestrator(
	id string,
	coord cluster.Coordinator,
	queue events.EventBus,
	eventPublisher events.DomainEventPublisher,
	enumerationService enumCoordinator.Coordinator,
	rulesService rulessvc.Service,
	stateRepo enumeration.StateRepository,
	configLoader loaders.Loader,
	logger *logger.Logger,
	metrics ControllerMetrics,
	tracer trace.Tracer,
) *Orchestrator {
	return &Orchestrator{
		id:                 id,
		coordinator:        coord,
		workQueue:          queue,
		eventPublisher:     eventPublisher,
		enumerationService: enumerationService,
		rulesService:       rulesService,
		stateRepo:          stateRepo,
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
func (o *Orchestrator) Run(ctx context.Context) (<-chan struct{}, error) {
	ctx, span := o.tracer.Start(ctx, "orchestrator.run",
		trace.WithAttributes(
			attribute.String("component", "orchestrator"),
			attribute.String("orchestrator_id", o.id),
		))
	defer span.End()

	ready := make(chan struct{})
	leaderCh := make(chan bool, 1)

	if err := o.workQueue.Subscribe(ctx, []events.EventType{rules.EventTypeRuleUpdated}, o.handleRule); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to subscribe to rules")
		return nil, fmt.Errorf("orchestrator[%s]: failed to subscribe to rules: %v", o.id, err)
	}
	span.AddEvent("subscribed_to_rules")

	o.coordinator.OnLeadershipChange(func(isLeader bool) {
		leaderCtx, leaderSpan := o.tracer.Start(ctx, "orchestrator.leadership_change",
			trace.WithAttributes(
				attribute.String("orchestrator_id", o.id),
				attribute.Bool("is_leader", isLeader),
			))
		defer leaderSpan.End()

		o.logger.Info(leaderCtx, "Leadership change", "orchestrator_id", o.id, "is_leader", isLeader)
		o.metrics.SetLeaderStatus(leaderCtx, isLeader)

		o.mu.Lock()
		o.running = isLeader
		if !isLeader && o.cancelFn != nil {
			o.cancelFn()
			o.cancelFn = nil
		}
		o.mu.Unlock()

		select {
		case leaderCh <- isLeader:
			leaderSpan.AddEvent("leadership_status_sent")
			o.logger.Info(leaderCtx, "Sent leadership status", "orchestrator_id", o.id, "is_leader", isLeader)
		default:
			leaderSpan.AddEvent("leadership_channel_full")
			o.logger.Info(leaderCtx, "Warning: leadership channel full, skipping update", "orchestrator_id", o.id)
		}
	})

	go func() {
		readyClosed := false
		o.logger.Info(ctx, "Waiting for leadership signal...", "orchestrator_id", o.id)

		for {
			select {
			case isLeader := <-leaderCh:
				loopCtx, loopSpan := o.tracer.Start(ctx, "orchestrator.leadership_loop",
					trace.WithAttributes(
						attribute.Bool("is_leader", isLeader),
					))

				if !isLeader {
					o.logger.Info(loopCtx, "Not leader, waiting...", "orchestrator_id", o.id)
					loopSpan.End()
					continue
				}

				o.logger.Info(loopCtx, "Leadership acquired, processing targets...", "orchestrator_id", o.id)

				err := o.metrics.TrackEnumeration(loopCtx, func() error {
					return o.Enumerate(loopCtx)
				})
				if err != nil {
					loopSpan.RecordError(err)
					loopSpan.SetStatus(codes.Error, "enumeration failed")
					o.logger.Error(loopCtx, "Failed to run enumeration process", "orchestrator_id", o.id, "error", err)
				}

				if !readyClosed {
					close(ready)
					readyClosed = true
					loopSpan.AddEvent("ready_channel_closed")
				}

				loopSpan.End()

			case <-ctx.Done():
				shutdownCtx, shutdownSpan := o.tracer.Start(ctx, "orchestrator.shutdown")
				o.logger.Info(shutdownCtx, "Context cancelled, shutting down", "orchestrator_id", o.id)
				if !readyClosed {
					close(ready)
					shutdownSpan.AddEvent("ready_channel_closed")
				}
				shutdownSpan.End()
				return
			}
		}
	}()

	o.logger.Info(ctx, "Starting coordinator...", "orchestrator_id", o.id)
	if err := o.coordinator.Start(ctx); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to start coordinator")
		return nil, fmt.Errorf("orchestrator[%s]: failed to start coordinator: %v", o.id, err)
	}
	span.AddEvent("coordinator_started")

	return ready, nil
}

// Enumerate starts a new enumeration session or resumes an existing one. It coordinates
// the scanning process by first checking for any active enumeration states. If none exist,
// it starts a fresh enumeration by loading the configuration and creating new scanning records.
// Otherwise, it resumes enumeration from the existing states. This ensures reliable and
// resumable scanning operations even after interruptions.
func (o *Orchestrator) Enumerate(ctx context.Context) error {
	ctx, span := o.tracer.Start(ctx, "orchestrator.enumerate",
		trace.WithAttributes(
			attribute.String("component", "orchestrator"),
			attribute.String("operation", "enumerate"),
		))
	defer span.End()

	span.AddEvent("checking_active_states")
	activeStates, err := o.stateRepo.GetActiveStates(ctx)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to load active states")
		return fmt.Errorf("failed to load active states: %w", err)
	}
	span.AddEvent("active_states_loaded", trace.WithAttributes(
		attribute.Int("active_state_count", len(activeStates)),
	))

	if len(activeStates) == 0 {
		// No active states means we need to start fresh.
		cfg, err := o.cfgLoader.Load(ctx)
		if err != nil {
			o.metrics.IncConfigReloadErrors(ctx)
			return fmt.Errorf("failed to load config: %w", err)
		}
		span.AddEvent("config_loaded")
		o.metrics.IncConfigReloads(ctx)

		// Create database records before starting enumeration to maintain data consistency.
		if err := o.createScanningRecords(ctx, cfg); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "failed to create scanning records")
			return fmt.Errorf("failed to create scanning records: %w", err)
		}
		span.AddEvent("scanning_records_created")

		span.AddEvent("starting_fresh_enumeration")
		if err := o.enumerationService.StartFreshEnumerations(ctx, cfg); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "failed to start fresh enumerations")
			return fmt.Errorf("failed to start fresh enumerations: %w", err)
		}
		span.AddEvent("fresh_enumeration_completed")
	}

	span.AddEvent("resuming_enumeration", trace.WithAttributes(
		attribute.Int("state_count", len(activeStates)),
	))
	if err := o.enumerationService.ResumeEnumerations(ctx, activeStates); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to resume enumerations")
		return fmt.Errorf("failed to resume enumerations: %w", err)
	}
	span.AddEvent("resumed_enumeration_completed")
	span.SetStatus(codes.Ok, "enumeration completed successfully")

	return nil
}

func (o *Orchestrator) createScanningRecords(ctx context.Context, cfg *config.Config) error {
	for _, tgt := range cfg.Targets {
		// e.g. scanningSvc.CreateGitHubRepo(tgt.GitHub.Org, ...)? or
		// scanningSvc.CreateScanTarget("github_repositories", /* repoID or url? */)

		if tgt.SourceType == "github" && tgt.GitHub != nil {
			// repoID, err := o.scanningSvc.CreateGitHubRepository(ctx, tgt.GitHub)
			// if err != nil {
			// 	return err
			// }
			// Then create scan_target row referencing that repo
			// scanTargetID, err := o.scanningSvc.CreateScanTarget(ctx, "github_repositories", repoID, tgt.Metadata)
			// if err != nil {
			// 	return err
			// }
			// Possibly create a job in "QUEUED" or "SCHEDULED" status
			// _, err := o.scanningSvc.CreateJob(ctx, scanTargetID)
			// if err != nil {
			// 	return err
			// }
		}
		// else if S3, do something else...
	}

	return nil
}

// Stop gracefully shuts down the controller if it is running.
// It is safe to call multiple times.
func (o *Orchestrator) Stop(ctx context.Context) error {
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

	o.logger.Info(ctx, "Stopped.", "orchestrator_id", o.id)
	return nil
}

// handleRule processes incoming rule update events. It deduplicates rules based on their hash
// to prevent unnecessary processing of duplicate rules within a short time window.
func (o *Orchestrator) handleRule(ctx context.Context, evt events.EventEnvelope) error {
	ruleEvent, ok := evt.Payload.(rules.RuleUpdatedEvent)
	if !ok {
		return fmt.Errorf("handleRule: payload is not RuleUpdatedEvent, got %T", evt.Payload)
	}

	// Check ephemeral duplicate skip (controller-level).
	o.rulesMutex.RLock()
	lastProcessed, exists := o.processedRules[ruleEvent.Rule.Hash]
	o.rulesMutex.RUnlock()

	if exists && time.Since(lastProcessed) < time.Minute*5 {
		o.logger.Info(ctx, "Skipping duplicate rule",
			"rule_id", ruleEvent.Rule.RuleID,
			"hash", ruleEvent.Rule.Hash,
			"occurred_at", ruleEvent.OccurredAt())
		return nil
	}

	// Delegate to domain-level service for real domain logic (persisting rule).
	if err := o.rulesService.SaveRule(ctx, ruleEvent.Rule.GitleaksRule); err != nil {
		return fmt.Errorf("failed to persist rule: %w", err)
	}

	// Mark processed, do some ephemeral cleanup.
	o.rulesMutex.Lock()
	o.processedRules[ruleEvent.Rule.Hash] = time.Now()
	o.rulesMutex.Unlock()

	o.logger.Info(ctx, "Stored new rule",
		"rule_id", ruleEvent.Rule.RuleID,
		"hash", ruleEvent.Rule.Hash,
		"occurred_at", ruleEvent.OccurredAt())
	return nil
}
