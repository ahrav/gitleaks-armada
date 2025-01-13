package orchestration

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/app/cluster"
	enumCoordinator "github.com/ahrav/gitleaks-armada/internal/app/enumeration"
	rulessvc "github.com/ahrav/gitleaks-armada/internal/app/rules"
	scanningSvc "github.com/ahrav/gitleaks-armada/internal/app/scanning"
	"github.com/ahrav/gitleaks-armada/internal/config"
	"github.com/ahrav/gitleaks-armada/internal/config/loaders"
	"github.com/ahrav/gitleaks-armada/internal/domain/enumeration"
	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/domain/rules"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
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
	scanningSvc        scanningSvc.ScanJobService
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
	cfgLoader loaders.Loader,
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
		cfgLoader:          cfgLoader,
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
	// Create a new context with a long-lived span for the entire Run lifecycle
	runCtx, runSpan := o.tracer.Start(ctx, "orchestrator.run",
		trace.WithAttributes(
			attribute.String("component", "orchestrator"),
			attribute.String("orchestrator_id", o.id),
		))

	initCtx, initSpan := o.tracer.Start(runCtx, "orchestrator.init")
	defer initSpan.End()

	ready := make(chan struct{})
	leaderCh := make(chan bool, 1)

	if err := o.workQueue.Subscribe(initCtx, []events.EventType{rules.EventTypeRuleUpdated}, o.handleRule); err != nil {
		initSpan.RecordError(err)
		initSpan.SetStatus(codes.Error, "failed to subscribe to rules")
		runSpan.End() // End the parent span on error
		return nil, fmt.Errorf("orchestrator[%s]: failed to subscribe to rules: %v", o.id, err)
	}
	initSpan.AddEvent("subscribed_to_rules")

	o.coordinator.OnLeadershipChange(func(isLeader bool) {
		leaderCtx, leaderSpan := o.tracer.Start(runCtx, "orchestrator.leadership_change",
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
		defer runSpan.End() // Ensure the parent span ends when the goroutine exits
		readyClosed := false
		o.logger.Info(runCtx, "Waiting for leadership signal...", "orchestrator_id", o.id)

		for {
			select {
			case isLeader := <-leaderCh:
				loopCtx, loopSpan := o.tracer.Start(runCtx, "orchestrator.handle_leadership",
					trace.WithAttributes(
						attribute.Bool("is_leader", isLeader),
					))

				if !isLeader {
					o.logger.Info(loopCtx, "Not leader, waiting...", "orchestrator_id", o.id)
					loopSpan.End()
					continue
				}

				o.logger.Info(loopCtx, "Leadership acquired, processing targets...", "orchestrator_id", o.id)
				loopSpan.End()

				enumCtx, enumSpan := o.tracer.Start(runCtx, "orchestrator.track_enumeration")
				err := o.metrics.TrackEnumeration(enumCtx, func() error {
					return o.Enumerate(enumCtx)
				})
				if err != nil {
					enumSpan.RecordError(err)
					enumSpan.SetStatus(codes.Error, "enumeration failed")
					o.logger.Error(enumCtx, "Failed to run enumeration process", "orchestrator_id", o.id, "error", err)
				}
				enumSpan.End()

				if !readyClosed {
					_, readySpan := o.tracer.Start(runCtx, "orchestrator.mark_ready")
					close(ready)
					readyClosed = true
					readySpan.AddEvent("ready_channel_closed")
					readySpan.End()
				}

			case <-ctx.Done():
				shutdownCtx, shutdownSpan := o.tracer.Start(runCtx, "orchestrator.shutdown")
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

	// Start coordinator span as child of runSpan.
	startCtx, startSpan := o.tracer.Start(runCtx, "orchestrator.start_coordinator")
	o.logger.Info(startCtx, "Starting coordinator...", "orchestrator_id", o.id)
	if err := o.coordinator.Start(startCtx); err != nil {
		startSpan.RecordError(err)
		startSpan.SetStatus(codes.Error, "failed to start coordinator")
		startSpan.End()
		runSpan.End() // End the parent span on error
		return nil, fmt.Errorf("orchestrator[%s]: failed to start coordinator: %v", o.id, err)
	}
	startSpan.AddEvent("coordinator_started")
	startSpan.End()

	return ready, nil
}

var _ enumCoordinator.ScanTargetCallback = (*orchestratorCallback)(nil)

// orchestratorCallback is a callback implementation for the orchestrator.
// It is used to notify the orchestrator when scan targets are discovered.
type orchestratorCallback struct {
	jobSvc scanningSvc.ScanJobService
	job    *scanning.ScanJob
}

func (oc *orchestratorCallback) OnScanTargetsDiscovered(ctx context.Context, targetIDs []uuid.UUID) {
	for _, tid := range targetIDs {
		if err := oc.jobSvc.AssociateTargets(ctx, oc.job, []uuid.UUID{tid}); err != nil {
			// Handle error (log it, maybe retry, etc.)
			continue
		}
	}
}

// Enumerate starts enumeration sessions for each target in the configuration.
// It creates a job for each target and associates discovered scan targets with that job.
func (o *Orchestrator) Enumerate(ctx context.Context) error {
	ctx, span := o.tracer.Start(ctx, "orchestrator.enumerate")
	defer span.End()

	// Check for active states first
	span.AddEvent("checking_active_states")
	activeStates, err := o.stateRepo.GetActiveStates(ctx)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to load active states: %w", err)
	}

	if len(activeStates) > 0 {
		return o.resumeEnumerations(ctx, activeStates)
	}

	// Start fresh enumeration
	cfg, err := o.cfgLoader.Load(ctx)
	if err != nil {
		o.metrics.IncConfigReloadErrors(ctx)
		return fmt.Errorf("failed to load config: %w", err)
	}
	span.AddEvent("config_loaded")
	o.metrics.IncConfigReloads(ctx)

	return o.startFreshEnumerations(ctx, cfg)
}

func (o *Orchestrator) startFreshEnumerations(ctx context.Context, cfg *config.Config) error {
	ctx, span := o.tracer.Start(ctx, "orchestrator.start_fresh_enumerations")
	defer span.End()

	for _, target := range cfg.Targets {
		targetSpan := trace.SpanFromContext(ctx)
		targetSpan.AddEvent("processing_target", trace.WithAttributes(
			attribute.String("target_name", target.Name),
			attribute.String("target_type", string(target.SourceType)),
		))

		job, err := o.scanningSvc.CreateJob(ctx)
		if err != nil {
			targetSpan.RecordError(err)
			return fmt.Errorf("failed to create job for target %s: %w", target.Name, err)
		}

		// Create callback that associates discovered targets with this job.
		cb := &orchestratorCallback{
			job:    job,
			jobSvc: o.scanningSvc,
		}

		if err := o.enumerationService.EnumerateTarget(ctx, target, cfg.Auth, cb); err != nil {
			targetSpan.RecordError(err)
			continue
		}

		targetSpan.AddEvent("target_enumeration_completed")
	}

	return nil
}

func (o *Orchestrator) resumeEnumerations(ctx context.Context, states []*enumeration.SessionState) error {
	ctx, span := o.tracer.Start(ctx, "orchestrator.resume_enumerations")
	defer span.End()

	for _, state := range states {
		stateSpan := trace.SpanFromContext(ctx)

		// TODO: Use existing job if possible, bleh...
		job, err := o.scanningSvc.CreateJob(ctx)
		if err != nil {
			stateSpan.RecordError(err)
			return fmt.Errorf("failed to create job for state %s: %w", state.SessionID(), err)
		}

		cb := &orchestratorCallback{
			job:    job,
			jobSvc: o.scanningSvc,
		}

		if err := o.enumerationService.ResumeTarget(ctx, state, cb); err != nil {
			stateSpan.RecordError(err)
			continue
		}

		stateSpan.AddEvent("state_enumeration_completed")
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
