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
	scan "github.com/ahrav/gitleaks-armada/internal/app/scanning"
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
	jobRepo            scanning.JobRepository
	stateRepo          enumeration.StateRepository

	progressTracker  scan.ProgressTracker
	progressHandlers map[events.EventType]progressEventHandler

	// mu protects running and cancelFn state
	mu       sync.Mutex
	running  bool
	cancelFn context.CancelFunc

	logger  *logger.Logger
	metrics OrchestrationMetrics

	tracer trace.Tracer

	// TODO: Use a ttl cache, or move this into its own pkg.
	processedRules map[string]time.Time // Map to track processed rule hashes
	rulesMutex     sync.RWMutex
}

type progressEventHandler func(context.Context, events.EventEnvelope) error

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
	jobRepo scanning.JobRepository,
	stateRepo enumeration.StateRepository,
	cfgLoader loaders.Loader,
	logger *logger.Logger,
	metrics OrchestrationMetrics,
	tracer trace.Tracer,
	progressTracker scan.ProgressTracker,
) *Orchestrator {
	o := &Orchestrator{
		id:                 id,
		coordinator:        coord,
		workQueue:          queue,
		eventPublisher:     eventPublisher,
		enumerationService: enumerationService,
		rulesService:       rulesService,
		jobRepo:            jobRepo,
		stateRepo:          stateRepo,
		cfgLoader:          cfgLoader,
		progressTracker:    progressTracker,
		metrics:            metrics,
		logger:             logger,
		tracer:             tracer,
		processedRules:     make(map[string]time.Time),
		rulesMutex:         sync.RWMutex{},
	}

	o.progressHandlers = map[events.EventType]progressEventHandler{
		scanning.EventTypeTaskStarted:    o.handleTaskStarted,
		scanning.EventTypeTaskProgressed: o.handleTaskProgressed,
		// TODO: Add failures, stale tasks, completed tasks, etc.
	}

	return o
}

// Run starts the controller's leadership election process and target processing loop.
// It participates in leader election and, when elected leader, processes scan targets.
// The controller will resume any in-progress enumerations if they exist, otherwise
// it starts fresh from the configuration.
//
// It returns a channel that is closed when initialization is complete and any startup error.
// The channel allows callers to wait for the controller to be ready before proceeding.
func (o *Orchestrator) Run(ctx context.Context) (<-chan struct{}, error) {
	// Short-lived "Run" span; ends after basic setup
	runCtx, runSpan := o.tracer.Start(ctx, "orchestrator.run",
		trace.WithAttributes(
			attribute.String("component", "orchestrator"),
			attribute.String("orchestrator_id", o.id),
		))
	// Make sure we end this span before long-lived operations.
	defer runSpan.End()

	// Initialization span.
	initCtx, initSpan := o.tracer.Start(runCtx, "orchestrator.init")
	defer initSpan.End()

	ready := make(chan struct{})
	leaderCh := make(chan bool, 1)

	if err := o.workQueue.Subscribe(initCtx, []events.EventType{rules.EventTypeRuleUpdated}, o.handleRule); err != nil {
		initSpan.RecordError(err)
		initSpan.SetStatus(codes.Error, "failed to subscribe to rules")
		return nil, fmt.Errorf("orchestrator[%s]: failed to subscribe to rules: %v", o.id, err)
	}
	initSpan.AddEvent("subscribed_to_rules")

	// Subscribe to progress tracking events.
	progressEvents := []events.EventType{
		scanning.EventTypeTaskStarted,
		scanning.EventTypeTaskProgressed,
		scanning.EventTypeTaskCompleted,
		scanning.EventTypeTaskFailed,
	}

	if err := o.workQueue.Subscribe(initCtx, progressEvents, o.handleProgressEvent); err != nil {
		initSpan.RecordError(err)
		return nil, fmt.Errorf("orchestrator[%s]: failed to subscribe to progress events: %v", o.id, err)
	}
	initSpan.AddEvent("subscribed_to_progress_events")

	// Create a new context for long-running operations that inherits the trace.
	longRunningCtx := trace.ContextWithSpan(ctx, initSpan)

	// Hook up leadership change callback with the traced context.
	o.coordinator.OnLeadershipChange(func(isLeader bool) {
		leaderCtx, leaderSpan := o.tracer.Start(longRunningCtx, "orchestrator.leadership_change",
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

	// Use the same longRunningCtx.
	go func() {
		readyClosed := false
		o.logger.Info(longRunningCtx, "Waiting for leadership signal...", "orchestrator_id", o.id)

		for {
			select {
			case isLeader := <-leaderCh:
				loopCtx, loopSpan := o.tracer.Start(longRunningCtx, "orchestrator.handle_leadership",
					trace.WithAttributes(
						attribute.Bool("is_leader", isLeader),
					))
				if !isLeader {
					o.logger.Info(loopCtx, "Not leader, waiting...", "orchestrator_id", o.id)
					loopSpan.End()
					continue
				}

				// Leader-specific processing.
				o.logger.Info(loopCtx, "Leadership acquired, processing targets...", "orchestrator_id", o.id)
				loopSpan.End()

				enumCtx, enumSpan := o.tracer.Start(ctx, "orchestrator.track_enumeration")
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
					// Mark orchestrator as ready.
					_, readySpan := o.tracer.Start(ctx, "orchestrator.mark_ready")
					close(ready)
					readyClosed = true
					readySpan.AddEvent("ready_channel_closed")
					readySpan.End()
				}

			case <-ctx.Done(): // Shutdown.
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

	// Start coordinator with its own span.
	startCtx, startSpan := o.tracer.Start(ctx, "orchestrator.start_coordinator")
	o.logger.Info(startCtx, "Starting coordinator...", "orchestrator_id", o.id)
	if err := o.coordinator.Start(startCtx); err != nil {
		startSpan.RecordError(err)
		startSpan.SetStatus(codes.Error, "failed to start coordinator")
		startSpan.End()
		return nil, fmt.Errorf("orchestrator[%s]: failed to start coordinator: %v", o.id, err)
	}
	startSpan.AddEvent("coordinator_started")
	startSpan.End()

	// Because of the `defer` above, the runSpan from the top will end
	// as soon as this function returns, avoiding a huge multi-hour parent span.
	return ready, nil
}

// Enumerate starts enumeration sessions for each target in the configuration.
// It creates a job for each target and associates discovered scan targets with that job.
func (o *Orchestrator) Enumerate(ctx context.Context) error {
	ctx, span := o.tracer.Start(ctx, "orchestrator.enumerate")
	defer span.End()

	span.AddEvent("checking_active_states")
	activeStates, err := o.stateRepo.GetActiveStates(ctx)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to load active states: %w", err)
	}

	if len(activeStates) > 0 {
		return o.resumeEnumerations(ctx, activeStates)
	}

	cfg, err := o.cfgLoader.Load(ctx)
	if err != nil {
		o.metrics.IncConfigReloadErrors(ctx)
		return fmt.Errorf("failed to load config: %w", err)
	}
	span.AddEvent("config_loaded")
	o.metrics.IncConfigReloads(ctx)

	err = o.startFreshEnumerations(ctx, cfg)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to start fresh enumerations")
		return fmt.Errorf("failed to start fresh enumerations: %w", err)
	}
	span.AddEvent("fresh_enumerations_started")

	return nil
}

func (o *Orchestrator) startFreshEnumerations(ctx context.Context, cfg *config.Config) error {
	ctx, span := o.tracer.Start(ctx, "orchestrator.start_fresh_enumerations")
	defer span.End()

	o.metrics.IncEnumerationStarted(ctx)
	span.AddEvent("fresh_enumeration_started")

	for _, target := range cfg.Targets {
		startTime := time.Now()

		targetSpan := trace.SpanFromContext(ctx)
		targetSpan.AddEvent("processing_target", trace.WithAttributes(
			attribute.String("target_name", target.Name),
			attribute.String("target_type", string(target.SourceType)),
		))

		job := scanning.NewJob()
		if err := o.createJob(ctx, job); err != nil {
			o.metrics.IncEnumerationErrors(ctx)
			targetSpan.RecordError(err)
			return fmt.Errorf("failed to create job for target %s: %w", target.Name, err)
		}
		o.metrics.IncJobsCreated(ctx)

		// TODO: Maybe handle this in 2 goroutines?
		enumChannels := o.enumerationService.EnumerateTarget(ctx, target, cfg.Auth)

		done := false
		for !done {
			select {
			case scanTargetIDs, ok := <-enumChannels.ScanTargetCh:
				if !ok {
					enumChannels.ScanTargetCh = nil // channel closed
				} else {
					if err := o.jobRepo.AssociateTargets(ctx, job.JobID(), scanTargetIDs); err != nil {
						o.logger.Error(ctx, "Failed to associate target", "error", err)
					}
				}

			case task, ok := <-enumChannels.TaskCh:
				if !ok {
					enumChannels.TaskCh = nil // channel closed
				} else {
					if err := o.eventPublisher.PublishDomainEvent(
						ctx,
						enumeration.NewTaskCreatedEvent(job.JobID(), task),
						events.WithKey(job.JobID().String()),
					); err != nil {
						o.logger.Error(ctx, "Failed to publish task event", "error", err)
					}
				}

			case err, ok := <-enumChannels.ErrCh:
				if ok && err != nil {
					// We got an error from enumerator.
					o.metrics.IncEnumerationErrors(ctx)
					targetSpan.RecordError(err)
					o.logger.Error(ctx, "Enumeration error", "error", err)
					done = true // let's break out for this target
				} else {
					// If !ok, channel closed with no error.
					enumChannels.ErrCh = nil
				}

			default:
				// If all channels have been set to nil, we’re done reading.
				if enumChannels.ScanTargetCh == nil && enumChannels.TaskCh == nil {
					done = true
				}
			}
		}

		duration := time.Since(startTime)
		o.metrics.ObserveTargetProcessingTime(ctx, duration)
		targetSpan.AddEvent("target_enumeration_completed", trace.WithAttributes(
			attribute.String("duration", duration.String()),
		))
	}
	span.AddEvent("fresh_enumeration_completed")

	o.metrics.IncEnumerationCompleted(ctx)
	return nil
}

// createJob persists a new scan job.
func (o *Orchestrator) createJob(ctx context.Context, job *scanning.Job) error {
	ctx, span := o.tracer.Start(ctx, "orchestrator.create_job",
		trace.WithAttributes(
			attribute.String("job_id", job.JobID().String()),
			attribute.String("status", string(job.Status())),
		))
	defer span.End()

	if err := o.jobRepo.CreateJob(ctx, job); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to create job")
		return fmt.Errorf("failed to create job: %w", err)
	}

	span.AddEvent("job_created")
	span.SetStatus(codes.Ok, "job created successfully")
	return nil
}

func (o *Orchestrator) resumeEnumerations(ctx context.Context, states []*enumeration.SessionState) error {
	ctx, span := o.tracer.Start(ctx, "orchestrator.resume_enumerations")
	defer span.End()

	span.AddEvent("resume_enumerations_started")
	for _, state := range states {
		stateSpan := trace.SpanFromContext(ctx)

		// TODO: Use existing job if possible, bleh...
		job := scanning.NewJob()
		if err := o.createJob(ctx, job); err != nil {
			stateSpan.RecordError(err)
			return fmt.Errorf("failed to create job for state %s: %w", state.SessionID(), err)
		}

		// TODO: Implement this.
		// if err := o.enumerationService.ResumeTarget(ctx, state, cb); err != nil {
		// 	stateSpan.RecordError(err)
		// 	continue
		// }

		stateSpan.AddEvent("state_enumeration_completed")
	}
	span.AddEvent("resume_enumerations_completed")

	return nil
}

func (o *Orchestrator) handleProgressEvent(ctx context.Context, evt events.EventEnvelope) error {
	ctx, span := o.tracer.Start(ctx, "orchestrator.handle_progress_event",
		trace.WithAttributes(
			attribute.String("event_type", string(evt.Type)),
		))
	defer span.End()

	handler, exists := o.progressHandlers[evt.Type]
	if !exists {
		span.SetStatus(codes.Error, "no handler registered for event type")
		span.RecordError(fmt.Errorf("no handler registered for event type: %s", evt.Type))
		return fmt.Errorf("no handler registered for event type: %s", evt.Type)
	}
	span.AddEvent("handler_found")

	return handler(ctx, evt)
}

func (o *Orchestrator) handleTaskStarted(ctx context.Context, evt events.EventEnvelope) error {
	ctx, span := o.tracer.Start(ctx, "orchestrator.handle_task_started")
	defer span.End()

	span.AddEvent("processing_task_started")

	startedEvt, ok := evt.Payload.(scanning.TaskStartedEvent)
	if !ok {
		span.RecordError(fmt.Errorf("invalid event payload type: %T", evt.Payload))
		span.SetStatus(codes.Error, "invalid event payload type")
		return fmt.Errorf("invalid event payload type: %T", evt.Payload)
	}
	span.AddEvent("task_started_tracking", trace.WithAttributes(
		attribute.String("task_id", startedEvt.TaskID.String()),
		attribute.String("job_id", startedEvt.JobID.String()),
	))

	if err := o.progressTracker.StartTracking(ctx, startedEvt); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to start tracking task")
		return fmt.Errorf("failed to start tracking task: %w", err)
	}
	span.AddEvent("task_started_tracking_completed")

	return nil
}

func (o *Orchestrator) handleTaskProgressed(ctx context.Context, evt events.EventEnvelope) error {
	ctx, span := o.tracer.Start(ctx, "orchestrator.handle_task_progressed")
	defer span.End()

	span.AddEvent("processing_task_progressed")

	progressEvt, ok := evt.Payload.(scanning.TaskProgressedEvent)
	if !ok {
		span.RecordError(fmt.Errorf("invalid event payload type: %T", evt.Payload))
		span.SetStatus(codes.Error, "invalid event payload type")
		return fmt.Errorf("invalid event payload type: %T", evt.Payload)
	}
	span.AddEvent("task_progressed_event_valid")

	if err := o.progressTracker.UpdateProgress(ctx, progressEvt); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to update progress")
		return fmt.Errorf("failed to update progress: %w", err)
	}
	span.AddEvent("task_progressed_event_updated")

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
	ctx, span := o.tracer.Start(ctx, "orchestrator.handle_rule")
	defer span.End()

	span.AddEvent("processing_rule_update")

	ruleEvent, ok := evt.Payload.(rules.RuleUpdatedEvent)
	if !ok {
		span.RecordError(fmt.Errorf("handleRule: payload is not RuleUpdatedEvent, got %T", evt.Payload))
		span.SetStatus(codes.Error, "payload is not RuleUpdatedEvent")
		return fmt.Errorf("handleRule: payload is not RuleUpdatedEvent, got %T", evt.Payload)
	}

	// Check ephemeral duplicate skip (controller-level).
	o.rulesMutex.RLock()
	lastProcessed, exists := o.processedRules[ruleEvent.Rule.Hash]
	o.rulesMutex.RUnlock()

	if exists && time.Since(lastProcessed) < time.Minute*5 {
		span.AddEvent("skipping_duplicate_rule")
		o.logger.Info(ctx, "Skipping duplicate rule",
			"rule_id", ruleEvent.Rule.RuleID,
			"hash", ruleEvent.Rule.Hash,
			"occurred_at", ruleEvent.OccurredAt())
		return nil
	}

	// Delegate to domain-level service for real domain logic (persisting rule).
	if err := o.rulesService.SaveRule(ctx, ruleEvent.Rule.GitleaksRule); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to persist rule")
		return fmt.Errorf("failed to persist rule: %w", err)
	}

	// Mark processed, do some ephemeral cleanup.
	o.rulesMutex.Lock()
	o.processedRules[ruleEvent.Rule.Hash] = time.Now()
	o.rulesMutex.Unlock()

	span.AddEvent("rule_processed")
	span.SetStatus(codes.Ok, "rule processed")

	o.logger.Info(ctx, "Stored new rule",
		"rule_id", ruleEvent.Rule.RuleID,
		"hash", ruleEvent.Rule.Hash,
		"occurred_at", ruleEvent.OccurredAt())

	return nil
}
