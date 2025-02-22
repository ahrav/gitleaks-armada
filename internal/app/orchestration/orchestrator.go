// Package orchestration provides a distributed work coordination system that manages
// scan jobs across a cluster of workers. It handles leader election, work distribution,
// and maintains system-wide scanning state.
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
	"github.com/ahrav/gitleaks-armada/internal/config/loaders"
	"github.com/ahrav/gitleaks-armada/internal/domain/enumeration"
	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/domain/rules"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	eventdispatcher "github.com/ahrav/gitleaks-armada/internal/infra/event_dispatcher"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

// Orchestrator coordinates work distribution across a cluster of workers. It manages
// leader election, rule processing, and target enumeration to ensure efficient
// scanning across the cluster. Only one controller is active at a time to prevent
// duplicate work.
type Orchestrator struct {
	controllerID string

	clusterCoordinator cluster.Coordinator
	eventBus           events.EventBus
	eventPublisher     events.DomainEventPublisher

	cfgLoader loaders.Loader

	taskHealthSupervisor scanning.TaskHealthMonitor
	metricsAggregator    scanning.JobMetricsAggregator
	enumService          enumeration.Service
	rulesService         rulessvc.Service
	stateRepo            enumeration.StateRepository

	dispatcher *eventdispatcher.Dispatcher

	// mu protects running and cancelFn state
	mu        sync.Mutex
	running   bool
	cancelFn  context.CancelFunc
	startTime time.Time

	logger  *logger.Logger
	metrics OrchestrationMetrics
	tracer  trace.Tracer
}

// NewOrchestrator creates an Orchestrator instance that coordinates scanning operations
// across a distributed cluster of workers. It implements the leader-follower pattern
// where only one instance actively manages work distribution while others stand by as
// hot backups.
//
// The constructor requires several dependencies to handle different aspects of the system:
//
//   - id: Unique identifier for this controller instance
//   - coord: Implements leader election using distributed locks
//   - queue: Reliable message queue for distributing work items
//   - eventPublisher: Broadcasts domain events for system observability
//   - eventReplayer: Replays domain events from a specific position
//   - enumerationService: Implements scanning logic and target discovery
//   - rulesService: Manages scanning rules and their updates
//   - jobService: Handles job lifecycle (creation, updates, completion)
//   - taskService: Manages individual task execution and state
//   - stateRepo: Persists enumeration state for crash recovery
//   - cfgLoader: Loads system configuration dynamically
//   - logger: Structured logging for debugging and audit trails
//   - metrics: Runtime metrics for monitoring and alerting
//   - tracer: Distributed tracing for request flow analysis
//
// The constructor sets up internal event handlers for:
//   - Task lifecycle events (started, progressed, completed)
//   - Rule updates and publishing events
//   - Leadership change notifications
func NewOrchestrator(
	id string,
	coord cluster.Coordinator,
	queue events.EventBus,
	eventPublisher events.DomainEventPublisher,
	eventReplayer events.DomainEventReplayer,
	enumCoord enumeration.Coordinator,
	rulesService rulessvc.Service,
	taskRepo scanning.TaskRepository,
	jobRepo scanning.JobRepository,
	stateRepo enumeration.StateRepository,
	cfgLoader loaders.Loader,
	logger *logger.Logger,
	metrics OrchestrationMetrics,
	tracer trace.Tracer,
) *Orchestrator {
	componentLogger := logger.With("component", "orchestrator")
	o := &Orchestrator{
		controllerID:       id,
		clusterCoordinator: coord,
		eventBus:           queue,
		eventPublisher:     eventPublisher,
		rulesService:       rulesService,
		stateRepo:          stateRepo,
		cfgLoader:          cfgLoader,
		metrics:            metrics,
		logger:             componentLogger,
		tracer:             tracer,
	}

	jobTaskSvc := scan.NewJobTaskService(
		id,
		jobRepo,
		taskRepo,
		logger,
		tracer,
	)

	executionTracker := scan.NewExecutionTracker(
		id,
		jobTaskSvc,
		eventPublisher,
		logger,
		tracer,
	)

	o.taskHealthSupervisor = scan.NewTaskHealthSupervisor(
		id,
		jobTaskSvc,
		executionTracker,
		eventPublisher,
		tracer,
		logger,
	)

	o.metricsAggregator = scan.NewJobMetricsAggregator(id, jobTaskSvc, eventReplayer, logger, tracer)
	go o.metricsAggregator.LaunchMetricsFlusher(30 * time.Second)

	o.enumService = enumCoordinator.NewEnumService(
		id,
		enumCoord,
		eventPublisher,
		logger,
		metrics,
		tracer,
	)

	eventsFacilitator := NewEventsFacilitator(
		id,
		executionTracker,
		o.taskHealthSupervisor,
		o.metricsAggregator,
		o.enumService,
		rulesService,
		tracer,
	)
	dispatcher := eventdispatcher.New(id, tracer, logger)
	ctx := context.Background()

	dispatcher.RegisterHandler(
		ctx,
		scanning.EventTypeJobRequested,
		eventsFacilitator.HandleScanJobRequested,
	)
	dispatcher.RegisterHandler(ctx, scanning.EventTypeJobScheduled, eventsFacilitator.HandleScanJobScheduled)
	dispatcher.RegisterHandler(ctx, scanning.EventTypeTaskStarted, eventsFacilitator.HandleTaskStarted)
	dispatcher.RegisterHandler(ctx, scanning.EventTypeTaskProgressed, eventsFacilitator.HandleTaskProgressed)
	dispatcher.RegisterHandler(ctx, scanning.EventTypeTaskCompleted, eventsFacilitator.HandleTaskCompleted)
	dispatcher.RegisterHandler(ctx, scanning.EventTypeTaskFailed, eventsFacilitator.HandleTaskFailed)
	dispatcher.RegisterHandler(ctx, scanning.EventTypeTaskHeartbeat, eventsFacilitator.HandleTaskHeartbeat)
	dispatcher.RegisterHandler(ctx, rules.EventTypeRulesUpdated, eventsFacilitator.HandleRule)
	dispatcher.RegisterHandler(ctx, rules.EventTypeRulesPublished, eventsFacilitator.HandleRulesPublished)
	dispatcher.RegisterHandler(ctx, scanning.EventTypeTaskJobMetric, eventsFacilitator.HandleTaskJobMetric)
	dispatcher.RegisterHandler(ctx, scanning.EventTypeJobEnumerationCompleted, eventsFacilitator.HandleTaskJobMetric)

	o.dispatcher = dispatcher

	return o
}

// Run starts the orchestrator's leadership election and target processing loop. It manages
// the lifecycle of scan target enumeration by participating in leader election and coordinating
// scan target processing across the cluster. When elected leader, it will either resume
// in-progress enumerations or start fresh ones based on configuration.
//
// The orchestrator uses a distributed lock to ensure only one instance is processing targets
// at a time, preventing duplicate work and race conditions. It also maintains internal state
// to track leadership changes and handle graceful shutdowns.
//
// Returns a channel that closes when initialization is complete, signaling readiness, and
// any startup errors. Callers should wait for the ready signal before proceeding.
func (o *Orchestrator) Run(ctx context.Context) error {
	logger := o.logger.With("operation", "run")
	o.startTime = time.Now().UTC()
	runCtx, runSpan := o.tracer.Start(ctx, "orchestrator.run",
		trace.WithAttributes(
			attribute.String("controller_id", o.controllerID),
			attribute.String("component", "orchestrator"),
			attribute.String("start_time", o.startTime.Format(time.RFC3339)),
		))
	logger.Info(runCtx, "Orchestrator started")

	o.taskHealthSupervisor.Start(runCtx)
	runSpan.AddEvent("heartbeat_monitor_started")

	if err := o.subscribeToEvents(runCtx); err != nil {
		runSpan.RecordError(err)
		runSpan.SetStatus(codes.Error, "failed to subscribe to events")
		runSpan.End()
		return err
	}

	readyCh, leaderCh := o.makeOrchestrationChannels()
	defer close(readyCh)
	defer close(leaderCh)

	leaderCtx, leaderCancel := context.WithCancel(runCtx)
	o.registerCancelFunc(leaderCancel)

	o.setupLeadershipCallback(leaderCtx, leaderCh)

	go o.startLeadershipLoop(leaderCtx, leaderCh, readyCh)

	if err := o.startCoordinator(leaderCtx); err != nil {
		runSpan.RecordError(err)
		runSpan.SetStatus(codes.Error, "failed to start coordinator")
		runSpan.End()
		return err
	}

	runSpan.AddEvent("orchestrator_ready")
	runSpan.End() // Avoid a long running span.

	// Wait for context cancellation.
	<-ctx.Done()
	return nil
}

// registerCancelFunc safely stores the cancellation function under lock.
func (o *Orchestrator) registerCancelFunc(cancel context.CancelFunc) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.cancelFn = cancel
}

// makeOrchestrationChannels creates the channels needed for leadership coordination
// and readiness signaling.
func (o *Orchestrator) makeOrchestrationChannels() (chan struct{}, chan bool) {
	ready := make(chan struct{})
	leaderCh := make(chan bool, 1)
	return ready, leaderCh
}

// subscribeToEvents sets up event subscriptions for tracking task progress and rule updates.
func (o *Orchestrator) subscribeToEvents(ctx context.Context) error {
	subCtx, subSpan := o.tracer.Start(ctx, "orchestrator.subscribe_events",
		trace.WithAttributes(
			attribute.String("controller_id", o.controllerID),
		))
	defer subSpan.End()

	eventTypes := []events.EventType{
		rules.EventTypeRulesUpdated,
		rules.EventTypeRulesPublished,
		scanning.EventTypeJobRequested,
		scanning.EventTypeJobScheduled,
		scanning.EventTypeJobEnumerationCompleted,
		scanning.EventTypeTaskStarted,
		scanning.EventTypeTaskProgressed,
		scanning.EventTypeTaskCompleted,
		scanning.EventTypeTaskFailed,
		scanning.EventTypeTaskHeartbeat,
		scanning.EventTypeTaskJobMetric,
	}

	if err := o.eventBus.Subscribe(
		subCtx,
		eventTypes,
		func(ctx context.Context, evt events.EventEnvelope, ack events.AckFunc) error {
			return o.dispatcher.Dispatch(ctx, evt, ack)
		},
	); err != nil {
		subSpan.RecordError(err)
		subSpan.SetStatus(codes.Error, "failed to subscribe to progress events")
		return fmt.Errorf("orchestrator[%s]: failed to subscribe to progress events: %w", o.controllerID, err)
	}

	subSpan.AddEvent("subscribed_to_events")
	return nil
}

// setupLeadershipCallback configures the handler for leadership changes, managing
// state transitions and metric updates when leadership status changes.
func (o *Orchestrator) setupLeadershipCallback(ctx context.Context, leaderCh chan<- bool) {
	logger := o.logger.With("operation", "setup_leadership_callback")
	o.clusterCoordinator.OnLeadershipChange(func(isLeader bool) {
		leaderCtx, leaderSpan := o.tracer.Start(ctx, "orchestrator.leadership_change",
			trace.WithAttributes(
				attribute.String("controller_id", o.controllerID),
				attribute.Bool("is_leader", isLeader),
			))
		defer leaderSpan.End()

		logger.Info(leaderCtx, "Leadership change",
			"controller_id", o.controllerID, "is_leader", isLeader)
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
		default:
			leaderSpan.AddEvent("leadership_channel_full")
			logger.Info(leaderCtx, "Warning: leadership channel full, skipping update",
				"controller_id", o.controllerID)
		}
	})
}

// startLeadershipLoop handles the main leadership election loop, coordinating state changes
// and enumeration processes based on leadership status.
func (o *Orchestrator) startLeadershipLoop(
	orchestratorCtx context.Context,
	leaderCh <-chan bool,
	readyCh chan<- struct{},
) {
	readyClosed := false
	logger := o.logger.With("operation", "start_leadership_loop")
	logger.Info(orchestratorCtx, "Waiting for leadership signal...", "controller_id", o.controllerID)

	for isLeader := range leaderCh {
		o.handleLeadership(orchestratorCtx, isLeader, &readyClosed, readyCh)
	}
}

// handleLeadership processes leadership state changes and triggers enumeration
// when leadership is acquired.
func (o *Orchestrator) handleLeadership(ctx context.Context, isLeader bool, readyClosed *bool, readyCh chan<- struct{}) {
	logger := o.logger.With("operation", "handle_leadership")
	leaderCtx, leaderSpan := o.tracer.Start(ctx, "orchestrator.handle_leadership",
		trace.WithAttributes(attribute.Bool("is_leader", isLeader)))
	defer leaderSpan.End()

	if !isLeader {
		logger.Info(leaderCtx, "Not leader, waiting...")
		leaderSpan.AddEvent("not_leader")
		return
	}

	logger.Info(leaderCtx, "Leadership acquired, processing targets...")
	leaderSpan.AddEvent("leader_acquired")

	// TODO: Figure out an overall strategy to reslient publishing of events across the system.
	if err := o.requestRulesUpdate(ctx); err != nil {
		leaderSpan.RecordError(err)
		leaderSpan.SetStatus(codes.Error, "failed to request rules update")
		logger.Error(leaderCtx, "Failed to request rules update", "error", err)
	} else {
		// TODO: come back to this to determine if we should return if we fail to request rules update.
		leaderSpan.AddEvent("rules_update_requested")
	}

	err := o.metrics.TrackEnumeration(leaderCtx, func() error {
		// TODO: This should get ripped out and use the enumeration service.
		// return o.Enumerate(leaderCtx)
		return nil
	})
	if err != nil {
		leaderSpan.RecordError(err)
		leaderSpan.SetStatus(codes.Error, "enumeration failed")
		logger.Error(leaderCtx, "Failed to run enumeration", "error", err)
	}
	leaderSpan.AddEvent("enumeration_completed")

	if !*readyClosed {
		close(readyCh)
		*readyClosed = true
		readySpan := trace.SpanFromContext(ctx)
		readySpan.AddEvent("ready_channel_closed")
		logger.Info(ctx, "Orchestrator is ready.")
	}
}

// startCoordinator initializes the cluster coordinator component.
func (o *Orchestrator) startCoordinator(ctx context.Context) error {
	logger := o.logger.With("operation", "start_coordinator")
	startSpan := trace.SpanFromContext(ctx)
	startSpan.AddEvent("starting_coordinator", trace.WithAttributes(
		attribute.String("controller_id", o.controllerID),
	))

	logger.Info(ctx, "Starting coordinator...")
	if err := o.clusterCoordinator.Start(ctx); err != nil {
		startSpan.RecordError(err)
		startSpan.SetStatus(codes.Error, "failed to start coordinator")
		return fmt.Errorf("failed to start coordinator: %w", err)
	}

	startSpan.AddEvent("coordinator_started")
	return nil
}

// requestRulesUpdate initiates a rule update request and waits for completion
func (o *Orchestrator) requestRulesUpdate(ctx context.Context) error {
	ctx, span := o.tracer.Start(ctx, "orchestrator.request_rules_update",
		trace.WithAttributes(
			attribute.String("controller_id", o.controllerID),
		),
	)
	defer span.End()

	if err := o.eventPublisher.PublishDomainEvent(ctx, rules.NewRuleRequestedEvent()); err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to publish rules request: %w", err)
	}

	span.AddEvent("rules_update_requested")
	return nil
}

// TODO: Consolidate this with the enumeration service with a provided config via a configloader
// or some other mechanism.
// Enumerate starts enumeration sessions for each target in the configuration.
// It creates a job for each target and associates discovered scan targets with that job.
// func (o *Orchestrator) Enumerate(ctx context.Context) error {
// 	ctx, span := o.tracer.Start(ctx, "orchestrator.enumerate",
// 		trace.WithAttributes(
// 			attribute.String("controller_id", o.controllerID),
// 		),
// 	)
// 	defer span.End()

// 	span.AddEvent("checking_active_states")
// 	activeStates, err := o.stateRepo.GetActiveStates(ctx)
// 	if err != nil {
// 		span.RecordError(err)
// 		return fmt.Errorf("failed to load active states: %w", err)
// 	}
// 	isResumeJob := len(activeStates) > 0

// 	span.SetAttributes(
// 		attribute.Int("active_states", len(activeStates)),
// 		attribute.Bool("is_resume_job", isResumeJob),
// 	)

// 	if isResumeJob {
// 		// TODO: Implement resume enumerations.
// 		// o.enumService.ResumeEnumeration(ctx, activeStates)
// 	}

// 	cfg, err := o.cfgLoader.Load(ctx)
// 	if err != nil {
// 		o.metrics.IncConfigReloadErrors(ctx)
// 		return fmt.Errorf("failed to load config: %w", err)
// 	}
// 	span.AddEvent("config_loaded")
// 	span.SetAttributes(
// 		attribute.Int("target_count", len(cfg.Targets)),
// 	)
// 	o.metrics.IncConfigReloads(ctx)

// 	// Delegate the enumeration process to the dedicated enumeration service.
// 	if err := o.enumService.StartEnumeration(ctx, cfg); err != nil {
// 		span.RecordError(err)
// 		span.SetStatus(codes.Error, "enumeration failed")
// 		o.logger.Error(ctx, "Enumeration failed", "error", err)
// 		return fmt.Errorf("failed to start enumeration: %w", err)
// 	}
// 	span.AddEvent("enumeration_started")

// 	return nil
// }

// Stop gracefully shuts down the controller if it is running.
// It is safe to call multiple times.
func (o *Orchestrator) Stop(ctx context.Context) error {
	logger := o.logger.With("operation", "stop")
	ctx, span := o.tracer.Start(ctx, "orchestrator.stop",
		trace.WithAttributes(
			attribute.String("controller_id", o.controllerID),
		),
	)
	defer span.End()

	o.mu.Lock()
	if !o.running {
		span.AddEvent("orchestrator_not_running")
		span.SetStatus(codes.Ok, "orchestrator not running")
		o.mu.Unlock()
		return nil
	}

	o.running = false
	if o.cancelFn != nil {
		span.AddEvent("teardown_function_called")
		o.cancelFn()
	}
	o.mu.Unlock()

	// Call internal shutdown to handle cleanup.
	if err := o.shutdown(ctx); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "shutdown failed")
		return err
	}

	runDuration := time.Since(o.startTime)
	span.AddEvent("orchestrator_stopped", trace.WithAttributes(
		attribute.String("run_duration", runDuration.String()),
	))
	span.SetStatus(codes.Ok, "orchestrator stopped")
	logger.Info(ctx, "Orchestrator stopped.", "run_duration", runDuration.String())

	return nil
}

// shutdown is the internal method for cleanup.
func (o *Orchestrator) shutdown(ctx context.Context) error {
	logger := o.logger.With("operation", "shutdown")
	shutdownCtx, shutdownSpan := o.tracer.Start(ctx, "orchestrator.shutdown")
	defer shutdownSpan.End()

	o.taskHealthSupervisor.Stop()
	o.metricsAggregator.Stop(shutdownCtx)
	shutdownSpan.AddEvent("component_shutdown_complete")
	logger.Info(shutdownCtx, "Orchestrator shutdown complete")

	return nil
}
