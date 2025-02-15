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
	"github.com/ahrav/gitleaks-armada/internal/config"
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
	metricsTracker       scanning.JobMetricsTracker
	enumCoordinator      enumCoordinator.Coordinator
	rulesService         rulessvc.Service
	scanJobCoordinator  scanning.ScanJobCoordinator
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
	enumerationService enumCoordinator.Coordinator,
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
		enumCoordinator:    enumerationService,
		rulesService:       rulesService,
		stateRepo:          stateRepo,
		cfgLoader:          cfgLoader,
		metrics:            metrics,
		logger:             componentLogger,
		tracer:             tracer,
	}

	o.scanJobCoordinator = scan.NewScanJobCoordinator(
		id,
		jobRepo,
		taskRepo,
		logger,
		tracer,
	)

	executionTracker := scan.NewExecutionTracker(
		id,
		o.scanJobCoordinator,
		eventPublisher,
		logger,
		tracer,
	)

	o.taskHealthSupervisor = scan.NewTaskHealthSupervisor(
		id,
		o.scanJobCoordinator,
		executionTracker,
		eventPublisher,
		tracer,
		logger,
	)

	metricsRepo := scan.NewMetricsRepositoryAdapter(id, jobRepo, taskRepo, tracer)
	o.metricsTracker = scan.NewJobMetricsTracker(id, metricsRepo, eventReplayer, logger, tracer)
	go o.metricsTracker.LaunchMetricsFlusher(30 * time.Second)

	eventsFacilitator := NewEventsFacilitator(
		id,
		executionTracker,
		o.taskHealthSupervisor,
		o.metricsTracker,
		rulesService,
		tracer,
	)
	dispatcher := eventdispatcher.New(id, tracer, logger)
	ctx := context.Background()
	dispatcher.RegisterHandler(ctx, scanning.EventTypeTaskStarted, eventsFacilitator.HandleTaskStarted)
	dispatcher.RegisterHandler(ctx, scanning.EventTypeTaskProgressed, eventsFacilitator.HandleTaskProgressed)
	dispatcher.RegisterHandler(ctx, scanning.EventTypeTaskCompleted, eventsFacilitator.HandleTaskCompleted)
	dispatcher.RegisterHandler(ctx, scanning.EventTypeTaskFailed, eventsFacilitator.HandleTaskFailed)
	dispatcher.RegisterHandler(ctx, scanning.EventTypeTaskHeartbeat, eventsFacilitator.HandleTaskHeartbeat)
	dispatcher.RegisterHandler(ctx, rules.EventTypeRulesUpdated, eventsFacilitator.HandleRule)
	dispatcher.RegisterHandler(ctx, rules.EventTypeRulesPublished, eventsFacilitator.HandleRulesPublished)
	dispatcher.RegisterHandler(ctx, scanning.EventTypeTaskJobMetric, eventsFacilitator.HandleTaskJobMetric)

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
		return o.Enumerate(leaderCtx)
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

// Enumerate starts enumeration sessions for each target in the configuration.
// It creates a job for each target and associates discovered scan targets with that job.
func (o *Orchestrator) Enumerate(ctx context.Context) error {
	ctx, span := o.tracer.Start(ctx, "orchestrator.enumerate",
		trace.WithAttributes(
			attribute.String("controller_id", o.controllerID),
		),
	)
	defer span.End()

	span.AddEvent("checking_active_states")
	activeStates, err := o.stateRepo.GetActiveStates(ctx)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to load active states: %w", err)
	}
	isResumeJob := len(activeStates) > 0

	span.SetAttributes(
		attribute.Int("active_states", len(activeStates)),
		attribute.Bool("is_resume_job", isResumeJob),
	)

	if isResumeJob {
		return o.resumeEnumerations(ctx, activeStates)
	}

	cfg, err := o.cfgLoader.Load(ctx)
	if err != nil {
		o.metrics.IncConfigReloadErrors(ctx)
		return fmt.Errorf("failed to load config: %w", err)
	}
	span.AddEvent("config_loaded")
	span.SetAttributes(
		attribute.Int("target_count", len(cfg.Targets)),
	)
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
	logger := o.logger.With("operation", "start_fresh_enumerations", "target_count", len(cfg.Targets))
	ctx, span := o.tracer.Start(ctx, "orchestrator.start_fresh_enumerations",
		trace.WithAttributes(
			attribute.String("controller_id", o.controllerID),
		),
	)
	defer span.End()

	o.metrics.IncEnumerationStarted(ctx)
	span.AddEvent("fresh_enumeration_started")

	for _, target := range cfg.Targets {
		err := func() error {
			startTime := time.Now()
			targetCtx, targetSpan := o.tracer.Start(ctx, "orchestrator.processing_target",
				trace.WithAttributes(
					attribute.String("target_name", target.Name),
					attribute.String("target_type", string(target.SourceType)),
				))
			defer targetSpan.End()
			targetSpan.AddEvent("processing_target")

			job, err := o.scanJobCoordinator.CreateJob(targetCtx)
			if err != nil {
				// TODO: Revist this we can make this more resilient to allow for failures.
				o.metrics.IncEnumerationErrors(targetCtx)
				targetSpan.RecordError(err)
				return fmt.Errorf("failed to create job for target %s: %w", target.Name, err)
			}
			o.metrics.IncJobsCreated(targetCtx)

			// TODO: Maybe handle this in 2 goroutines?
			enumChannels := o.enumCoordinator.EnumerateTarget(targetCtx, target, cfg.Auth)

			done := false
			for !done {
				select {
				case <-targetCtx.Done():
					targetSpan.AddEvent("target_context_cancelled")
					done = true
				case scanTargetIDs, ok := <-enumChannels.ScanTargetCh:
					scanTargetIDCtx, scanTargetIDSpan := o.tracer.Start(targetCtx, "orchestrator.handle_scan_target_ids")
					if !ok {
						scanTargetIDSpan.AddEvent("scan_target_ids_channel_closed")
						scanTargetIDSpan.SetStatus(codes.Ok, "scan target ids channel closed")
						enumChannels.ScanTargetCh = nil // channel closed
					} else {
						if err := o.scanJobCoordinator.LinkTargets(scanTargetIDCtx, job.JobID(), scanTargetIDs); err != nil {
							scanTargetIDSpan.RecordError(err)
							scanTargetIDSpan.SetStatus(codes.Error, "failed to associate targets")
							logger.Error(scanTargetIDCtx, "Failed to associate targets", "error", err)
						}
						scanTargetIDSpan.AddEvent("targets_associated")
						scanTargetIDSpan.SetStatus(codes.Ok, "targets associated")
					}
					scanTargetIDSpan.End()

				case task, ok := <-enumChannels.TaskCh:
					if !ok {
						enumChannels.TaskCh = nil // channel closed
						continue
					}

					taskCtx, taskSpan := o.tracer.Start(targetCtx, "orchestrator.handle_task_created",
						trace.WithAttributes(
							attribute.String("task_id", task.ID.String()),
							attribute.String("job_id", job.JobID().String()),
						))

					if err := o.eventPublisher.PublishDomainEvent(
						taskCtx,
						enumeration.NewTaskCreatedEvent(job.JobID(), task),
						events.WithKey(task.ID.String()),
					); err != nil {
						taskSpan.RecordError(err)
						taskSpan.SetStatus(codes.Error, "failed to publish task event")
						logger.Error(taskCtx, "Failed to publish task event", "error", err)
					} else {
						taskSpan.AddEvent("task_event_published")
						taskSpan.SetStatus(codes.Ok, "task event published")
					}
					taskSpan.End()

				case err, ok := <-enumChannels.ErrCh:
					errCtx, errSpan := o.tracer.Start(targetCtx, "orchestrator.handle_enumeration_error")
					if ok && err != nil {
						// We got an error from enumerator.
						o.metrics.IncEnumerationErrors(errCtx)
						errSpan.RecordError(err)
						errSpan.SetStatus(codes.Error, "enumeration error")
						logger.Error(errCtx, "Enumeration error", "error", err)
						done = true // let's break out for this target
					} else {
						// If !ok, channel closed with no error.
						enumChannels.ErrCh = nil
						errSpan.AddEvent("enumeration_error_channel_closed")
						errSpan.SetStatus(codes.Ok, "enumeration error channel closed")
					}
					errSpan.End()
				default:
					if enumChannels.ScanTargetCh == nil && enumChannels.TaskCh == nil && enumChannels.ErrCh == nil {
						done = true
					}
				}

			}

			duration := time.Since(startTime)
			o.metrics.ObserveTargetProcessingTime(targetCtx, duration)
			targetSpan.AddEvent("target_enumeration_completed", trace.WithAttributes(
				attribute.String("duration", duration.String()),
			))
			logger.Info(targetCtx, "Target enumeration completed", "duration", duration.String())

			targetSpan.SetStatus(codes.Ok, "target enumeration completed")
			targetSpan.End()

			return nil
		}()
		if err != nil {
			return err
		}
	}
	span.AddEvent("fresh_enumeration_completed")

	o.metrics.IncEnumerationCompleted(ctx)
	return nil
}

// createJob persists a new scan job.
func (o *Orchestrator) createJob(ctx context.Context, job *scanning.Job) error {
	ctx, span := o.tracer.Start(ctx, "orchestrator.create_job",
		trace.WithAttributes(
			attribute.String("controller_id", o.controllerID),
			attribute.String("job_id", job.JobID().String()),
			attribute.String("status", string(job.Status())),
		))
	defer span.End()

	_, err := o.scanJobCoordinator.CreateJob(ctx)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to create job")
		return fmt.Errorf("failed to create job: %w", err)
	}
	span.AddEvent("job_created")
	span.SetStatus(codes.Ok, "job created successfully")

	return nil
}

func (o *Orchestrator) resumeEnumerations(ctx context.Context, states []*enumeration.SessionState) error {
	ctx, span := o.tracer.Start(ctx, "orchestrator.resume_enumerations",
		trace.WithAttributes(
			attribute.String("controller_id", o.controllerID),
		),
	)
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
	o.metricsTracker.Stop(shutdownCtx)
	shutdownSpan.AddEvent("component_shutdown_complete")
	logger.Info(shutdownCtx, "Orchestrator shutdown complete")

	return nil
}

// handleEnumerationRequestedEvent handles the EnumerationRequestedEvent and triggers enumeration.
func (o *Orchestrator) handleEnumerationRequestedEvent(
	ctx context.Context,
	evt events.EventEnvelope,
	ack events.AckFunc,
) error {
	ctx, span := o.tracer.Start(ctx, "orchestrator.handle_enumeration_requested")
	defer span.End()

	enumEvt, ok := evt.Payload.(enumeration.EnumerationRequestedEvent)
	if !ok {
		err := fmt.Errorf("expected EnumerationRequestedEvent but got %T", evt.Payload)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		ack(err)
		return err
	}

	o.logger.Info(ctx, "Received enumeration request event",
		"controller_id", o.controllerID,
		"requested_by", enumEvt.RequestedBy)

	// Check if enumerations are already in progress here to avoid concurrent runs.

	err := o.metrics.TrackEnumeration(ctx, func() error {
		return o.startFreshEnumerations(ctx, enumEvt.Config)
	})
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		ack(err)
		return fmt.Errorf("failed to start enumeration from event: %w", err)
	}

	span.AddEvent("enumeration_triggered_from_event")
	ack(nil)
	return nil
}
