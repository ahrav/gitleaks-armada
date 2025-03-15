// Package scanning provides services for coordinating and executing secret scanning operations.
package scanning

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/app/scanning/acl"
	"github.com/ahrav/gitleaks-armada/internal/app/scanning/dtos"
	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/domain/rules"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	domain "github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
	"github.com/ahrav/gitleaks-armada/pkg/common/uuid"
)

// metrics defines the interface for tracking scanning-related metrics.
type metrics interface {
	TrackTask(ctx context.Context, f func() error) error
	SetActiveWorkers(ctx context.Context, count int)
}

// RuleProvider defines the interface for scanners that use rule-based detection.
// TODO: IDK... what?
type RuleProvider interface {
	// GetRules streams converted rules ready for publishing.
	// The channel will be closed when all rules have been sent.
	GetRules(ctx context.Context) (<-chan rules.GitleaksRuleMessage, error)
}

// ScanOrchestrator coordinates the execution of secret scanning tasks across multiple workers.
// It subscribes to enumeration events and distributes scanning work to maintain optimal
// resource utilization.
type ScanOrchestrator struct {
	scannerID uuid.UUID

	eventBus          events.EventBus // Main event bus for task events
	broadcastEventBus events.EventBus // Event bus for broadcast events where all scanners need to receive the message
	domainPublisher   events.DomainEventPublisher
	progressReporter  ProgressReporter

	secretScanner SecretScanner
	enumACL       acl.EnumerationACL

	ruleProvider RuleProvider // TODO: Figure out where this should live

	// jobStateController is used to track the state of jobs and its associated tasks.
	// This is used to pause/resume jobs and tasks.
	jobStateController *JobTaskStateController

	workers   int
	stopCh    chan struct{}
	workerWg  sync.WaitGroup
	taskEvent chan *dtos.ScanRequest
	// This is a semaphore to limit the number of high priority tasks that can be processed.
	// We want to make sure we have a way to prioritize resuming tasks over new tasks,
	// but we also want to make sure we don't overwhelm the system with too many high priority tasks.
	highPrioritySem chan struct{}

	logger  *logger.Logger
	metrics metrics
	tracer  trace.Tracer
}

// NewScanOrchestrator creates a new scan orchestrator with the specified dependencies.
// It configures worker pools based on available CPU cores to optimize scanning throughput.
func NewScanOrchestrator(
	id uuid.UUID,
	eventBus events.EventBus,
	broadcastEventBus events.EventBus,
	dp events.DomainEventPublisher,
	pr ProgressReporter,
	scanner SecretScanner,
	logger *logger.Logger,
	metrics metrics,
	tracer trace.Tracer,
) *ScanOrchestrator {
	workerCount := 4 // TODO: This should be configurable or set via runtime.NumCPU
	logger = logger.With(
		"component", "scanner_service",
		"num_workers", workerCount,
	)

	// Try to get rule provider if scanner supports it. (e.g. Gitleaks)
	ruleProvider, _ := scanner.(RuleProvider)

	return &ScanOrchestrator{
		scannerID:          id,
		eventBus:           eventBus,
		broadcastEventBus:  broadcastEventBus,
		domainPublisher:    dp,
		secretScanner:      scanner,
		progressReporter:   pr,
		ruleProvider:       ruleProvider,
		enumACL:            acl.EnumerationACL{},
		jobStateController: NewJobTaskStateController(id.String(), logger, tracer),
		workers:            workerCount,
		stopCh:             make(chan struct{}),
		taskEvent:          make(chan *dtos.ScanRequest, workerCount*10),
		highPrioritySem:    make(chan struct{}, workerCount), // TODO: Come back to this
		logger:             logger,
		metrics:            metrics,
		tracer:             tracer,
	}
}

// Run starts the scanner service and its worker pool. It subscribes to task events
// and coordinates scanning operations until the context is cancelled.
// TODO: Use Dispatcher to handle events similar to the controller.
func (s *ScanOrchestrator) Run(ctx context.Context) error {
	// Create a shorter-lived span just for initialization.
	// This is because Run is a long-running operation and we don't want to
	// create a span for the entire operation.
	initCtx, initSpan := s.tracer.Start(ctx, "scanner_service.scanning.init",
		trace.WithAttributes(
			attribute.String("component", "scanner_service"),
			attribute.String("scanner_id", s.scannerID.String()),
			attribute.Int("num_workers", s.workers),
		))

	s.logger.Info(initCtx, "Running scanner service")

	// Subscribe to task events.
	// TODO: We need to make handling events more resilient once we ack (commit)
	// the event, but fail after.
	if err := s.eventBus.Subscribe(
		ctx,
		[]events.EventType{
			scanning.EventTypeTaskCreated,
			scanning.EventTypeTaskResume,
			rules.EventTypeRulesRequested,
		},
		s.handleEvent,
	); err != nil {
		initSpan.RecordError(err)
		initSpan.SetStatus(codes.Error, "failed to subscribe to events")
		return fmt.Errorf("failed to subscribe to events: %w", err)
	}

	// Subscribe to broadcast events where every scanner instance needs to receive the message.
	if err := s.broadcastEventBus.Subscribe(
		ctx,
		[]events.EventType{
			scanning.EventTypeJobPaused,
			scanning.EventTypeJobCancelled,
		},
		s.handleEvent,
	); err != nil {
		initSpan.RecordError(err)
		initSpan.SetStatus(codes.Error, "failed to subscribe to broadcast events")
		return fmt.Errorf("failed to subscribe to broadcast events: %w", err)
	}

	initSpan.AddEvent("starting_workers")
	s.workerWg.Add(s.workers)
	for i := range s.workers {
		go func(workerID int) {
			defer s.workerWg.Done()
			s.workerLoop(ctx, workerID)
		}(i)
	}
	s.metrics.SetActiveWorkers(initCtx, s.workers)

	initSpan.AddEvent("subscribed_to_events")
	initSpan.End()

	<-ctx.Done()
	s.logger.Info(ctx, "Stopping scanner service", "id", s.scannerID)

	_, shutdownSpan := s.tracer.Start(ctx, "scanner_service.scanning.shutdown")
	defer shutdownSpan.End()

	shutdownSpan.AddEvent("initiating_shutdown")
	close(s.stopCh)
	close(s.taskEvent)
	s.workerWg.Wait()
	shutdownSpan.AddEvent("shutdown_complete")

	return ctx.Err()
}

// handleEvent routes events to appropriate handlers.
// TODO: Replace this with an events facilitator.
func (s *ScanOrchestrator) handleEvent(ctx context.Context, evt events.EventEnvelope, ack events.AckFunc) error {
	switch evt.Type {
	case scanning.EventTypeTaskResume:
		return s.handleTaskResumeEvent(ctx, evt, ack)
	case scanning.EventTypeTaskCreated:
		return s.handleTaskEvent(ctx, evt, ack)
	case rules.EventTypeRulesRequested:
		return s.handleRuleRequest(ctx, evt, ack)
	case scanning.EventTypeJobPaused:
		return s.handleJobPausedEvent(ctx, evt, ack)
	case scanning.EventTypeJobCancelled:
		return s.handleJobCancelledEvent(ctx, evt, ack)
	default:
		return fmt.Errorf("unknown event type: %s", evt.Type)
	}
}

// handleRuleRequest processes rule request events and publishes current rules
// TODO: Handle the situation where the scanner crashes before all rules are published.
func (s *ScanOrchestrator) handleRuleRequest(
	ctx context.Context,
	evt events.EventEnvelope,
	ack events.AckFunc,
) error {
	logger := logger.NewLoggerContext(s.logger.With(
		"operation", "handle_rule_request",
		"event_type", string(evt.Type),
	))
	ctx, span := s.tracer.Start(ctx, "scanner_service.scanning.handle_rule_request",
		trace.WithAttributes(
			attribute.String("component", "scanner_service"),
			attribute.String("scanner_id", s.scannerID.String()),
			attribute.String("event_type", string(evt.Type)),
		))
	defer span.End()

	// Get rule channel from the scanner if it supports them.
	ruleChan, err := s.ruleProvider.GetRules(ctx)
	if err != nil {
		ack(err)
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to get rules from scanner")
		return fmt.Errorf("failed to get rules: %w", err)
	}
	ack(nil)
	logger.Info(ctx, "Rules received")

	ruleCount := 0
	for rule := range ruleChan {
		if err := s.domainPublisher.PublishDomainEvent(ctx, rules.NewRuleUpdatedEvent(rule)); err != nil {
			span.RecordError(err)
			return fmt.Errorf("failed to publish rule: %w", err)
		}
		ruleCount++
	}

	span.SetAttributes(attribute.Int("rules_published", ruleCount))

	if err := s.domainPublisher.PublishDomainEvent(ctx, rules.NewRulePublishingCompletedEvent()); err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to publish completion event: %w", err)
	}
	logger.Info(ctx, "Rules published")
	span.AddEvent("rules_published")

	return nil
}

// handleTaskEvent processes incoming task events and routes them to available workers.
// It ensures graceful handling of shutdown scenarios to prevent task loss.
func (s *ScanOrchestrator) handleTaskEvent(
	ctx context.Context,
	evt events.EventEnvelope,
	ack events.AckFunc,
) error {
	logger := logger.NewLoggerContext(s.logger.With(
		"operation", "handle_task_event",
		"event_type", string(evt.Type),
	))
	ctx, span := s.tracer.Start(ctx, "scanner_service.scanning.handle_task_event",
		trace.WithSpanKind(trace.SpanKindConsumer),
		trace.WithAttributes(
			attribute.String("component", "scanner_service"),
			attribute.String("event_type", string(evt.Type)),
		))
	defer span.End()

	tce, ok := evt.Payload.(*scanning.TaskCreatedEvent)
	if !ok {
		span.SetStatus(codes.Error, "invalid event payload type")
		return fmt.Errorf("expected TaskCreatedEvent, got %T", evt.Payload)
	}
	logger.Add(
		"task_id", tce.TaskID,
		"resource_uri", tce.ResourceURI,
		"source_type", tce.SourceType,
		// "session_id", tce.SessionID,
	)
	logger.Debug(ctx, "Routing task")

	span.SetAttributes(
		attribute.String("task_id", tce.TaskID.String()),
		attribute.String("resource_uri", tce.ResourceURI),
		attribute.String("source_type", string(tce.SourceType)),
		// attribute.String("session_id", tce.SessionID.String()),
	)
	span.AddEvent("routing_task")

	select {
	case s.taskEvent <- s.enumACL.ToScanRequest(tce):
		ack(nil)
		logger.Debug(ctx, "Task routed")
		span.AddEvent("task_routed")
		return nil
	case <-ctx.Done():
		ack(ctx.Err())
		span.SetStatus(codes.Error, "context cancelled")
		return ctx.Err()
	case <-s.stopCh:
		ack(fmt.Errorf("scanner[%s]: stopping", s.scannerID))
		span.SetStatus(codes.Error, "service stopping")
		return fmt.Errorf("scanner[%s]: stopping", s.scannerID)
	}
}

// handleTaskResumeEvent spawns a goroutine for high-priority tasks:
func (s *ScanOrchestrator) handleTaskResumeEvent(
	ctx context.Context,
	evt events.EventEnvelope,
	ack events.AckFunc,
) error {
	logger := logger.NewLoggerContext(s.logger.With(
		"operation", "handle_task_resume_event",
		"event_type", string(evt.Type),
	))
	ctx, span := s.tracer.Start(ctx, "scanner_service.scanning.handle_task_resume_event",
		trace.WithAttributes(
			attribute.String("component", "scanner_service"),
			attribute.String("event_type", string(evt.Type)),
		))
	defer span.End()

	span.AddEvent("starting_resume_task")

	rEvt, ok := evt.Payload.(*scanning.TaskResumeEvent)
	if !ok {
		err := fmt.Errorf("invalid resume event payload: %T", evt.Payload)
		span.SetStatus(codes.Error, err.Error())
		span.RecordError(err)
		return err
	}
	logger.Add("task_id", rEvt.TaskID, "job_id", rEvt.JobID, "resource_uri", rEvt.ResourceURI)
	logger.Info(ctx, "Resuming task")

	req, err := dtos.NewScanRequestFromResumeEvent(rEvt)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to create scan request")
		return fmt.Errorf("failed to create scan request: %w", err)
	}
	span.SetAttributes(
		attribute.String("checkpoint", req.Metadata[dtos.MetadataKeyCheckpoint]),
		attribute.String("sequence_num", req.Metadata[dtos.MetadataKeySequenceNum]),
	)

	s.highPrioritySem <- struct{}{}
	ack(nil)
	go func() {
		defer func() { <-s.highPrioritySem }()

		// Remove the job from the paused state to allow it to be processed again
		s.jobStateController.ResumeJob(req.JobID)

		if err := s.executeScanTask(ctx, req, logger); err != nil {
			logger.Error(ctx, "Failed to handle scan task", "err", err)
			span.RecordError(err)
			span.SetStatus(codes.Error, "failed to handle scan task")
			return
		}
		span.AddEvent("resume_task_handled")
		span.SetStatus(codes.Ok, "resume_task_handled")
		logger.Info(ctx, "Resumed task successfully")
	}()

	span.AddEvent("resume_task_spawned")
	span.SetStatus(codes.Ok, "resume_task_spawned")
	logger.Info(ctx, "Resume task spawned")

	return nil
}

// handleJobPausedEvent processes job paused events and handles the task.
// TODO: How do we want to handle the scenario where the scanner gets killed.
// We lose our in-memory paused job state.
func (s *ScanOrchestrator) handleJobPausedEvent(
	ctx context.Context,
	evt events.EventEnvelope,
	ack events.AckFunc,
) error {
	logger := logger.NewLoggerContext(s.logger.With(
		"operation", "handle_job_paused_event",
		"event_type", string(evt.Type),
	))
	ctx, span := s.tracer.Start(ctx, "scanner_service.scanning.handle_job_paused_event",
		trace.WithAttributes(
			attribute.String("component", "scanner_service"),
			attribute.String("scanner_id", s.scannerID.String()),
			attribute.String("event_type", string(evt.Type)),
		))
	defer span.End()
	defer ack(nil)

	span.AddEvent("starting_job_paused_task")

	jobPausedEvt, ok := evt.Payload.(scanning.JobPausedEvent)
	if !ok {
		err := fmt.Errorf("invalid job paused event payload: %T", evt.Payload)
		span.SetStatus(codes.Error, err.Error())
		span.RecordError(err)
		return err
	}
	logger.Add("job_id", jobPausedEvt.JobID)
	logger.Info(ctx, "Handling job paused task")

	jobID := uuid.MustParse(jobPausedEvt.JobID)
	cancelCount := s.jobStateController.PauseJob(jobID)

	logger.Info(ctx, "Job paused tasks cancelled", "cancel_count", cancelCount)
	span.AddEvent("job_paused_task_handled")
	span.SetStatus(codes.Ok, "job_paused_task_handled")
	logger.Info(ctx, "Job paused task handled")

	return nil
}

// handleJobCancelledEvent processes job cancelled events by cancelling
// all tasks associated with the job.
// It publishes a TaskCancelledEvent and a TaskJobMetricEvent for each task.
func (s *ScanOrchestrator) handleJobCancelledEvent(
	ctx context.Context,
	evt events.EventEnvelope,
	ack events.AckFunc,
) error {
	logger := logger.NewLoggerContext(s.logger.With(
		"operation", "handle_job_cancelled_event",
		"event_type", string(evt.Type),
	))
	ctx, span := s.tracer.Start(ctx, "scanner_service.scanning.handle_job_cancelled_event",
		trace.WithAttributes(
			attribute.String("component", "scanner_service"),
			attribute.String("scanner_id", s.scannerID.String()),
			attribute.String("event_type", string(evt.Type)),
		))
	defer span.End()
	defer ack(nil)

	span.AddEvent("starting_job_cancelled_task")

	jobCancelledEvt, ok := evt.Payload.(scanning.JobCancelledEvent)
	if !ok {
		err := fmt.Errorf("invalid job cancelled event payload: %T", evt.Payload)
		span.SetStatus(codes.Error, err.Error())
		span.RecordError(err)
		return err
	}
	logger.Add("job_id", jobCancelledEvt.JobID)
	logger.Info(ctx, "Handling job cancelled task")

	jobID := uuid.MustParse(jobCancelledEvt.JobID)
	span.SetAttributes(attribute.String("job_id", jobID.String()))

	taskIDs := s.jobStateController.CancelJob(jobID)
	// TODO: Should we send individual task cancelled events or bulk?
	for _, taskID := range taskIDs {
		if err := s.domainPublisher.PublishDomainEvent(
			ctx,
			scanning.NewTaskCancelledEvent(jobID, taskID, "system"),
			events.WithKey(taskID.String()),
		); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "failed to publish task cancelled event")
			return fmt.Errorf("failed to publish task cancelled event: %w", err)
		}
		span.AddEvent("task_cancelled_event_published", trace.WithAttributes(
			attribute.String("task_id", taskID.String()),
		))

		if err := s.domainPublisher.PublishDomainEvent(
			ctx,
			scanning.NewTaskJobMetricEvent(jobID, taskID, scanning.TaskStatusCancelled),
			events.WithKey(jobID.String()),
		); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "failed to publish task job metric event")
			return fmt.Errorf("failed to publish task job metric task cancelled event: %w", err)
		}
		span.AddEvent("task_job_metric_event_published")
	}
	span.AddEvent("job_tasks_cancelled", trace.WithAttributes(
		attribute.Int("task_count", len(taskIDs)),
	))
	span.SetStatus(codes.Ok, "job_tasks_cancelled")
	logger.Info(ctx, "Job tasks cancelled")

	return nil
}

// workerLoop processes scan tasks until shutdown is signaled. It manages a single worker's lifecycle,
// handling task processing and recovery from panics. Each worker operates independently to maximize
// throughput while maintaining ordered task processing within its own queue.
//
// The worker will automatically restart after a panic with a small delay, ensuring service resilience.
// It gracefully handles shutdown signals from both context cancellation and service stop channel.
// TODO: Add mechanism to consume from mutlple tasks with different priorities.
// We need this in the event of a worker panicking, as we need to consume from the higher priority
// resume task queue. This avoids having an in-progress task stuck behind other not started tasks.
func (s *ScanOrchestrator) workerLoop(ctx context.Context, workerID int) {
	workerLogger := logger.NewLoggerContext(s.logger.With(
		"worker_id", workerID,
		"worker_type", "scanner",
		"operation", "worker_loop",
	))
	workerLogger.Info(ctx, "Worker starting up")

	for {
		func() {
			defer func() {
				// Recover from panics to prevent worker termination. This ensures service stability
				// by containing failures to individual tasks rather than bringing down the worker.
				if r := recover(); r != nil {
					rctx, rspan := s.tracer.Start(ctx, "scanner_service.worker.panic",
						trace.WithAttributes(attribute.Int("worker_id", workerID)),
					)
					defer rspan.End()

					err := fmt.Errorf("worker panic: %v", r)
					workerLogger.Error(rctx, "Worker recovered from panic",
						"panic", r,
					)
					rspan.RecordError(err)
					rspan.SetStatus(codes.Error, "worker panic")
				}
			}()

			s.doWorkerLoop(ctx, workerID, workerLogger)
		}()

		select {
		case <-ctx.Done():
			workerLogger.Info(ctx, "Worker stopped - context cancelled")
			return
		case <-s.stopCh:
			workerLogger.Info(ctx, "Worker stopped - service shutdown")
			return
		case <-time.After(1 * time.Second): // Delay restart to prevent tight loop on persistent panics
		}
	}
}

// doWorkerLoop handles the core task processing loop for a worker. It continuously pulls tasks
// from the shared task channel and processes them with proper context management and tracing.
// The loop continues until context cancellation signals shutdown.
func (s *ScanOrchestrator) doWorkerLoop(ctx context.Context, workerID int, workerLogger *logger.LoggerContext) {
	for {
		select {
		case <-ctx.Done():
			return
		case task := <-s.taskEvent:
			taskCtx, taskSpan := s.tracer.Start(ctx, "scanner_service.worker.process_task",
				trace.WithAttributes(
					attribute.Int("worker_id", workerID),
					attribute.String("task_id", task.TaskID.String()),
					attribute.String("resource_uri", task.ResourceURI),
				))

			// Note: We have this check while consuming from taskEvent because it
			// is possible the job was paused after the task was enqueued but before
			// it was consumed.
			if s.jobStateController.ShouldRejectTask(task.JobID) {
				taskSpan.SetStatus(codes.Error, "job paused")
				taskSpan.RecordError(fmt.Errorf("job paused"))
				taskSpan.End()
				continue
			}

			taskCtx, cancel := context.WithCancelCause(taskCtx)
			s.jobStateController.AddTask(task.JobID, task.TaskID, cancel)

			workerLogger.Add(
				"task_id", task.TaskID,
				"job_id", task.JobID,
				"resource_uri", task.ResourceURI,
				"operation", "do_worker_loop",
			)

			err := s.handleScanTask(taskCtx, task, workerLogger)
			if err != nil {
				taskSpan.RecordError(err)
				taskSpan.SetStatus(codes.Error, "failed to handle scan task")
				workerLogger.Error(taskCtx, "Failed to handle scan task",
					"worker_id", workerID,
					"task_id", task.TaskID,
					"error", err)
			}
			taskSpan.End()

			cancel(nil)
			s.jobStateController.RemoveTask(task.JobID, task.TaskID)
		}
	}
}

// handleScanTask executes an individual scanning task.
// TODO: tracking progress (|TaskProgressedEvent|)
func (s *ScanOrchestrator) handleScanTask(ctx context.Context, req *dtos.ScanRequest, logger *logger.LoggerContext) error {
	logger.Add("operation", "handle_scan_task")
	ctx, span := s.tracer.Start(ctx, "scanner_service.scanning.handle_scan_task",
		trace.WithAttributes(
			attribute.String("component", "scanner_service"),
			attribute.String("resource_uri", req.ResourceURI),
			attribute.String("task_id", req.TaskID.String()),
			attribute.String("job_id", req.JobID.String()),
			attribute.String("scanner_id", s.scannerID.String()),
		))
	defer span.End()

	logger.Info(ctx, "Handling scan task")
	span.AddEvent("starting_scan")

	// Create a copy of the scanner ID to ensure it's not affected by external changes
	startedEvt := scanning.NewTaskStartedEvent(req.JobID, req.TaskID, s.scannerID, req.ResourceURI)
	if err := s.domainPublisher.PublishDomainEvent(ctx, startedEvt, events.WithKey(req.TaskID.String())); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to publish task started event")
		return fmt.Errorf("failed to publish task started event: %w", err)
	}
	if err := s.domainPublisher.PublishDomainEvent(
		ctx,
		scanning.NewTaskJobMetricEvent(req.JobID, req.TaskID, domain.TaskStatusPending),
		events.WithKey(req.JobID.String()),
	); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to publish task job metric event")
		return fmt.Errorf("failed to publish task job metric task pending event: %w", err)
	}

	logger.Info(ctx, "Task started event published; executing scan task")
	span.AddEvent("task_started_event_published")

	return s.executeScanTask(ctx, req, logger)
}

// executeScanTask handles the core scanning logic for both new and resumed tasks
func (s *ScanOrchestrator) executeScanTask(ctx context.Context, req *dtos.ScanRequest, logger *logger.LoggerContext) error {
	logger.Add("operation", "execute_scan_task")
	ctx, span := s.tracer.Start(ctx, "scanner_service.scanning.execute_scan_task",
		trace.WithAttributes(
			attribute.String("component", "scanner_service"),
			attribute.String("resource_uri", req.ResourceURI),
			attribute.String("task_id", req.TaskID.String()),
			attribute.String("job_id", req.JobID.String()),
			attribute.String("scanner_id", s.scannerID.String()),
		))
	defer span.End()

	err := s.metrics.TrackTask(ctx, func() error {
		if err := s.domainPublisher.PublishDomainEvent(
			ctx,
			scanning.NewTaskJobMetricEvent(req.JobID, req.TaskID, domain.TaskStatusInProgress),
			events.WithKey(req.JobID.String()),
		); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "failed to publish task job metric event")
			return fmt.Errorf("failed to publish task job metric task in progress event: %w", err)
		}

		logger.Info(ctx, "Task job metric event published; scanning task")
		streamResult := s.secretScanner.Scan(ctx, req, s.progressReporter)
		span.AddEvent("streaming_scan_started")

		return s.consumeStream(ctx, req.TaskID, streamResult)
	})

	// Only fail the task if it's not a context cancellation error.
	// This allows the task to be handled by staleness detection and get resumed.
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to track task")

		if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			failEvt := scanning.NewTaskFailedEvent(req.JobID, req.TaskID, err.Error())
			if err := s.domainPublisher.PublishDomainEvent(
				ctx,
				failEvt,
				events.WithKey(req.TaskID.String()),
			); err != nil {
				span.RecordError(err)
				span.SetStatus(codes.Error, "failed to publish task failed event")
				return fmt.Errorf("failed to publish task failed event: %w", err)
			}
			if err := s.domainPublisher.PublishDomainEvent(
				ctx,
				scanning.NewTaskJobMetricEvent(req.JobID, req.TaskID, domain.TaskStatusFailed),
				events.WithKey(req.JobID.String()),
			); err != nil {
				span.RecordError(err)
				span.SetStatus(codes.Error, "failed to publish task job metric event")
				return fmt.Errorf("failed to publish task job metric task failed event: %w", err)
			}
			span.AddEvent("task_failed_event_published")
			return fmt.Errorf("failed to track task: %w", err)
		}

		logger.Info(ctx, "Scan cancelled - will be handled by staleness detection", "error", err)
		span.AddEvent("scan_context_cancelled")

		return nil
	}

	completedEvt := scanning.NewTaskCompletedEvent(req.JobID, req.TaskID)
	if err := s.domainPublisher.PublishDomainEvent(
		ctx,
		completedEvt,
		events.WithKey(req.TaskID.String()),
	); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to publish task completed event")
		return fmt.Errorf("failed to publish task completed event: %w", err)
	}
	if err := s.domainPublisher.PublishDomainEvent(
		ctx,
		scanning.NewTaskJobMetricEvent(req.JobID, req.TaskID, domain.TaskStatusCompleted),
		events.WithKey(req.JobID.String()),
	); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to publish task job metric event")
		return fmt.Errorf("failed to publish task job metric task completed event: %w", err)
	}

	span.AddEvent("task_completed_event_published")
	span.SetStatus(codes.Ok, "task completed")
	logger.Info(ctx, "Scan completed successfully")

	return nil
}

func (s *ScanOrchestrator) consumeStream(
	ctx context.Context,
	taskID uuid.UUID,
	sr StreamResult,
) error {
	heartbeatChan := sr.HeartbeatChan
	findingsChan := sr.FindingsChan
	errChan := sr.ErrChan

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case _, ok := <-heartbeatChan:
			if !ok {
				heartbeatChan = nil
			} else {
				// Publish the heartbeat event for this task.
				evt := scanning.NewTaskHeartbeatEvent(taskID)
				if pErr := s.domainPublisher.PublishDomainEvent(
					ctx,
					evt,
					events.WithKey(taskID.String()),
				); pErr != nil {
					s.logger.Error(ctx, "failed to publish heartbeat event", "err", pErr)
				}
			}

		case f, ok := <-findingsChan:
			if !ok {
				findingsChan = nil
			} else {
				s.logger.Info(ctx, "Got finding", "task_id", taskID, "finding", f)
				// TODO: Publish...
			}

		case scanErr, ok := <-errChan:
			if !ok {
				// Channel closed => success.
				return nil
			}
			// We have an actual error => scanning failed.
			// But if it's context cancellation, pass it through.
			if errors.Is(scanErr, context.Canceled) || errors.Is(scanErr, context.DeadlineExceeded) {
				return scanErr
			}
			return fmt.Errorf("scan error: %w", scanErr)
		}

		if heartbeatChan == nil && findingsChan == nil {
			select {
			case scanErr, ok := <-errChan:
				if !ok {
					return nil // success
				}
				// Same context cancellation check here
				if errors.Is(scanErr, context.Canceled) || errors.Is(scanErr, context.DeadlineExceeded) {
					return scanErr
				}
				return fmt.Errorf("scan error: %w", scanErr)
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
}
