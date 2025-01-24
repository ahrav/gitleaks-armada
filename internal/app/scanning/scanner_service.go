// Package scanning provides services for coordinating and executing secret scanning operations.
package scanning

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/app/scanning/acl"
	"github.com/ahrav/gitleaks-armada/internal/app/scanning/dtos"
	"github.com/ahrav/gitleaks-armada/internal/domain/enumeration"
	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/domain/rules"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
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

// ScannerService coordinates the execution of secret scanning tasks across multiple workers.
// It subscribes to enumeration events and distributes scanning work to maintain optimal
// resource utilization.
type ScannerService struct {
	id string

	eventBus         events.EventBus
	domainPublisher  events.DomainEventPublisher
	progressReporter ProgressReporter

	secretScanner SecretScanner
	enumACL       acl.EnumerationACL

	ruleProvider RuleProvider // TODO: Figure out where this should live

	workers         int
	stopCh          chan struct{}
	workerWg        sync.WaitGroup
	taskEvent       chan *dtos.ScanRequest
	highPrioritySem chan struct{}

	logger  *logger.Logger
	metrics metrics
	tracer  trace.Tracer
}

// NewScannerService creates a new scanner service with the specified dependencies.
// It configures worker pools based on available CPU cores to optimize scanning throughput.
func NewScannerService(
	id string,
	eb events.EventBus,
	dp events.DomainEventPublisher,
	pr ProgressReporter,
	scanner SecretScanner,
	logger *logger.Logger,
	metrics metrics,
	tracer trace.Tracer,
) *ScannerService {
	// Try to get rule provider if scanner supports it. (e.g. Gitleaks)
	ruleProvider, _ := scanner.(RuleProvider)
	return &ScannerService{
		id:               id,
		eventBus:         eb,
		domainPublisher:  dp,
		secretScanner:    scanner,
		progressReporter: pr,
		ruleProvider:     ruleProvider,
		enumACL:          acl.EnumerationACL{},
		logger:           logger,
		metrics:          metrics,
		tracer:           tracer,
		workers:          runtime.NumCPU(),
		stopCh:           make(chan struct{}),
		taskEvent:        make(chan *dtos.ScanRequest, 1),
		highPrioritySem:  make(chan struct{}, runtime.NumCPU()/2),
	}
}

// Run starts the scanner service and its worker pool. It subscribes to task events
// and coordinates scanning operations until the context is cancelled.
func (s *ScannerService) Run(ctx context.Context) error {
	// Create a shorter-lived span just for initialization.
	// This is because Run is a long-running operation and we don't want to
	// create a span for the entire operation.
	initCtx, initSpan := s.tracer.Start(ctx, "scanner_service.scanning.init",
		trace.WithAttributes(
			attribute.String("component", "scanner_service"),
			attribute.String("scanner_id", s.id),
			attribute.Int("num_workers", s.workers),
		))

	s.logger.Info(initCtx, "Starting scanner service", "id", s.id, "workers", s.workers)

	initSpan.AddEvent("starting_workers")
	s.workerWg.Add(s.workers)
	for i := 0; i < s.workers; i++ {
		go func(workerID int) {
			defer s.workerWg.Done()
			s.workerLoop(ctx, workerID)
		}(i)
	}
	s.metrics.SetActiveWorkers(initCtx, s.workers)

	err := s.eventBus.Subscribe(
		initCtx,
		[]events.EventType{
			enumeration.EventTypeTaskCreated,
			scanning.EventTypeTaskResume,
			rules.EventTypeRulesRequested,
		},
		s.handleEvent,
	)
	if err != nil {
		initSpan.RecordError(err)
		initSpan.SetStatus(codes.Error, "failed to subscribe to events")
		initSpan.End()
		return fmt.Errorf("scanner[%s]: failed to subscribe: %w", s.id, err)
	}
	initSpan.AddEvent("subscribed_to_events")
	initSpan.End()

	<-initCtx.Done()
	s.logger.Info(initCtx, "Scanner service stopping", "id", s.id)

	_, shutdownSpan := s.tracer.Start(initCtx, "scanner_service.scanning.shutdown")
	defer shutdownSpan.End()

	shutdownSpan.AddEvent("initiating_shutdown")
	close(s.stopCh)
	close(s.taskEvent)
	s.workerWg.Wait()
	shutdownSpan.AddEvent("shutdown_complete")

	return initCtx.Err()
}

// handleEvent routes events to appropriate handlers.
// TODO: Replace this with an events facilitator.
func (s *ScannerService) handleEvent(ctx context.Context, evt events.EventEnvelope) error {
	switch evt.Type {
	case enumeration.EventTypeTaskCreated:
		return s.handleTaskEvent(ctx, evt)
	case rules.EventTypeRulesRequested:
		return s.handleRuleRequest(ctx, evt)
	default:
		return fmt.Errorf("unknown event type: %s", evt.Type)
	}
}

// handleRuleRequest processes rule request events and publishes current rules
func (s *ScannerService) handleRuleRequest(ctx context.Context, evt events.EventEnvelope) error {
	ctx, span := s.tracer.Start(ctx, "scanner_service.scanning.handle_rule_request",
		trace.WithAttributes(
			attribute.String("component", "scanner_service"),
			attribute.String("scanner_id", s.id),
			attribute.String("event_type", string(evt.Type)),
		))
	defer span.End()

	// Get rule channel from the scanner if it supports them.
	ruleChan, err := s.ruleProvider.GetRules(ctx)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to get rules from scanner")
		return fmt.Errorf("failed to get rules: %w", err)
	}

	ruleCount := 0
	for rule := range ruleChan {
		err := s.domainPublisher.PublishDomainEvent(
			ctx,
			rules.NewRuleUpdatedEvent(rule),
			events.WithKey(rule.Hash),
		)
		if err != nil {
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

	span.AddEvent("rules_published")
	return nil
}

// handleTaskEvent processes incoming task events and routes them to available workers.
// It ensures graceful handling of shutdown scenarios to prevent task loss.
func (s *ScannerService) handleTaskEvent(ctx context.Context, evt events.EventEnvelope) error {
	ctx, span := s.tracer.Start(ctx, "scanner_service.scanning.handle_task_event",
		trace.WithSpanKind(trace.SpanKindConsumer),
		trace.WithAttributes(
			attribute.String("component", "scanner_service"),
			attribute.String("event_type", string(evt.Type)),
		))
	defer span.End()

	tce, ok := evt.Payload.(enumeration.TaskCreatedEvent)
	if !ok {
		span.SetStatus(codes.Error, "invalid event payload type")
		return fmt.Errorf("expected TaskCreatedEvent, got %T", evt.Payload)
	}

	span.SetAttributes(
		attribute.String("task_id", tce.Task.ID.String()),
		attribute.String("resource_uri", tce.Task.ResourceURI()),
		attribute.String("source_type", string(tce.Task.SourceType)),
		attribute.String("session_id", tce.Task.SessionID().String()),
	)
	span.AddEvent("routing_task")

	select {
	case s.taskEvent <- s.enumACL.ToScanRequest(&tce):
		span.AddEvent("task_routed")
		return nil
	case <-ctx.Done():
		span.SetStatus(codes.Error, "context cancelled")
		return ctx.Err()
	case <-s.stopCh:
		span.SetStatus(codes.Error, "service stopping")
		return fmt.Errorf("scanner[%s]: stopping", s.id)
	}
}

// handleTaskResumeEvent spawns a goroutine for high-priority tasks:
func (s *ScannerService) handleTaskResumeEvent(ctx context.Context, evt events.EventEnvelope) error {
	ctx, span := s.tracer.Start(ctx, "scanner_service.scanning.handle_task_resume_event",
		trace.WithAttributes(
			attribute.String("component", "scanner_service"),
			attribute.String("event_type", string(evt.Type)),
		))
	defer span.End()

	span.AddEvent("starting_resume_task")

	rEvt, ok := evt.Payload.(scanning.TaskResumeEvent)
	if !ok {
		return fmt.Errorf("invalid resume event payload: %T", evt.Payload)
	}

	_ = &dtos.ScanRequest{
		TaskID: rEvt.TaskID,
		JobID:  rEvt.JobID,
		// ResourceURI: rEvt.Task.ResourceURI(),
		Metadata: make(map[string]string),
	}

	s.highPrioritySem <- struct{}{}
	go func() {
		defer func() { <-s.highPrioritySem }()

		// err := s.processResumeTask(ctx, rEvt.TaskID, rEvt.Checkpoint)
		// if err != nil {
		// 	// fail event
		// }
	}()
	span.AddEvent("resume_task_spawned")
	span.SetStatus(codes.Ok, "resume_task_spawned")

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
func (s *ScannerService) workerLoop(ctx context.Context, workerID int) {
	s.logger.Info(ctx, "Starting scanner worker", "worker_id", workerID)

	for {
		func() {
			defer func() {
				// Recover from panics to prevent worker termination. This ensures service stability
				// by containing failures to individual tasks rather than bringing down the worker.
				if r := recover(); r != nil {
					rctx, rspan := s.tracer.Start(ctx,
						"scanner_service.worker.panic",
						trace.WithAttributes(
							attribute.Int("worker_id", workerID),
						),
					)
					defer rspan.End()

					err := fmt.Errorf("worker panic: %v", r)
					s.logger.Error(rctx, "Worker panic",
						"worker_id", workerID, "panic", r)
					rspan.RecordError(err)
					rspan.SetStatus(codes.Error, "worker panic")
				}
			}()

			s.logger.Info(ctx, "Worker starting", "worker_id", workerID)
			s.doWorkerLoop(ctx, workerID)
		}()

		select {
		case <-ctx.Done():
			s.logger.Info(ctx, "Worker stopping", "worker_id", workerID)
			return
		case <-s.stopCh:
			s.logger.Info(ctx, "Worker stopping", "worker_id", workerID)
			return
		case <-time.After(1 * time.Second): // Delay restart to prevent tight loop on persistent panics
		}
	}
}

// doWorkerLoop handles the core task processing loop for a worker. It continuously pulls tasks
// from the shared task channel and processes them with proper context management and tracing.
// The loop continues until context cancellation signals shutdown.
func (s *ScannerService) doWorkerLoop(ctx context.Context, workerID int) {
	for {
		select {
		case <-ctx.Done():
			return
		case task := <-s.taskEvent:
			taskCtx, cancel := context.WithCancelCause(ctx)
			taskCtx, taskSpan := s.tracer.Start(taskCtx, "scanner_service.worker.process_task",
				trace.WithAttributes(
					attribute.Int("worker_id", workerID),
					attribute.String("task_id", task.TaskID.String()),
					attribute.String("resource_uri", task.ResourceURI),
				))

			err := s.handleScanTask(taskCtx, task)
			if err != nil {
				taskSpan.RecordError(err)
				taskSpan.SetStatus(codes.Error, "failed to handle scan task")
				s.logger.Error(taskCtx, "Failed to handle scan task",
					"worker_id", workerID,
					"task_id", task.TaskID,
					"error", err)
			}
			taskSpan.End()
			cancel(nil)
		}
	}
}

// handleScanTask executes an individual scanning task.
// TODO: tracking progress (|TaskProgressedEvent|)
func (s *ScannerService) handleScanTask(ctx context.Context, req *dtos.ScanRequest) error {
	ctx, span := s.tracer.Start(ctx, "scanner_service.scanning.handle_scan_task",
		trace.WithAttributes(
			attribute.String("component", "scanner_service"),
			attribute.String("resource_uri", req.ResourceURI),
			attribute.String("task_id", req.TaskID.String()),
			attribute.String("job_id", req.JobID.String()),
		))
	defer span.End()

	s.logger.Info(ctx, "Handling scan task", "resource_uri", req.ResourceURI)
	span.AddEvent("starting_scan")

	startedEvt := scanning.NewTaskStartedEvent(req.JobID, req.TaskID)
	if err := s.domainPublisher.PublishDomainEvent(ctx, startedEvt); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to publish task started event")
		return fmt.Errorf("failed to publish task started event: %w", err)
	}
	span.AddEvent("task_started_event_published")

	err := s.metrics.TrackTask(ctx, func() error {
		streamResult := s.secretScanner.Scan(ctx, req, s.progressReporter)
		span.AddEvent("streaming_scan_started")

		return s.consumeStream(ctx, req.TaskID, streamResult)
	})
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to track task")

		failEvt := scanning.NewTaskFailedEvent(req.JobID, req.TaskID, err.Error())
		if err := s.domainPublisher.PublishDomainEvent(ctx, failEvt); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "failed to publish task failed event")
			return fmt.Errorf("failed to publish task failed event: %w", err)
		}
		span.AddEvent("task_failed_event_published")

		return fmt.Errorf("failed to track task: %w", err)
	}

	completedEvt := scanning.NewTaskCompletedEvent(req.JobID, req.TaskID)
	if err := s.domainPublisher.PublishDomainEvent(ctx, completedEvt); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to publish task completed event")
		return fmt.Errorf("failed to publish task completed event: %w", err)
	}
	span.AddEvent("task_completed_event_published")
	span.SetStatus(codes.Ok, "task completed")

	return nil
}

func (s *ScannerService) consumeStream(
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
			// context canceled => stop.
			return ctx.Err()

		case _, ok := <-heartbeatChan:
			if !ok {
				heartbeatChan = nil
			} else {
				// Publish the heartbeat event for this task.
				evt := scanning.NewTaskHeartbeatEvent(taskID)
				if pErr := s.domainPublisher.PublishDomainEvent(ctx, evt); pErr != nil {
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
			// Typically, the scan is finished when this channel returns an error or closes.
			if !ok {
				// Channel closed => success.
				return nil
			}
			// We have an actual error => scanning failed.
			return scanErr
		}

		// Optionally, if both heartbeatChan and findingsChan are nil (i.e. closed),
		// we can check if we’re just waiting on errChan to close for success.
		if heartbeatChan == nil && findingsChan == nil {
			// If the scanner is done streaming both heartbeats and findings,
			// we only need to see if errChan is also closed or yields an error
			select {
			case scanErr, ok := <-errChan:
				if !ok {
					return nil // success
				}
				return scanErr
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
}
