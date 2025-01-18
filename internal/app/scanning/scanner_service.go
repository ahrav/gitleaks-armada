// Package scanning provides services for coordinating and executing secret scanning operations.
package scanning

import (
	"context"
	"fmt"
	"runtime"
	"sync"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/app/scanning/acl"
	"github.com/ahrav/gitleaks-armada/internal/app/scanning/dtos"
	"github.com/ahrav/gitleaks-armada/internal/domain/enumeration"
	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

// metrics defines the interface for tracking scanning-related metrics.
type metrics interface {
	TrackTask(ctx context.Context, f func() error) error
	SetActiveWorkers(ctx context.Context, count int)
}

// ScannerService coordinates the execution of secret scanning tasks across multiple workers.
// It subscribes to enumeration events and distributes scanning work to maintain optimal
// resource utilization.
type ScannerService struct {
	id              string
	eventBus        events.EventBus
	domainPublisher events.DomainEventPublisher
	secretScanner   SecretScanner
	taskRepo        scanning.TaskRepository
	enumACL         acl.EnumerationACL

	workers   int
	stopCh    chan struct{}
	workerWg  sync.WaitGroup
	taskEvent chan *dtos.ScanRequest

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
	secretScanner SecretScanner,
	// taskRepo scanning.TaskRepository,
	logger *logger.Logger,
	metrics metrics,
	tracer trace.Tracer,
) *ScannerService {
	return &ScannerService{
		id:              id,
		eventBus:        eb,
		domainPublisher: dp,
		secretScanner:   secretScanner,
		// taskRepo:        taskRepo,
		enumACL:   acl.EnumerationACL{},
		logger:    logger,
		metrics:   metrics,
		tracer:    tracer,
		workers:   runtime.NumCPU(),
		stopCh:    make(chan struct{}),
		taskEvent: make(chan *dtos.ScanRequest, 1),
	}
}

// Run starts the scanner service and its worker pool. It subscribes to task events
// and coordinates scanning operations until the context is cancelled.
func (s *ScannerService) Run(ctx context.Context) error {
	// Create a shorter-lived span just for initialization.
	// This is because Run is a long-running operation and we don't want to
	// create a span for the entire operation.
	ctx, initSpan := s.tracer.Start(ctx, "scanner_service.scanning.init",
		trace.WithAttributes(
			attribute.String("component", "scanner_service"),
			attribute.String("scanner_id", s.id),
			attribute.Int("num_workers", s.workers),
		))

	s.logger.Info(ctx, "Starting scanner service", "id", s.id, "workers", s.workers)

	initSpan.AddEvent("starting_workers")
	s.workerWg.Add(s.workers)
	for i := 0; i < s.workers; i++ {
		// Create a new context for each worker that inherits the trace
		workerCtx := trace.ContextWithSpan(ctx, initSpan)
		go func(workerID int) {
			defer s.workerWg.Done()
			s.workerLoop(workerCtx, workerID)
		}(i)
	}
	s.metrics.SetActiveWorkers(ctx, s.workers)

	err := s.eventBus.Subscribe(ctx, []events.EventType{enumeration.EventTypeTaskCreated},
		s.handleTaskEvent)
	if err != nil {
		initSpan.RecordError(err)
		initSpan.SetStatus(codes.Error, "failed to subscribe to events")
		initSpan.End()
		return fmt.Errorf("scanner[%s]: failed to subscribe: %w", s.id, err)
	}
	initSpan.AddEvent("subscribed_to_events")
	initSpan.End()

	<-ctx.Done()
	s.logger.Info(ctx, "Scanner service stopping", "id", s.id)

	_, shutdownSpan := s.tracer.Start(ctx, "scanner_service.scanning.shutdown")
	defer shutdownSpan.End()

	shutdownSpan.AddEvent("initiating_shutdown")
	close(s.stopCh)
	close(s.taskEvent)
	s.workerWg.Wait()
	shutdownSpan.AddEvent("shutdown_complete")

	return ctx.Err()
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

// workerLoop processes scan tasks until shutdown is signaled.
// Each worker operates independently to maximize throughput while maintaining
// ordered task processing within the worker.
func (s *ScannerService) workerLoop(ctx context.Context, workerID int) {
	// No parent span for the loop itself - we'll create spans per operation.
	// This is because the loop is a long-running operation and we don't want to
	// create a span for the entire loop.
	s.logger.Info(ctx, "Starting scanner worker", "worker_id", workerID)

	for {
		select {
		case <-ctx.Done():
			s.logger.Info(ctx, "Worker stopping", "worker_id", workerID)
			return

		case task := <-s.taskEvent:
			taskCtx, span := s.tracer.Start(ctx, "scanner_service.worker.process_task",
				trace.WithAttributes(
					attribute.Int("worker_id", workerID),
					attribute.String("task_id", task.TaskID.String()),
					attribute.String("resource_uri", task.ResourceURI),
				))

			err := s.handleScanTask(taskCtx, task)
			if err != nil {
				span.RecordError(err)
				span.SetStatus(codes.Error, "failed to handle scan task")
				s.logger.Error(taskCtx, "Failed to handle scan task",
					"worker_id", workerID,
					"task_id", task.TaskID,
					"error", err)
			}
			span.End()
		}
	}
}

// handleScanTask executes an individual scanning task.
// TODO: Implement task state management through the repository.
// TODO: Create |TaskStartedEvent| and then begin tracking progress (|TaskProgressedEvent|)
func (s *ScannerService) handleScanTask(ctx context.Context, req *dtos.ScanRequest) error {
	ctx, span := s.tracer.Start(ctx, "scanner_service.scanning.handle_scan_task",
		trace.WithAttributes(
			attribute.String("component", "scanner_service"),
			attribute.String("resource_uri", req.ResourceURI),
		))
	defer span.End()

	s.logger.Info(ctx, "Handling scan task", "resource_uri", req.ResourceURI)
	span.AddEvent("starting_scan")

	startedEvt := scanning.NewTaskStartedEvent(req.JobID, req.TaskID)
	if err := s.domainPublisher.PublishDomainEvent(ctx, startedEvt, events.WithKey(req.TaskID.String())); err != nil {
		return fmt.Errorf("failed to publish task started event: %w", err)
	}

	return s.metrics.TrackTask(ctx, func() error {
		if err := s.secretScanner.Scan(ctx, req); err != nil {
			span.RecordError(err)
			return err
		}
		span.AddEvent("scan_completed")
		return nil
	})
}
