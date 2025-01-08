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
	taskRepo scanning.TaskRepository,
	logger *logger.Logger,
	metrics metrics,
	tracer trace.Tracer,
) *ScannerService {
	return &ScannerService{
		id:              id,
		eventBus:        eb,
		domainPublisher: dp,
		secretScanner:   secretScanner,
		taskRepo:        taskRepo,
		enumACL:         acl.EnumerationACL{},
		logger:          logger,
		metrics:         metrics,
		tracer:          tracer,
		workers:         runtime.NumCPU(),
		stopCh:          make(chan struct{}),
		taskEvent:       make(chan *dtos.ScanRequest, 1),
	}
}

// Run starts the scanner service and its worker pool. It subscribes to task events
// and coordinates scanning operations until the context is cancelled.
func (s *ScannerService) Run(ctx context.Context) error {
	ctx, span := s.tracer.Start(ctx, "scanner_service.scanning.run",
		trace.WithAttributes(
			attribute.String("component", "scanner_service"),
			attribute.String("scanner_id", s.id),
			attribute.Int("num_workers", s.workers),
		))
	defer span.End()

	s.logger.Info(ctx, "Starting scanner service", "id", s.id, "workers", s.workers)

	span.AddEvent("starting_workers")
	s.workerWg.Add(s.workers)
	for i := 0; i < s.workers; i++ {
		go func(workerID int) {
			defer s.workerWg.Done()
			s.workerLoop(ctx, workerID)
		}(i)
	}

	err := s.eventBus.Subscribe(ctx, []events.EventType{enumeration.EventTypeTaskCreated},
		s.handleTaskEvent)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to subscribe to events")
		return fmt.Errorf("scanner[%s]: failed to subscribe: %w", s.id, err)
	}
	span.AddEvent("subscribed_to_events")

	span.AddEvent("waiting_for_shutdown")
	<-ctx.Done()
	s.logger.Info(ctx, "Scanner service stopping", "id", s.id)

	span.AddEvent("initiating_shutdown")
	close(s.stopCh)
	close(s.taskEvent)
	s.workerWg.Wait()
	span.AddEvent("shutdown_complete")

	return ctx.Err()
}

// handleTaskEvent processes incoming task events and routes them to available workers.
// It ensures graceful handling of shutdown scenarios to prevent task loss.
func (s *ScannerService) handleTaskEvent(ctx context.Context, evt events.EventEnvelope) error {
	ctx, span := s.tracer.Start(ctx, "scanner_service.scanning.handle_task_event",
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

	span.SetAttributes(attribute.String("task_id", tce.Task.TaskID))
	span.AddEvent("routing_task")

	select {
	case s.taskEvent <- s.enumACL.ToScanRequest(tce.Task):
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
	ctx, span := s.tracer.Start(ctx, "scanner_service.scanning.worker_loop",
		trace.WithAttributes(
			attribute.String("component", "scanner_service"),
			attribute.Int("worker_id", workerID),
			attribute.String("scanner_id", s.id),
		))
	defer span.End()

	s.logger.Info(ctx, "Worker started", "scanner_id", s.id, "worker_id", workerID)
	span.AddEvent("worker_started")

	for {
		select {
		case tce, ok := <-s.taskEvent:
			if !ok {
				span.AddEvent("worker_shutdown_channel_closed")
				s.logger.Info(ctx, "Worker shutting down", "worker_id", workerID)
				return
			}
			if err := s.handleScanTask(ctx, tce); err != nil {
				span.RecordError(err)
				s.logger.Error(ctx, "Failed to process task", "error", err)
			}
		case <-ctx.Done():
			span.AddEvent("worker_shutdown_context_cancelled")
			s.logger.Info(ctx, "Worker shutting down (ctx cancelled)", "worker_id", workerID)
			return
		case <-s.stopCh:
			span.AddEvent("worker_shutdown_stop_signal")
			s.logger.Info(ctx, "Worker shutting down (stop signal)", "worker_id", workerID)
			return
		}
	}
}

// handleScanTask executes an individual scanning task.
// TODO: Implement task state management through the repository.
func (s *ScannerService) handleScanTask(ctx context.Context, req *dtos.ScanRequest) error {
	ctx, span := s.tracer.Start(ctx, "scanner_service.scanning.handle_scan_task",
		trace.WithAttributes(
			attribute.String("component", "scanner_service"),
			attribute.String("resource_uri", req.ResourceURI),
		))
	defer span.End()

	s.logger.Info(ctx, "Handling scan task", "resource_uri", req.ResourceURI)
	span.AddEvent("starting_scan")

	return s.metrics.TrackTask(ctx, func() error {
		if err := s.secretScanner.Scan(ctx, req); err != nil {
			span.RecordError(err)
			return err
		}
		span.AddEvent("scan_completed")
		return nil
	})
}
