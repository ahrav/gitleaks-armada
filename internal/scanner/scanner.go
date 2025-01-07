// Package scanner provides functionality for processing and scanning repository tasks
// for sensitive information.
package scanner

import (
	"context"
	"fmt"
	"runtime"
	"sync"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/domain/enumeration"
	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/scanner/metrics"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

// Scanner processes repository scanning tasks received from a message broker.
// It manages a pool of workers to concurrently scan repositories for sensitive information
// while tracking metrics about task processing performance.
type Scanner struct {
	id string

	broker  events.EventBus
	metrics metrics.ScannerMetrics
	scanner *GitLeaksScanner
	workers int

	stopCh   chan struct{}
	workerWg sync.WaitGroup

	logger *logger.Logger
	tracer trace.Tracer
}

// NewScanner creates a Scanner that will process tasks from the provided broker.
// It configures the scanner to use the system's CPU count for worker concurrency
// and initializes metrics collection.
func NewScanner(
	ctx context.Context,
	id string,
	broker events.EventBus,
	eventPublisher events.DomainEventPublisher,
	metrics metrics.ScannerMetrics,
	logger *logger.Logger,
	tracer trace.Tracer,
) *Scanner {
	return &Scanner{
		id:      id,
		broker:  broker,
		metrics: metrics,
		scanner: NewGitLeaksScanner(ctx, eventPublisher, logger, tracer),
		workers: runtime.NumCPU(),
		logger:  logger,
		tracer:  tracer,
	}
}

// Run starts the scanner with a pool of workers to process tasks concurrently.
func (s *Scanner) Run(ctx context.Context) error {
	s.stopCh = make(chan struct{})
	s.logger.Info(ctx, "Starting scanner", "scanner_id", s.id, "num_workers", s.workers)

	taskEventCh := make(chan enumeration.TaskCreatedEvent, 1)

	s.workerWg.Add(s.workers)
	for i := 0; i < s.workers; i++ {
		go func(workerID int) {
			defer s.workerWg.Done()
			s.worker(ctx, workerID, taskEventCh)
		}(i)
	}

	if err := s.broker.Subscribe(ctx, []events.EventType{enumeration.EventTypeTaskCreated},
		func(ctx context.Context, evt events.EventEnvelope) error {
			taskEvent, ok := evt.Payload.(enumeration.TaskCreatedEvent)
			if !ok {
				return fmt.Errorf("expected TaskCreatedEvent, got %T", evt.Payload)
			}

			select {
			case taskEventCh <- taskEvent:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			case <-s.stopCh:
				return fmt.Errorf("scanner[%s]: stopping", s.id)
			}
		}); err != nil {
		close(taskEventCh)
		s.workerWg.Wait()
		return fmt.Errorf("scanner[%s]: failed to subscribe to tasks: %w", s.id, err)
	}

	<-ctx.Done()
	s.logger.Info(ctx, "Context cancelled, stopping scanner", "scanner_id", s.id)

	close(s.stopCh)
	close(taskEventCh)
	s.workerWg.Wait()
	return ctx.Err()
}

// worker processes task events
func (s *Scanner) worker(ctx context.Context, id int, taskEventCh <-chan enumeration.TaskCreatedEvent) {
	s.logger.Info(ctx, "Worker started", "scanner_id", s.id, "worker_id", id)
	for {
		select {
		case taskEvent, ok := <-taskEventCh:
			if !ok {
				s.logger.Info(ctx, "Worker shutting down", "scanner_id", s.id, "worker_id", id, "reason", "task_channel_closed")
				return
			}
			if err := s.handleScanTask(ctx, taskEvent); err != nil {
				s.logger.Error(ctx, "Worker failed to process task", "scanner_id", s.id, "worker_id", id, "error", err)
			}
		case <-ctx.Done():
			s.logger.Info(ctx, "Worker shutting down", "scanner_id", s.id, "worker_id", id, "reason", "context_cancelled")
			return
		case <-s.stopCh:
			s.logger.Info(ctx, "Worker shutting down", "scanner_id", s.id, "worker_id", id, "reason", "stop_signal_received")
			return
		}
	}
}

// handleScanTask processes a single task event
func (s *Scanner) handleScanTask(ctx context.Context, evt enumeration.TaskCreatedEvent) error {
	s.logger.Info(ctx, "Scanning repository",
		"scanner_id", s.id,
		"resource_uri", evt.Task.ResourceURI,
		"occurred_at", evt.OccurredAt(),
	)

	ctx, span := s.tracer.Start(ctx, "process_scan_task",
		trace.WithAttributes(
			attribute.String("task.id", evt.Task.TaskID),
			attribute.String("resource.uri", evt.Task.ResourceURI()),
			attribute.String("event.occurred_at", evt.OccurredAt().String()),
		))
	defer span.End()

	return s.metrics.TrackTask(ctx, func() error {
		if err := s.scanner.Scan(ctx, evt.Task.ResourceURI()); err != nil {
			span.RecordError(err)
			return err
		}
		return nil
	})
}
