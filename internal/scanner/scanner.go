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
	"github.com/ahrav/gitleaks-armada/internal/domain/task"
	"github.com/ahrav/gitleaks-armada/internal/scanner/metrics"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

// Scanner processes repository scanning tasks received from a message broker.
// It manages a pool of workers to concurrently scan repositories for sensitive information
// while tracking metrics about task processing performance.
type Scanner struct {
	id string

	broker         events.EventBus
	eventPublisher events.DomainEventPublisher
	metrics        metrics.ScannerMetrics
	scanner        *GitLeaksScanner
	workers        int

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

	taskCh := make(chan task.Task, 1)

	s.workerWg.Add(s.workers)
	for i := 0; i < s.workers; i++ {
		go func(workerID int) {
			defer s.workerWg.Done()
			s.worker(ctx, workerID, taskCh)
		}(i)
	}

	// Set up the subscription to feed tasks to workers.
	if err := s.broker.Subscribe(ctx, []events.EventType{enumeration.EventTypeTaskCreated}, func(ctx context.Context, evt events.DomainEvent) error {
		select {
		case taskCh <- evt.Payload.(task.Task):
			return nil
		case <-ctx.Done():
			return ctx.Err()
		case <-s.stopCh:
			return fmt.Errorf("scanner[%s]: stopping", s.id)
		}
	}); err != nil {
		close(taskCh)
		s.workerWg.Wait()
		return fmt.Errorf("scanner[%s]: failed to subscribe to tasks: %w", s.id, err)
	}

	<-ctx.Done()
	s.logger.Info(ctx, "Context cancelled, stopping scanner", "scanner_id", s.id)

	close(s.stopCh)
	close(taskCh)
	s.workerWg.Wait()
	return ctx.Err()
}

// worker processes tasks from the task channel until it's closed or context is cancelled.
func (s *Scanner) worker(ctx context.Context, id int, taskCh <-chan task.Task) {
	s.logger.Info(ctx, "Worker started", "scanner_id", s.id, "worker_id", id)
	for {
		select {
		case task, ok := <-taskCh:
			if !ok {
				s.logger.Info(ctx, "Worker shutting down", "scanner_id", s.id, "worker_id", id, "reason", "task_channel_closed")
				return
			}
			if err := s.handleScanTask(ctx, task); err != nil {
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

// handleScanTask processes a single repository scan task.
// It updates metrics for task processing and delegates the actual scanning
// to the configured scanner implementation.
func (s *Scanner) handleScanTask(ctx context.Context, task task.Task) error {
	s.logger.Info(ctx, "Scanning repository", "scanner_id", s.id, "resource_uri", task.ResourceURI)

	// Start a new span for the entire task processing
	ctx, span := s.tracer.Start(ctx, "process_scan_task",
		trace.WithAttributes(
			attribute.String("task.id", task.TaskID),
			attribute.String("resource.uri", task.ResourceURI),
		))
	defer span.End()

	return s.metrics.TrackTask(func() error {
		if err := s.scanner.Scan(ctx, task.ResourceURI); err != nil {
			span.RecordError(err)
			return err
		}
		return nil
	})
}
