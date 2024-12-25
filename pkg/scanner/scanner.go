// Package scanner provides functionality for processing and scanning repository tasks
// for sensitive information.
package scanner

import (
	"context"
	"fmt"
	"log"
	"runtime"
	"sync"

	"github.com/ahrav/gitleaks-armada/pkg/messaging"
	"github.com/ahrav/gitleaks-armada/pkg/metrics"
)

// Scanner processes repository scanning tasks received from a message broker.
// It manages a pool of workers to concurrently scan repositories for sensitive information
// while tracking metrics about task processing performance.
type Scanner struct {
	broker  messaging.Broker
	metrics metrics.ScannerMetrics
	scanner *GitLeaksScanner
	workers int

	stopCh   chan struct{}
	workerWg sync.WaitGroup
}

// NewScanner creates a Scanner that will process tasks from the provided broker.
// It configures the scanner to use the system's CPU count for worker concurrency
// and initializes metrics collection.
func NewScanner(ctx context.Context, broker messaging.Broker, metrics metrics.ScannerMetrics) *Scanner {
	return &Scanner{
		broker:  broker,
		metrics: metrics,
		scanner: NewGitLeaksScanner(ctx, broker),
		workers: runtime.NumCPU(),
	}
}

// Run starts the scanner with a pool of workers to process tasks concurrently.
func (s *Scanner) Run(ctx context.Context) error {
	s.stopCh = make(chan struct{})
	log.Printf("Starting scanner with %d workers...", s.workers)

	taskCh := make(chan messaging.Task, 1)

	s.workerWg.Add(s.workers)
	for i := 0; i < s.workers; i++ {
		go func(workerID int) {
			defer s.workerWg.Done()
			s.worker(ctx, workerID, taskCh)
		}(i)
	}

	// Set up the subscription to feed tasks to workers.
	if err := s.broker.SubscribeTasks(ctx, func(task messaging.Task) error {
		select {
		case taskCh <- task:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		case <-s.stopCh:
			return fmt.Errorf("scanner stopping")
		}
	}); err != nil {
		close(taskCh)
		s.workerWg.Wait()
		return fmt.Errorf("failed to subscribe to tasks: %w", err)
	}

	<-ctx.Done()

	close(s.stopCh)
	close(taskCh)
	s.workerWg.Wait()
	return ctx.Err()
}

// worker processes tasks from the task channel until it's closed or context is cancelled.
func (s *Scanner) worker(ctx context.Context, id int, taskCh <-chan messaging.Task) {
	log.Printf("Worker %d started", id)
	for {
		select {
		case task, ok := <-taskCh:
			if !ok {
				log.Printf("Worker %d shutting down: task channel closed", id)
				return
			}
			if err := s.handleScanTask(ctx, task); err != nil {
				log.Printf("Worker %d failed to process task: %v", id, err)
			}
		case <-ctx.Done():
			log.Printf("Worker %d shutting down: context cancelled", id)
			return
		case <-s.stopCh:
			log.Printf("Worker %d shutting down: stop signal received", id)
			return
		}
	}
}

// handleScanTask processes a single repository scan task.
// It updates metrics for task processing and delegates the actual scanning
// to the configured scanner implementation.
func (s *Scanner) handleScanTask(ctx context.Context, task messaging.Task) error {
	log.Printf("Scanning repository: %s", task.ResourceURI)
	s.metrics.IncTasksDequeued()

	return s.metrics.TrackTask(func() error {
		return s.scanner.Scan(ctx, task.ResourceURI)
	})
}
