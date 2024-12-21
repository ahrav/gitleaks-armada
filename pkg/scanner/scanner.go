// Package scanner provides functionality for processing and scanning repository tasks
// for sensitive information.
package scanner

import (
	"context"
	"log"

	"github.com/ahrav/gitleaks-armada/pkg/metrics"
	"github.com/ahrav/gitleaks-armada/pkg/orchestration"
)

// Scanner processes repository scanning tasks received from a message broker.
// It tracks metrics about task processing and handles the scanning of repositories.
type Scanner struct {
	broker  orchestration.Broker
	metrics metrics.ScannerMetrics
}

// NewScanner creates a Scanner instance that will process tasks from the provided broker
// and record metrics about task processing.
func NewScanner(broker orchestration.Broker, metrics metrics.ScannerMetrics) *Scanner {
	return &Scanner{
		broker:  broker,
		metrics: metrics,
	}
}

// ProcessTasks subscribes to tasks from the broker and processes them.
// It tracks metrics for each task and runs until the context is cancelled.
func (s *Scanner) ProcessTasks(ctx context.Context) error {
	return s.broker.SubscribeTasks(ctx, func(task orchestration.Task) error {
		s.metrics.IncTasksDequeued()
		return s.metrics.TrackTask(func() error {
			return s.handleScanTask(task)
		})
	})
}

func (s *Scanner) handleScanTask(task orchestration.Task) error {
	// TODO: Implement scanning logic
	log.Printf("Scanning task: %s", task.ResourceURI)
	return nil
}
