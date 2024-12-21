// Package scanner provides functionality for processing and scanning repository tasks
// for sensitive information.
package scanner

import (
	"context"
	"log"

	"github.com/ahrav/gitleaks-armada/pkg/messaging"
	"github.com/ahrav/gitleaks-armada/pkg/metrics"
)

// Scanner processes repository scanning tasks received from a message broker.
// It tracks metrics about task processing and handles the scanning of repositories.
type Scanner struct {
	broker  messaging.Broker
	metrics metrics.ScannerMetrics
}

// NewScanner creates a Scanner instance that will process tasks from the provided broker
// and record metrics about task processing.
func NewScanner(broker messaging.Broker, metrics metrics.ScannerMetrics) *Scanner {
	return &Scanner{
		broker:  broker,
		metrics: metrics,
	}
}

// Run starts the scanner and processes tasks until the context is cancelled.
func (s *Scanner) Run(ctx context.Context) error {
	log.Println("Starting scanner...")
	return s.broker.SubscribeTasks(ctx, s.handleScanTask)
}

// handleScanTask processes a single scan task.
func (s *Scanner) handleScanTask(task messaging.Task) error {
	log.Printf("Scanning task: %s", task.ResourceURI)
	s.metrics.IncTasksDequeued()
	return s.metrics.TrackTask(func() error {
		// TODO: Implement actual scanning logic
		return nil
	})
}
