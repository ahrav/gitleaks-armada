package scanning

import (
	"context"

	"github.com/ahrav/gitleaks-armada/internal/app/scanning/dtos"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
)

// ProgressReporter enables scanners to communicate their progress during long-running scans.
// This feedback mechanism helps track scan status, detect stalled operations, and provide
// visibility into the scanning process. Progress updates flow through the system to update
// task state and inform interested subscribers.
type ProgressReporter interface {
	// ReportProgress updates the system with the current state of a scan operation.
	// The provided Progress contains metrics and state information that help track
	// the scan's execution and enable recovery in case of failures.
	// Returns an error if the progress report fails.
	ReportProgress(ctx context.Context, progress scanning.Progress) error

	// ReportPausedProgress updates the system with the current state of a paused scan operation.
	// The provided Progress contains metrics and state information that help track
	// the scan's execution and enable recovery in case of failures.
	// Returns an error if the progress report fails.
	ReportPausedProgress(ctx context.Context, progress scanning.Progress) error
}

// StreamResult encapsulates the streaming channels used for real-time scan feedback.
// This streaming approach enables:
// 1. Immediate visibility into scan progress via heartbeats, crucial for monitoring long-running scans
// 2. Real-time secret detection through the findings channel, allowing rapid response to critical findings
// 3. Asynchronous error handling that doesn't block the main scanning process
// The channel-based design supports non-blocking operations and clean cancellation patterns.
type StreamResult struct {
	// HeartbeatChan emits periodic signals to indicate the scan is still active,
	// helping detect stalled or hung operations
	HeartbeatChan <-chan struct{}

	// FindingsChan streams discovered secrets as they're found, enabling
	// immediate action on critical findings rather than waiting for scan completion
	FindingsChan <-chan Finding

	// ErrChan communicates scan completion status - either an error on failure
	// or closure on success, providing clean error handling semantics
	ErrChan <-chan error
}

// Finding represents a detected secret or sensitive information.
// TODO: Implement finding details including context, severity, and location
type Finding struct{}

// SecretScanner defines the core scanning capability for detecting secrets in source code.
// This interface is designed around the Command pattern, encapsulating the scanning logic
// while providing a consistent contract for the application layer. The streaming-first
// approach enables:
// - Real-time monitoring and feedback of scan progress
// - Graceful handling of long-running scans
// - Clean cancellation patterns via context
// - Flexible integration with different scanning engines
type SecretScanner interface {
	// Scan initiates a secret detection scan on the provided resource.
	// It returns a StreamResult containing channels for real-time monitoring
	// rather than waiting for full completion, enabling responsive feedback
	// and early warning of potential issues.
	//
	// The ProgressReporter allows tracking scan progress for monitoring
	// and recovery purposes.
	Scan(ctx context.Context, task *dtos.ScanRequest, reporter ProgressReporter) StreamResult
}
