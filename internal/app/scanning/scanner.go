package scanning

import (
	"context"

	"github.com/ahrav/gitleaks-armada/internal/app/scanning/dtos"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
)

// SecretScanner defines the core scanning capability for detecting secrets in source code.
// Implementations of this interface handle the actual scanning logic while abstracting
// the underlying scanning engine details from the rest of the system. This separation
// allows for different scanning implementations while maintaining a consistent interface.
type SecretScanner interface {
	// Scan processes a scan request to detect potential secrets in the specified resource.
	// It returns an error if the scan fails or cannot be completed. The scanning process
	// is expected to emit findings through the configured event system.
	Scan(ctx context.Context, task *dtos.ScanRequest) error
}

// ProgressReporter enables scanners to communicate their progress during long-running scans.
// This feedback mechanism helps track scan status, detect stalled operations, and provide
// visibility into the scanning process. Progress updates flow through the system to update
// task state and inform interested subscribers.
type ProgressReporter interface {
	// ReportProgress updates the system with the current state of a scan operation.
	// The provided Progress contains metrics and state information that help track
	// the scan's execution and enable recovery in case of failures.
	ReportProgress(ctx context.Context, progress scanning.Progress)
}
