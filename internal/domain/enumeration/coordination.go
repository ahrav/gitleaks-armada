package enumeration

import (
	"context"

	"github.com/ahrav/gitleaks-armada/pkg/common/uuid"
)

// EnumerationResult represents the outcome of an enumeration operation
// and streams the results back to the caller.
type EnumerationResult struct {
	ScanTargetsCh <-chan []uuid.UUID // Stream of discovered scan target IDs
	TasksCh       <-chan *Task       // Stream of created tasks
	ErrCh         <-chan error       // Stream of errors
}

// Coordinator orchestrates the discovery and enumeration of scan targets across different
// source types. It manages the lifecycle of enumeration sessions to ensure reliable and
// resumable target discovery, which is critical for handling large-scale scanning operations
// that may be interrupted.
type Coordinator interface {
	// EnumerateTarget initiates target discovery for a new scanning session. It processes
	// the provided target specification and authentication configuration to discover and
	// enumerate scannable resources. The operation streams discovered targets and tasks
	// through channels to enable concurrent processing.
	//
	// Returns three channels:
	// - A channel of target IDs for discovered scannable resources
	// - A channel of enumeration tasks that need to be processed
	// - An error channel for reporting any issues during enumeration
	EnumerateTarget(
		ctx context.Context,
		target TargetSpec,
	) EnumerationResult

	// ResumeTarget restarts an interrupted enumeration session from its last saved state.
	// This enables fault tolerance by allowing long-running enumerations to recover from
	// failures without losing progress. The operation continues streaming newly discovered
	// targets and tasks from the last checkpoint.
	//
	// Returns three channels:
	// - A channel of target IDs for newly discovered resources
	// - A channel of enumeration tasks that need to be processed
	// - An error channel for reporting any issues during resumption
	// ResumeTarget(
	// 	ctx context.Context,
	// 	state *SessionState,
	// ) EnumerationResult
}
