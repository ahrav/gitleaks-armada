package cluster

import "context"

// Coordinator manages leader election to ensure only one instance actively coordinates work.
type Coordinator interface {
	// Start initiates coordination and blocks until context cancellation or error.
	Start(ctx context.Context) error
	// Stop gracefully terminates coordination.
	Stop() error
	// OnLeadershipChange registers a callback for leadership status changes.
	OnLeadershipChange(cb func(isLeader bool))
}
