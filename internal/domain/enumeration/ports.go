// Package enumeration provides domain types and interfaces for scanning target enumeration.
// It enables reliable, resumable scanning of large data sources by managing enumeration
// state, checkpoints, and task generation.
package enumeration

import (
	"context"

	"github.com/ahrav/gitleaks-armada/internal/domain/task"
	"github.com/ahrav/gitleaks-armada/pkg/config"
)

// Service defines the core domain operations for target enumeration.
// It coordinates the overall scanning process by managing enumeration state
// and supporting resumable scans.
type Service interface {
	// ExecuteEnumeration performs target enumeration by either resuming from
	// existing state or starting fresh. It handles the full enumeration lifecycle
	// including state management and task generation.
	ExecuteEnumeration(ctx context.Context) error
}

// TargetEnumerator generates scan tasks by walking through a data source.
// Implementations handle source-specific details like pagination and state tracking
// to enable reliable scanning of different target types.
type TargetEnumerator interface {
	// Enumerate walks through a data source to generate scan tasks.
	// It uses enumeration state for context and checkpoint data,
	// streaming generated tasks through the provided channel.
	Enumerate(ctx context.Context, state *EnumerationState, taskCh chan<- []task.Task) error
}

// EnumeratorFactory creates TargetEnumerators for different data sources.
// It encapsulates the logic for instantiating appropriate enumerators based on
// target configuration and authentication details.
type EnumeratorFactory interface {
	// CreateEnumerator constructs a new TargetEnumerator for the given target
	// specification and authentication configuration.
	CreateEnumerator(target config.TargetSpec, auth map[string]config.AuthConfig) (TargetEnumerator, error)
}

// EnumerationStateRepository provides persistent storage for enumeration session state.
// This enables resumable scanning across process restarts by maintaining the lifecycle
// state and progress of enumeration sessions.
type EnumerationStateRepository interface {
	// Save persists the current state of an enumeration session.
	Save(ctx context.Context, state *EnumerationState) error

	// Load retrieves an enumeration session state by session ID.
	// Returns nil if no matching session exists.
	Load(ctx context.Context, sessionID string) (*EnumerationState, error)

	// GetActiveStates returns all enumeration states that are initialized or in progress.
	// This enables monitoring and management of ongoing enumeration sessions.
	GetActiveStates(ctx context.Context) ([]*EnumerationState, error)

	// List returns the most recent enumeration states, limited by count.
	// This supports historical tracking and analysis of enumeration sessions.
	List(ctx context.Context, limit int) ([]*EnumerationState, error)
}

// CheckpointRepository provides persistent storage for enumeration checkpoints.
// It enables resumable scanning by maintaining progress markers that allow
// enumeration to continue from the last successful position.
type CheckpointRepository interface {
	// Save persists a checkpoint for later retrieval.
	Save(ctx context.Context, checkpoint *Checkpoint) error

	// Load retrieves the most recent checkpoint for a target.
	Load(ctx context.Context, targetID string) (*Checkpoint, error)

	// LoadByID retrieves a checkpoint by its unique identifier.
	LoadByID(ctx context.Context, id int64) (*Checkpoint, error)

	// Delete removes a checkpoint for the given target.
	// It is not an error if the checkpoint does not exist.
	Delete(ctx context.Context, targetID string) error
}
