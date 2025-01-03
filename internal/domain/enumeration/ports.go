package enumeration

import (
	"context"

	"github.com/ahrav/gitleaks-armada/internal/domain/task"
	"github.com/ahrav/gitleaks-armada/pkg/config"
)

// TargetEnumerator generates scan tasks by enumerating a data source.
// Implementations handle source-specific pagination and checkpointing.
type TargetEnumerator interface {
	// Enumerate walks through a data source to generate scan tasks.
	// It uses the enumeration state for context and checkpoint data,
	// and streams tasks through taskCh.
	Enumerate(ctx context.Context, state *EnumerationState, taskCh chan<- []task.Task) error
}

// EnumeratorFactory is a factory for creating TargetEnumerators.
type EnumeratorFactory interface {
	CreateEnumerator(target config.TargetSpec, auth map[string]config.AuthConfig) (TargetEnumerator, error)
}

// EnumerationStateStorage provides persistent storage for enumeration session state.
// This enables resumable scanning across process restarts.
type EnumerationStateStorage interface {
	Save(ctx context.Context, state *EnumerationState) error
	// Load retrieves an enumeration session state by session ID.
	// Returns nil if no matching session exists.
	Load(ctx context.Context, sessionID string) (*EnumerationState, error)
	// GetActiveStates returns all enumeration states that are initialized or in progress
	GetActiveStates(ctx context.Context) ([]*EnumerationState, error)
	// List returns the most recent enumeration states, limited by count
	List(ctx context.Context, limit int) ([]*EnumerationState, error)
}

// CheckpointStorage provides persistent storage for enumeration checkpoints.
// Implementations allow saving and retrieving checkpoint state to enable
// resumable scanning across process restarts.
type CheckpointStorage interface {
	// Save persists a checkpoint for later retrieval.
	Save(ctx context.Context, checkpoint *Checkpoint) error

	// Load by target ID (for business logic)
	Load(ctx context.Context, targetID string) (*Checkpoint, error)

	// LoadByID loads a checkpoint by its database ID.
	LoadByID(ctx context.Context, id int64) (*Checkpoint, error)

	// Delete removes a checkpoint for the given target.
	// It is not an error if the checkpoint does not exist.
	Delete(ctx context.Context, targetID string) error
}

// Service provides the core domain logic for target enumeration. It handles
// scanning targets, managing enumeration state, and coordinating the overall
// enumeration process. The service supports resuming partial scans and
// re-scanning targets when needed.
type Service interface {
	// ExecuteEnumeration performs target enumeration by either resuming from
	// existing states or starting fresh enumerations from configuration.
	// It returns an error if the enumeration process fails.
	ExecuteEnumeration(ctx context.Context) error
}
