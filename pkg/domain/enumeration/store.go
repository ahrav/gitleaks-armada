package enumeration

import "context"

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
