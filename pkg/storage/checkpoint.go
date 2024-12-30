package storage

import (
	"context"
	"time"
)

// Checkpoint stores progress information for resumable target enumeration.
// It enables reliable scanning of large data sources by tracking the last
// successfully processed position.
type Checkpoint struct {
	ID        int64          `json:"id"`
	TargetID  string         `json:"target_id"`
	Data      map[string]any `json:"data"`
	UpdatedAt time.Time      `json:"updated_at"`
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
