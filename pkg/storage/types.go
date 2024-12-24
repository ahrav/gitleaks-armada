package storage

import (
	"context"
	"encoding/json"
	"time"

	"github.com/ahrav/gitleaks-armada/pkg/messaging"
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

// EnumerationStatus represents the lifecycle states of an enumeration session.
type EnumerationStatus string

const (
	// StatusInitialized indicates the session is configured but hasn't started scanning.
	StatusInitialized EnumerationStatus = "initialized"
	// StatusInProgress indicates active scanning and task generation is underway.
	StatusInProgress EnumerationStatus = "in_progress"
	// StatusCompleted indicates all targets were successfully enumerated.
	StatusCompleted EnumerationStatus = "completed"
	// StatusFailed indicates the enumeration encountered an unrecoverable error.
	StatusFailed EnumerationStatus = "failed"
)

// EnumerationState tracks the progress and status of a target enumeration session.
// It maintains configuration, checkpoints, and status to enable resumable scanning
// of large data sources.
type EnumerationState struct {
	SessionID      string            `json:"session_id"`
	SourceType     string            `json:"source_type"`
	Config         json.RawMessage   `json:"config"`
	LastCheckpoint *Checkpoint       `json:"last_checkpoint"`
	LastUpdated    time.Time         `json:"last_updated"`
	Status         EnumerationStatus `json:"status"`
}

// UpdateCheckpoint updates the checkpoint and last updated time.
func (s *EnumerationState) UpdateCheckpoint(checkpoint *Checkpoint) {
	s.LastCheckpoint = checkpoint
	s.LastUpdated = time.Now()
}

// UpdateStatus changes the enumeration status and updates the timestamp.
func (s *EnumerationState) UpdateStatus(status EnumerationStatus) {
	s.Status = status
	s.LastUpdated = time.Now()
}

// TargetEnumerator generates scan tasks by enumerating a data source.
// Implementations handle source-specific pagination and checkpointing.
type TargetEnumerator interface {
	// Enumerate walks through a data source to generate scan tasks.
	// It resumes from the provided checkpoint and streams tasks through taskCh.
	Enumerate(ctx context.Context, checkpoint *Checkpoint, taskCh chan<- []messaging.Task) error
}

// EnumerationStateStorage provides persistent storage for enumeration session state.
// This enables resumable scanning across process restarts.
type EnumerationStateStorage interface {
	Save(ctx context.Context, state *EnumerationState) error
	// Load retrieves the current active enumeration session state.
	// Returns nil if no active session exists.
	Load(ctx context.Context) (*EnumerationState, error)
}
