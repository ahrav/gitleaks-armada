// Package enumeration provides domain types and interfaces for target enumeration.
// It defines core abstractions for discovering and enumerating scan targets from
// different data sources (e.g. GitHub, S3). The package enables reliable, resumable
// scanning by managing enumeration state, checkpoints, and task generation.
// The enumeration process coordinates the overall scanning lifecycle by managing
// state transitions, supporting resumable operations, and generating scan tasks
// that get published to the event bus for processing.
package enumeration

import (
	"context"

	"github.com/ahrav/gitleaks-armada/internal/domain/task"
)

// TargetEnumerator generates scan tasks by walking through a data source.
// Implementations handle source-specific details like pagination and state tracking
// to enable reliable scanning of different target types.
type TargetEnumerator interface {
	// Enumerate walks through a data source to generate scan tasks.
	// It uses enumeration state for context and checkpoint data,
	// streaming generated tasks through the provided channel.
	Enumerate(ctx context.Context, state *State, taskCh chan<- []task.Task) error
}

// EnumerationStateRepository provides persistent storage for enumeration session state.
// This enables resumable scanning across process restarts by maintaining the lifecycle
// state and progress of enumeration sessions.
type EnumerationStateRepository interface {
	// Save persists the current state of an enumeration session.
	Save(ctx context.Context, state *State) error

	// Load retrieves an enumeration session state by session ID.
	// Returns nil if no matching session exists.
	Load(ctx context.Context, sessionID string) (*State, error)

	// GetActiveStates returns all enumeration states that are initialized or in progress.
	// This enables monitoring and management of ongoing enumeration sessions.
	GetActiveStates(ctx context.Context) ([]*State, error)

	// List returns the most recent enumeration states, limited by count.
	// This supports historical tracking and analysis of enumeration sessions.
	List(ctx context.Context, limit int) ([]*State, error)
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
