package controller

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/ahrav/gitleaks-armada/pkg/messaging"
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

// InMemoryEnumerationStateStorage provides a thread-safe in-memory implementation
// of EnumerationStateStorage for testing and development.
type InMemoryEnumerationStateStorage struct {
	mu    sync.Mutex
	state *EnumerationState
}

// NewInMemoryEnumerationStateStorage creates an empty in-memory state storage.
func NewInMemoryEnumerationStateStorage() *InMemoryEnumerationStateStorage {
	return new(InMemoryEnumerationStateStorage)
}

// Save stores the provided state as the current active enumeration session.
// Any existing state is overwritten.
func (s *InMemoryEnumerationStateStorage) Save(ctx context.Context, state *EnumerationState) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	state.LastUpdated = time.Now()

	s.state = state
	return nil
}

// Load retrieves the current active enumeration session state.
// Returns nil if no state exists to prevent operating on invalid state.
func (s *InMemoryEnumerationStateStorage) Load(ctx context.Context) (*EnumerationState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state == nil {
		return nil, nil
	}

	// Return a copy to prevent mutation of internal state.
	copy := *s.state
	return &copy, nil
}
