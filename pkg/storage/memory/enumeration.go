package memory

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/ahrav/gitleaks-armada/pkg/storage"
)

// InMemoryEnumerationStateStorage provides a thread-safe in-memory implementation
// of EnumerationStateStorage for testing and development.
type InMemoryEnumerationStateStorage struct {
	mu    sync.Mutex
	state *storage.EnumerationState
}

// NewInMemoryEnumerationStateStorage creates an empty in-memory state storage.
func NewInMemoryEnumerationStateStorage() *InMemoryEnumerationStateStorage {
	return new(InMemoryEnumerationStateStorage)
}

// Save stores the provided state as the current active enumeration session.
// Any existing state is overwritten.
func (s *InMemoryEnumerationStateStorage) Save(ctx context.Context, state *storage.EnumerationState) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	state.LastUpdated = time.Now()

	s.state = state
	return nil
}

// Load retrieves the current active enumeration session state.
// Returns nil if no state exists to prevent operating on invalid state.
func (s *InMemoryEnumerationStateStorage) Load(ctx context.Context) (*storage.EnumerationState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state == nil {
		return nil, nil
	}

	// We need to make to deep copy the json and the checkpoint (if it exists).
	copy := &storage.EnumerationState{
		SessionID:   s.state.SessionID,
		SourceType:  s.state.SourceType,
		Config:      append(json.RawMessage(nil), s.state.Config...),
		LastUpdated: s.state.LastUpdated,
		Status:      s.state.Status,
	}

	if s.state.LastCheckpoint != nil {
		copy.LastCheckpoint = &storage.Checkpoint{
			TargetID:  s.state.LastCheckpoint.TargetID,
			UpdatedAt: s.state.LastCheckpoint.UpdatedAt,
			Data:      deepCopyMap(s.state.LastCheckpoint.Data),
		}
	}

	return copy, nil
}
