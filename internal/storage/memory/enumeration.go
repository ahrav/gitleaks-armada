package memory

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"

	"github.com/ahrav/gitleaks-armada/pkg/storage"
)

// EnumerationStateStorage provides an in-memory implementation of EnumerationStateStorage
// for testing and development.
type EnumerationStateStorage struct {
	mu              sync.Mutex
	states          map[string]*storage.EnumerationState // Keyed by session ID
	checkpointStore storage.CheckpointStorage
}

// NewEnumerationStateStorage creates a new in-memory enumeration state storage.
func NewEnumerationStateStorage(checkpointStore storage.CheckpointStorage) *EnumerationStateStorage {
	return &EnumerationStateStorage{
		states:          make(map[string]*storage.EnumerationState),
		checkpointStore: checkpointStore,
	}
}

// Save persists the enumeration state and its associated checkpoint.
func (s *EnumerationStateStorage) Save(ctx context.Context, state *storage.EnumerationState) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if state.LastCheckpoint != nil {
		if err := s.checkpointStore.Save(ctx, state.LastCheckpoint); err != nil {
			return fmt.Errorf("failed to save checkpoint: %w", err)
		}
	}

	// Store a deep copy to prevent mutations
	s.states[state.SessionID] = &storage.EnumerationState{
		SessionID:      state.SessionID,
		SourceType:     state.SourceType,
		Config:         append(json.RawMessage(nil), state.Config...),
		LastUpdated:    state.LastUpdated,
		Status:         state.Status,
		LastCheckpoint: deepCopyCheckpoint(state.LastCheckpoint),
	}

	return nil
}

// Load retrieves an enumeration session state by session ID.
func (s *EnumerationStateStorage) Load(ctx context.Context, sessionID string) (*storage.EnumerationState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	state, exists := s.states[sessionID]
	if !exists {
		return nil, nil
	}

	// Return a deep copy to prevent mutations
	return &storage.EnumerationState{
		SessionID:      state.SessionID,
		SourceType:     state.SourceType,
		Config:         append(json.RawMessage(nil), state.Config...),
		LastUpdated:    state.LastUpdated,
		Status:         state.Status,
		LastCheckpoint: deepCopyCheckpoint(state.LastCheckpoint),
	}, nil
}

// GetActiveStates returns all enumeration states that are initialized or in progress
func (s *EnumerationStateStorage) GetActiveStates(ctx context.Context) ([]*storage.EnumerationState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var active []*storage.EnumerationState
	for _, state := range s.states {
		if state.Status == storage.StatusInitialized || state.Status == storage.StatusInProgress {
			active = append(active, &storage.EnumerationState{
				SessionID:      state.SessionID,
				SourceType:     state.SourceType,
				Config:         append(json.RawMessage(nil), state.Config...),
				LastUpdated:    state.LastUpdated,
				Status:         state.Status,
				LastCheckpoint: deepCopyCheckpoint(state.LastCheckpoint),
			})
		}
	}
	return active, nil
}

// List returns the most recent enumeration states, limited by count
func (s *EnumerationStateStorage) List(ctx context.Context, limit int) ([]*storage.EnumerationState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Convert map to slice for sorting
	states := make([]*storage.EnumerationState, 0, len(s.states))
	for _, state := range s.states {
		states = append(states, &storage.EnumerationState{
			SessionID:      state.SessionID,
			SourceType:     state.SourceType,
			Config:         append(json.RawMessage(nil), state.Config...),
			LastUpdated:    state.LastUpdated,
			Status:         state.Status,
			LastCheckpoint: deepCopyCheckpoint(state.LastCheckpoint),
		})
	}

	// Sort by LastUpdated descending
	sort.Slice(states, func(i, j int) bool {
		return states[i].LastUpdated.After(states[j].LastUpdated)
	})

	if limit > len(states) {
		limit = len(states)
	}
	return states[:limit], nil
}

// Helper function to deep copy a checkpoint
func deepCopyCheckpoint(cp *storage.Checkpoint) *storage.Checkpoint {
	if cp == nil {
		return nil
	}
	return &storage.Checkpoint{
		ID:        cp.ID,
		TargetID:  cp.TargetID,
		Data:      deepCopyMap(cp.Data),
		UpdatedAt: cp.UpdatedAt,
	}
}
