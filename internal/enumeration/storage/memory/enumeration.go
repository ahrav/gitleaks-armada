package memory

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"

	"github.com/ahrav/gitleaks-armada/internal/domain/enumeration"
)

// EnumerationStateStorage provides an in-memory implementation of EnumerationStateStorage
// for testing and development.
type EnumerationStateStorage struct {
	mu              sync.Mutex
	states          map[string]*enumeration.EnumerationState // Keyed by session ID
	checkpointStore enumeration.CheckpointRepository
}

// NewEnumerationStateStorage creates a new in-memory enumeration state storage.
func NewEnumerationStateStorage(checkpointStore enumeration.CheckpointRepository) *EnumerationStateStorage {
	return &EnumerationStateStorage{
		states:          make(map[string]*enumeration.EnumerationState),
		checkpointStore: checkpointStore,
	}
}

// Save persists the enumeration state and its associated checkpoint.
func (s *EnumerationStateStorage) Save(ctx context.Context, state *enumeration.EnumerationState) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if state.LastCheckpoint != nil {
		if err := s.checkpointStore.Save(ctx, state.LastCheckpoint); err != nil {
			return fmt.Errorf("failed to save checkpoint: %w", err)
		}
	}

	// Store a deep copy to prevent mutations
	s.states[state.SessionID] = &enumeration.EnumerationState{
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
func (s *EnumerationStateStorage) Load(ctx context.Context, sessionID string) (*enumeration.EnumerationState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	state, exists := s.states[sessionID]
	if !exists {
		return nil, nil
	}

	// Return a deep copy to prevent mutations
	return &enumeration.EnumerationState{
		SessionID:      state.SessionID,
		SourceType:     state.SourceType,
		Config:         append(json.RawMessage(nil), state.Config...),
		LastUpdated:    state.LastUpdated,
		Status:         state.Status,
		LastCheckpoint: deepCopyCheckpoint(state.LastCheckpoint),
	}, nil
}

// GetActiveStates returns all enumeration states that are initialized or in progress
func (s *EnumerationStateStorage) GetActiveStates(ctx context.Context) ([]*enumeration.EnumerationState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var active []*enumeration.EnumerationState
	for _, state := range s.states {
		if state.Status == enumeration.StatusInitialized || state.Status == enumeration.StatusInProgress {
			active = append(active, &enumeration.EnumerationState{
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
func (s *EnumerationStateStorage) List(ctx context.Context, limit int) ([]*enumeration.EnumerationState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Convert map to slice for sorting
	states := make([]*enumeration.EnumerationState, 0, len(s.states))
	for _, state := range s.states {
		states = append(states, &enumeration.EnumerationState{
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
func deepCopyCheckpoint(cp *enumeration.Checkpoint) *enumeration.Checkpoint {
	if cp == nil {
		return nil
	}
	return &enumeration.Checkpoint{
		ID:        cp.ID,
		TargetID:  cp.TargetID,
		Data:      deepCopyMap(cp.Data),
		UpdatedAt: cp.UpdatedAt,
	}
}
