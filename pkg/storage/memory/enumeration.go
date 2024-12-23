package memory

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/ahrav/gitleaks-armada/pkg/storage"
)

// EnumerationStateStorage provides a thread-safe in-memory implementation
// of EnumerationStateStorage for testing and development.
type EnumerationStateStorage struct {
	mu              sync.Mutex
	state           *storage.EnumerationState
	checkpointStore storage.CheckpointStorage
}

// NewEnumerationStateStorage creates an empty in-memory state storage.
func NewEnumerationStateStorage(checkpointStore storage.CheckpointStorage) *EnumerationStateStorage {
	return &EnumerationStateStorage{
		checkpointStore: checkpointStore,
	}
}

// Save stores the provided state as the current active enumeration session.
// Any existing state is overwritten. If the state contains a checkpoint,
// it will be saved first to maintain referential integrity.
func (s *EnumerationStateStorage) Save(ctx context.Context, state *storage.EnumerationState) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	state.LastUpdated = time.Now()

	// Save checkpoint first if it exists.
	if state.LastCheckpoint != nil {
		if err := s.checkpointStore.Save(ctx, state.LastCheckpoint); err != nil {
			return err
		}
	}

	// Deep copy the state to prevent external modifications.
	s.state = &storage.EnumerationState{
		SessionID:      state.SessionID,
		SourceType:     state.SourceType,
		Config:         append(json.RawMessage(nil), state.Config...),
		LastUpdated:    state.LastUpdated,
		Status:         state.Status,
		LastCheckpoint: state.LastCheckpoint,
	}

	return nil
}

// Load retrieves the current active enumeration session state.
// Returns nil if no state exists to prevent operating on invalid state.
func (s *EnumerationStateStorage) Load(ctx context.Context) (*storage.EnumerationState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state == nil {
		return nil, nil
	}

	// Deep copy the state to prevent external modifications.
	copy := &storage.EnumerationState{
		SessionID:   s.state.SessionID,
		SourceType:  s.state.SourceType,
		Config:      append(json.RawMessage(nil), s.state.Config...),
		LastUpdated: s.state.LastUpdated,
		Status:      s.state.Status,
	}

	// Lazy load checkpoint if it exists.
	if s.state.LastCheckpoint != nil {
		checkpoint, err := s.checkpointStore.LoadByID(ctx, s.state.LastCheckpoint.ID)
		if err != nil {
			return nil, err
		}
		copy.LastCheckpoint = checkpoint
	}

	return copy, nil
}
