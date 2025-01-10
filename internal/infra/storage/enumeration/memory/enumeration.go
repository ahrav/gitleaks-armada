package memory

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/ahrav/gitleaks-armada/internal/domain/enumeration"
)

// EnumerationStateStorage provides an in-memory implementation of EnumerationStateStorage
// for testing and development.
type EnumerationStateStorage struct {
	mu              sync.Mutex
	states          map[string]*enumeration.SessionState // Keyed by session ID
	checkpointStore enumeration.CheckpointRepository
}

// NewEnumerationStateStorage creates a new in-memory enumeration state storage.
func NewEnumerationStateStorage(checkpointStore enumeration.CheckpointRepository) *EnumerationStateStorage {
	return &EnumerationStateStorage{
		states:          make(map[string]*enumeration.SessionState),
		checkpointStore: checkpointStore,
	}
}

// Save persists the enumeration state and its associated checkpoint.
func (s *EnumerationStateStorage) Save(ctx context.Context, state *enumeration.SessionState) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if state.LastCheckpoint() != nil {
		if err := s.checkpointStore.Save(ctx, state.LastCheckpoint()); err != nil {
			return fmt.Errorf("failed to save checkpoint: %w", err)
		}
	}

	s.states[state.SessionID().String()] = enumeration.ReconstructState(
		state.SessionID(),
		state.SourceType(),
		state.Config(),
		state.Status(),
		enumeration.ReconstructTimeline(
			state.Timeline().StartedAt(),
			state.Timeline().CompletedAt(),
			state.Timeline().LastUpdate(),
		),
		state.FailureReason(),
		deepCopyCheckpoint(state.LastCheckpoint()),
		enumeration.ReconstructSessionMetrics(
			state.Metrics().TotalBatches(),
			state.Metrics().FailedBatches(),
			state.Metrics().ItemsFound(),
			state.Metrics().ItemsProcessed(),
		),
	)

	return nil
}

// Load retrieves an enumeration session state by session ID.
func (s *EnumerationStateStorage) Load(ctx context.Context, sessionID string) (*enumeration.SessionState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	state, exists := s.states[sessionID]
	if !exists {
		return nil, nil
	}

	return enumeration.ReconstructState(
		state.SessionID(),
		state.SourceType(),
		state.Config(),
		state.Status(),
		enumeration.ReconstructTimeline(
			state.Timeline().StartedAt(),
			state.Timeline().CompletedAt(),
			state.Timeline().LastUpdate(),
		),
		state.FailureReason(),
		deepCopyCheckpoint(state.LastCheckpoint()),
		enumeration.ReconstructSessionMetrics(
			state.Metrics().TotalBatches(),
			state.Metrics().FailedBatches(),
			state.Metrics().ItemsFound(),
			state.Metrics().ItemsProcessed(),
		),
	), nil
}

// GetActiveStates returns all enumeration states that are initialized or in progress
func (s *EnumerationStateStorage) GetActiveStates(ctx context.Context) ([]*enumeration.SessionState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var active []*enumeration.SessionState
	for _, state := range s.states {
		if state.Status() == enumeration.StatusInitialized || state.Status() == enumeration.StatusInProgress {
			active = append(active, enumeration.ReconstructState(
				state.SessionID(),
				state.SourceType(),
				state.Config(),
				state.Status(),
				enumeration.ReconstructTimeline(
					state.Timeline().StartedAt(),
					state.Timeline().CompletedAt(),
					state.Timeline().LastUpdate(),
				),
				state.FailureReason(),
				deepCopyCheckpoint(state.LastCheckpoint()),
				enumeration.ReconstructSessionMetrics(
					state.Metrics().TotalBatches(),
					state.Metrics().FailedBatches(),
					state.Metrics().ItemsFound(),
					state.Metrics().ItemsProcessed(),
				),
			))
		}
	}
	return active, nil
}

// List returns the most recent enumeration states, limited by count.
func (s *EnumerationStateStorage) List(ctx context.Context, limit int) ([]*enumeration.SessionState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	states := make([]*enumeration.SessionState, 0, len(s.states))
	for _, state := range s.states {
		states = append(states, enumeration.ReconstructState(
			state.SessionID(),
			state.SourceType(),
			state.Config(),
			state.Status(),
			enumeration.ReconstructTimeline(
				state.Timeline().StartedAt(),
				state.Timeline().CompletedAt(),
				state.Timeline().LastUpdate(),
			),
			state.FailureReason(),
			deepCopyCheckpoint(state.LastCheckpoint()),
			enumeration.ReconstructSessionMetrics(
				state.Metrics().TotalBatches(),
				state.Metrics().FailedBatches(),
				state.Metrics().ItemsFound(),
				state.Metrics().ItemsProcessed(),
			),
		))
	}

	sort.Slice(states, func(i, j int) bool {
		return states[i].Timeline().LastUpdate().After(states[j].Timeline().LastUpdate())
	})

	if limit > len(states) {
		limit = len(states)
	}
	return states[:limit], nil
}

// Helper function to deep copy a checkpoint.
func deepCopyCheckpoint(cp *enumeration.Checkpoint) *enumeration.Checkpoint {
	if cp == nil {
		return nil
	}
	return enumeration.NewCheckpoint(cp.ID(), cp.TargetID(), deepCopyMap(cp.Data()))
}
