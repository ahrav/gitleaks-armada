package controller

import (
	"context"
	"sync"
	"time"
)

// Checkpoint stores progress information for resumable target enumeration.
// It enables reliable scanning of large data sources by tracking the last
// successfully processed position.
type Checkpoint struct {
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

	// Load retrieves a checkpoint by target ID.
	// Returns nil if no checkpoint exists for the target.
	Load(ctx context.Context, targetID string) (*Checkpoint, error)

	// Delete removes a checkpoint for the given target.
	// It is not an error if the checkpoint does not exist.
	Delete(ctx context.Context, targetID string) error
}

// InMemoryCheckpointStorage provides a thread-safe in-memory implementation
// of CheckpointStorage for testing and development.
type InMemoryCheckpointStorage struct {
	mu          sync.Mutex
	checkpoints map[string]*Checkpoint
}

// NewInMemoryCheckpointStorage creates an empty in-memory checkpoint store.
func NewInMemoryCheckpointStorage() *InMemoryCheckpointStorage {
	return &InMemoryCheckpointStorage{
		checkpoints: make(map[string]*Checkpoint),
	}
}

func (cs *InMemoryCheckpointStorage) Save(ctx context.Context, checkpoint *Checkpoint) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	checkpoint.UpdatedAt = time.Now()
	cs.checkpoints[checkpoint.TargetID] = checkpoint
	return nil
}

func (cs *InMemoryCheckpointStorage) Load(ctx context.Context, targetID string) (*Checkpoint, error) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	cp, ok := cs.checkpoints[targetID]
	if !ok {
		return nil, nil
	}

	// This needs to be a deep copy to prevent mutation of stored checkpoint.
	copy := &Checkpoint{
		TargetID:  cp.TargetID,
		UpdatedAt: cp.UpdatedAt,
		Data:      deepCopyMap(cp.Data),
	}

	return copy, nil
}

func deepCopyMap(m map[string]any) map[string]any {
	copy := make(map[string]any, len(m))
	for k, v := range m {
		switch val := v.(type) {
		case map[string]any:
			copy[k] = deepCopyMap(val)
		case []any:
			copySlice := make([]any, len(val))
			for i, item := range val {
				if mapItem, ok := item.(map[string]any); ok {
					copySlice[i] = deepCopyMap(mapItem)
				} else {
					copySlice[i] = item
				}
			}
			copy[k] = copySlice
		default:
			copy[k] = val
		}
	}
	return copy
}

func (cs *InMemoryCheckpointStorage) Delete(ctx context.Context, targetID string) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	delete(cs.checkpoints, targetID)
	return nil
}
