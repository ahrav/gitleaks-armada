package memory

import (
	"context"
	"sync"
	"time"

	"github.com/ahrav/gitleaks-armada/pkg/storage"
)

// InMemoryCheckpointStorage provides a thread-safe in-memory implementation
// of CheckpointStorage for testing and development.
type InMemoryCheckpointStorage struct {
	mu          sync.Mutex
	checkpoints map[string]*storage.Checkpoint
}

// NewInMemoryCheckpointStorage creates an empty in-memory checkpoint store.
func NewInMemoryCheckpointStorage() *InMemoryCheckpointStorage {
	return &InMemoryCheckpointStorage{
		checkpoints: make(map[string]*storage.Checkpoint),
	}
}

func (cs *InMemoryCheckpointStorage) Save(ctx context.Context, checkpoint *storage.Checkpoint) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	checkpoint.UpdatedAt = time.Now()
	cs.checkpoints[checkpoint.TargetID] = checkpoint
	return nil
}

func (cs *InMemoryCheckpointStorage) Load(ctx context.Context, targetID string) (*storage.Checkpoint, error) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	cp, ok := cs.checkpoints[targetID]
	if !ok {
		return nil, nil
	}

	// This needs to be a deep copy to prevent mutation of stored checkpoint.
	copy := &storage.Checkpoint{
		ID:        cp.ID,
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

func (cs *InMemoryCheckpointStorage) LoadByID(ctx context.Context, id int64) (*storage.Checkpoint, error) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	for _, cp := range cs.checkpoints {
		if cp.ID == id {
			return &storage.Checkpoint{
				ID:        cp.ID,
				TargetID:  cp.TargetID,
				Data:      deepCopyMap(cp.Data),
				UpdatedAt: cp.UpdatedAt,
			}, nil
		}
	}
	return nil, nil
}
