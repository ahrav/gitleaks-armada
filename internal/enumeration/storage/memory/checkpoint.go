package memory

import (
	"context"
	"sync"

	"github.com/ahrav/gitleaks-armada/internal/domain/enumeration"
)

// CheckpointStorage provides a thread-safe in-memory implementation
// of CheckpointStorage for testing and development.
type CheckpointStorage struct {
	mu          sync.Mutex
	checkpoints map[string]*enumeration.Checkpoint
}

// NewCheckpointStorage creates an empty in-memory checkpoint store.
func NewCheckpointStorage() *CheckpointStorage {
	return &CheckpointStorage{checkpoints: make(map[string]*enumeration.Checkpoint)}
}

func (cs *CheckpointStorage) Save(ctx context.Context, checkpoint *enumeration.Checkpoint) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	cs.checkpoints[checkpoint.TargetID()] = checkpoint
	return nil
}

func (cs *CheckpointStorage) Load(ctx context.Context, targetID string) (*enumeration.Checkpoint, error) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	cp, ok := cs.checkpoints[targetID]
	if !ok {
		return nil, nil
	}

	// This needs to be a deep copy to prevent mutation of stored checkpoint.
	copy := enumeration.NewCheckpoint(cp.ID(), cp.TargetID(), deepCopyMap(cp.Data()))

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

func (cs *CheckpointStorage) Delete(ctx context.Context, targetID string) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	delete(cs.checkpoints, targetID)
	return nil
}

func (cs *CheckpointStorage) LoadByID(ctx context.Context, id int64) (*enumeration.Checkpoint, error) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	for _, cp := range cs.checkpoints {
		if cp.ID() == id {
			return enumeration.NewCheckpoint(cp.ID(), cp.TargetID(), deepCopyMap(cp.Data())), nil
		}
	}
	return nil, nil
}
