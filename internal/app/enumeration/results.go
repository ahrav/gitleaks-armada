package enumeration

import (
	"context"
	"sync"

	"github.com/google/uuid"
)

// TargetEnumerationResults collects and manages scan target IDs discovered during enumeration.
// It provides thread-safe operations for adding targets and notifying callbacks.
type TargetEnumerationResults struct {
	mu        sync.Mutex
	targetIDs []uuid.UUID
	callback  ScanTargetCallback
}

// NewEnumerationResults creates a new results collector with the specified callback.
func NewEnumerationResults(callback ScanTargetCallback) *TargetEnumerationResults {
	return &TargetEnumerationResults{targetIDs: make([]uuid.UUID, 0), callback: callback}
}

// AddTargets safely adds new target IDs and notifies the callback.
// This method is thread-safe and can be called from multiple goroutines.
func (r *TargetEnumerationResults) AddTargets(ctx context.Context, ids []uuid.UUID) {
	if len(ids) == 0 {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.targetIDs = append(r.targetIDs, ids...)
	if r.callback != nil {
		r.callback.OnScanTargetsDiscovered(ctx, ids)
	}
}
