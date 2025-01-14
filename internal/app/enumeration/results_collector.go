package enumeration

import (
	"context"

	"github.com/google/uuid"
)

// targetEnumerationResults collects and manages scan target IDs discovered during enumeration.
type targetEnumerationResults struct {
	targetIDs []uuid.UUID
	callback  ScanTargetCallback
}

// newEnumerationResults creates a new results collector with the specified callback.
func newEnumerationResults(callback ScanTargetCallback) *targetEnumerationResults {
	return &targetEnumerationResults{targetIDs: make([]uuid.UUID, 0), callback: callback}
}

// AddTargets safely adds new target IDs and notifies the callback.
func (r *targetEnumerationResults) AddTargets(ctx context.Context, ids []uuid.UUID) {
	if len(ids) == 0 {
		return
	}

	r.targetIDs = append(r.targetIDs, ids...)
	if r.callback != nil {
		r.callback.OnScanTargetsDiscovered(ctx, ids)
	}
}
