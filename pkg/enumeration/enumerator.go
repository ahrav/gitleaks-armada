package enumeration

import (
	"context"

	"github.com/ahrav/gitleaks-armada/pkg/events/types"

	"github.com/ahrav/gitleaks-armada/pkg/storage"
)

// TargetEnumerator generates scan tasks by enumerating a data source.
// Implementations handle source-specific pagination and checkpointing.
type TargetEnumerator interface {
	// Enumerate walks through a data source to generate scan tasks.
	// It uses the enumeration state for context and checkpoint data,
	// and streams tasks through taskCh.
	Enumerate(ctx context.Context, state *storage.EnumerationState, taskCh chan<- []types.Task) error
}
