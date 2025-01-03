package enumeration

import (
	"context"

	"github.com/ahrav/gitleaks-armada/pkg/config"
	"github.com/ahrav/gitleaks-armada/pkg/domain"
)

// TargetEnumerator generates scan tasks by enumerating a data source.
// Implementations handle source-specific pagination and checkpointing.
type TargetEnumerator interface {
	// Enumerate walks through a data source to generate scan tasks.
	// It uses the enumeration state for context and checkpoint data,
	// and streams tasks through taskCh.
	Enumerate(ctx context.Context, state *EnumerationState, taskCh chan<- []domain.Task) error
}

// EnumeratorFactory is a factory for creating TargetEnumerators.
type EnumeratorFactory interface {
	CreateEnumerator(target config.TargetSpec, auth map[string]config.AuthConfig) (TargetEnumerator, error)
}
