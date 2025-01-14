package shared

import (
	"context"

	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
)

// TargetEnumerator provides application-level target enumeration capabilities.
// It differs from the domain interface by operating on batches and managing cursors
// directly to support efficient streaming of large datasets.
type TargetEnumerator interface {
	// Enumerate walks through a data source and streams batches of scan tasks.
	// It accepts a cursor to support resumable operations and sends batches through
	// the provided channel. Each batch includes both tasks and checkpoint data.
	Enumerate(
		ctx context.Context,
		startCursor *string,
		batchCh chan<- EnumerateBatch,
	) error
}

// TargetInfo represents a scannable target with its associated metadata.
// It provides the minimal information needed to create a scan task while
// keeping the enumeration layer decoupled from domain specifics.
type TargetInfo struct {
	// TargetType identifies the type of target being scanned (e.g., "github_repo").
	TargetType shared.TargetType

	// ResourceURI is the unique location identifier for the target.
	ResourceURI string

	// Metadata contains additional context needed for scanning the target.
	Metadata map[string]string
}

// EnumerateBatch groups related scan tasks with their checkpoint data.
// This enables atomic processing of task batches while maintaining
// resumability through checkpoint tracking.
type EnumerateBatch struct {
	Targets    []*TargetInfo
	NextCursor string
}
