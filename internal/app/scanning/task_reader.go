package scanning

import (
	"context"

	"github.com/google/uuid"

	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
)

// TaskStateReader provides read-only access to task state.
// This interface is used by monitoring components that need
// to verify task state without modifying it.
type TaskStateReader interface {
	// GetTask retrieves the current state of a task.
	// Returns nil and an error if the task doesn't exist
	// or cannot be retrieved.
	GetTask(ctx context.Context, taskID uuid.UUID) (*scanning.Task, error)
}
