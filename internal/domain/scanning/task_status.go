package scanning

import (
	"errors"
	"fmt"
)

// TaskStatus represents the execution state of an individual scan task. It enables
// fine-grained tracking of task progress and error conditions.
type TaskStatus string

// ErrTaskStatusUnknown is returned when a task status is unknown.
var ErrTaskStatusUnknown = errors.New("task status unknown")

const (
	// TaskStatusPending indicates a task is created but not yet started.
	TaskStatusPending TaskStatus = "PENDING"

	// TaskStatusInProgress indicates a task is actively scanning.
	TaskStatusInProgress TaskStatus = "IN_PROGRESS"

	// TaskStatusCompleted indicates a task finished successfully.
	TaskStatusCompleted TaskStatus = "COMPLETED"

	// TaskStatusFailed indicates a task encountered an unrecoverable error.
	TaskStatusFailed TaskStatus = "FAILED"

	// TaskStatusStale indicates a task stopped reporting progress and may need recovery.
	TaskStatusStale TaskStatus = "STALE"

	// TaskStatusPaused indicates a task has been temporarily halted.
	TaskStatusPaused TaskStatus = "PAUSED"

	// TODO: Add retrying, cancelled, timed out.
	// No Paused on the task level. We either let the task finish, or kill it. (tbh)

	// TaskStatusUnspecified is used when a task status is unknown.
	TaskStatusUnspecified TaskStatus = "UNSPECIFIED"
)

// String returns the string representation of the TaskStatus.
func (s TaskStatus) String() string { return string(s) }

// validateTransition checks if a status transition is valid and returns an error if not.
func (s TaskStatus) validateTransition(target TaskStatus) error {
	if !s.isValidTransition(target) {
		return fmt.Errorf("invalid task status transition from %s to %s", s, target)
	}
	return nil
}

// isValidTransition checks if the current status can transition to the target status.
// It enforces the task lifecycle rules to prevent invalid state changes.
func (s TaskStatus) isValidTransition(target TaskStatus) bool {
	switch s {
	case TaskStatusPending:
		// From Pending, can only move to InProgress, Failed, or Paused.
		return target == TaskStatusInProgress || target == TaskStatusFailed || target == TaskStatusPaused
	case TaskStatusInProgress:
		// From InProgress, can move to Completed, Failed, Stale, or Paused.
		return target == TaskStatusCompleted || target == TaskStatusFailed || target == TaskStatusStale || target == TaskStatusPaused
	case TaskStatusStale:
		// From Stale, can move to InProgress, Failed, Completed, or Paused.
		return target == TaskStatusInProgress || target == TaskStatusFailed || target == TaskStatusCompleted || target == TaskStatusPaused
	case TaskStatusPaused:
		// From Paused, can move to InProgress, Failed, or Stale.
		return target == TaskStatusInProgress || target == TaskStatusFailed || target == TaskStatusStale
	case TaskStatusCompleted, TaskStatusFailed:
		// Terminal states - no further transitions allowed.
		return false
	case TaskStatusUnspecified:
		// Cannot transition from unspecified state.
		return false
	default:
		return false
	}
}
