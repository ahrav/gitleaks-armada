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

// Int32 returns the int32 value for protobuf enum values.
func (s TaskStatus) Int32() int32 {
	switch s {
	case TaskStatusPending:
		return 1
	case TaskStatusInProgress:
		return 2
	case TaskStatusCompleted:
		return 3
	case TaskStatusFailed:
		return 4
	case TaskStatusStale:
		return 5
	case TaskStatusPaused:
		return 6
	default:
		return 0
	}
}

// ProtoString returns the SCREAMING_SNAKE_CASE string representation
// of the TaskStatus. Used for protobuf enum string values.
func (s TaskStatus) ProtoString() string {
	switch s {
	case TaskStatusPending:
		return "TASK_STATUS_PENDING"
	case TaskStatusInProgress:
		return "TASK_STATUS_IN_PROGRESS"
	case TaskStatusCompleted:
		return "TASK_STATUS_COMPLETED"
	case TaskStatusFailed:
		return "TASK_STATUS_FAILED"
	case TaskStatusStale:
		return "TASK_STATUS_STALE"
	case TaskStatusPaused:
		return "TASK_STATUS_PAUSED"
	default:
		return "TASK_STATUS_UNSPECIFIED"
	}
}

// FromInt32 creates a TaskStatus from an int32 value.
func TaskStatusFromInt32(i int32) TaskStatus {
	switch i {
	case 1:
		return TaskStatusPending
	case 2:
		return TaskStatusInProgress
	case 3:
		return TaskStatusCompleted
	case 4:
		return TaskStatusFailed
	case 5:
		return TaskStatusStale
	case 6:
		return TaskStatusPaused
	default:
		return TaskStatusUnspecified
	}
}

// ParseTaskStatus converts a string to a TaskStatus.
func ParseTaskStatus(s string) TaskStatus {
	switch s {
	case "PENDING", "TASK_STATUS_PENDING":
		return TaskStatusPending
	case "IN_PROGRESS", "TASK_STATUS_IN_PROGRESS":
		return TaskStatusInProgress
	case "COMPLETED", "TASK_STATUS_COMPLETED":
		return TaskStatusCompleted
	case "FAILED", "TASK_STATUS_FAILED":
		return TaskStatusFailed
	case "STALE", "TASK_STATUS_STALE":
		return TaskStatusStale
	case "PAUSED", "TASK_STATUS_PAUSED":
		return TaskStatusPaused
	default:
		return TaskStatusUnspecified
	}
}

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
