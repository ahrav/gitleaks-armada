package scanning

import (
	"fmt"
)

// JobStatus represents the current state of a scan job. It enables tracking of
// job lifecycle from initialization through completion or failure.
type JobStatus string

const (
	// JobStatusInitialized indicates a job has been created but not yet started.
	JobStatusQueued JobStatus = "QUEUED"

	// JobStatusEnumerating indicates a job is enumerating targets.
	JobStatusEnumerating JobStatus = "ENUMERATING"

	// JobStatusRunning indicates a job is actively processing tasks.
	JobStatusRunning JobStatus = "RUNNING"

	// JobStatusPausing indicates a job is in the process of pausing.
	JobStatusPausing JobStatus = "PAUSING"

	// JobStatusPaused indicates a job has been temporarily halted.
	JobStatusPaused JobStatus = "PAUSED"

	// JobStatusCompleted indicates all job tasks finished successfully.
	JobStatusCompleted JobStatus = "COMPLETED"

	// JobStatusCancelling indicates a job is in the process of cancelling.
	JobStatusCancelling JobStatus = "CANCELLING"

	// JobStatusCancelled indicates a job has been cancelled.
	JobStatusCancelled JobStatus = "CANCELLED"

	// JobStatusFailed indicates the job encountered an unrecoverable error.
	JobStatusFailed JobStatus = "FAILED"
)

func (s JobStatus) String() string { return string(s) }

// Int32 returns the int32 value for protobuf enum values.
func (s JobStatus) Int32() int32 {
	switch s {
	case JobStatusQueued:
		return 1
	case JobStatusEnumerating:
		return 2
	case JobStatusRunning:
		return 3
	case JobStatusPausing:
		return 4
	case JobStatusPaused:
		return 5
	case JobStatusCompleted:
		return 6
	case JobStatusCancelling:
		return 7
	case JobStatusCancelled:
		return 8
	case JobStatusFailed:
		return 9
	default:
		return 0
	}
}

// ProtoString returns the SCREAMING_SNAKE_CASE string representation
// of the JobStatus. Used for protobuf enum string values.
func (s JobStatus) ProtoString() string {
	switch s {
	case JobStatusQueued:
		return "SCAN_JOB_STATUS_QUEUED"
	case JobStatusEnumerating:
		return "SCAN_JOB_STATUS_ENUMERATING"
	case JobStatusRunning:
		return "SCAN_JOB_STATUS_RUNNING"
	case JobStatusPausing:
		return "SCAN_JOB_STATUS_PAUSING"
	case JobStatusPaused:
		return "SCAN_JOB_STATUS_PAUSED"
	case JobStatusCompleted:
		return "SCAN_JOB_STATUS_COMPLETED"
	case JobStatusCancelling:
		return "SCAN_JOB_STATUS_CANCELLING"
	case JobStatusCancelled:
		return "SCAN_JOB_STATUS_CANCELLED"
	case JobStatusFailed:
		return "SCAN_JOB_STATUS_FAILED"
	default:
		return "SCAN_JOB_STATUS_UNSPECIFIED"
	}
}

// FromInt32 creates a JobStatus from an int32 value.
func JobStatusFromInt32(i int32) JobStatus {
	switch i {
	case 1:
		return JobStatusQueued
	case 2:
		return JobStatusEnumerating
	case 3:
		return JobStatusRunning
	case 4:
		return JobStatusPausing
	case 5:
		return JobStatusPaused
	case 6:
		return JobStatusCompleted
	case 7:
		return JobStatusCancelling
	case 8:
		return JobStatusCancelled
	case 9:
		return JobStatusFailed
	default:
		return "" // represents unspecified
	}
}

// ParseJobStatus converts a string to a JobStatus.
func ParseJobStatus(s string) JobStatus {
	switch s {
	case "QUEUED", "SCAN_JOB_STATUS_QUEUED":
		return JobStatusQueued
	case "ENUMERATING", "SCAN_JOB_STATUS_ENUMERATING":
		return JobStatusEnumerating
	case "RUNNING", "SCAN_JOB_STATUS_RUNNING":
		return JobStatusRunning
	case "PAUSING", "SCAN_JOB_STATUS_PAUSING":
		return JobStatusPausing
	case "PAUSED", "SCAN_JOB_STATUS_PAUSED":
		return JobStatusPaused
	case "COMPLETED", "SCAN_JOB_STATUS_COMPLETED":
		return JobStatusCompleted
	case "CANCELLING", "SCAN_JOB_STATUS_CANCELLING":
		return JobStatusCancelling
	case "CANCELLED", "SCAN_JOB_STATUS_CANCELLED":
		return JobStatusCancelled
	case "FAILED", "SCAN_JOB_STATUS_FAILED":
		return JobStatusFailed
	default:
		return "" // represents unspecified
	}
}

// validateTransition checks if a status transition is valid and returns an error if not.
func (s JobStatus) validateTransition(target JobStatus) error {
	if !s.isValidTransition(target) {
		return fmt.Errorf("invalid job status transition from %s to %s", s, target)
	}
	return nil
}

// isValidTransition checks if the current status can transition to the target status.
// It enforces the job lifecycle rules to prevent invalid state changes.
func (s JobStatus) isValidTransition(target JobStatus) bool {
	switch s {
	case JobStatusQueued:
		// From Queued, can only move to Enumerating.
		return target == JobStatusEnumerating
	case JobStatusEnumerating:
		// From Enumerating, can move to Running, Failed, Completed, Pausing, or Cancelling.
		return target == JobStatusRunning ||
			target == JobStatusFailed ||
			target == JobStatusCompleted ||
			target == JobStatusPausing ||
			target == JobStatusCancelling
	case JobStatusRunning:
		// From Running, can move to Completed, Failed, Pausing, or Cancelling.
		return target == JobStatusCompleted ||
			target == JobStatusFailed ||
			target == JobStatusPausing ||
			target == JobStatusCancelling
	case JobStatusPausing:
		// From Pausing, can move to Paused, Failed, or Cancelling.
		return target == JobStatusPaused ||
			target == JobStatusFailed ||
			target == JobStatusCancelling
	case JobStatusPaused:
		// From Paused, can move to Running, Failed, or Cancelling.
		return target == JobStatusRunning ||
			target == JobStatusFailed ||
			target == JobStatusCancelling
	case JobStatusCancelling:
		// From Cancelling, can only move to Cancelled or Failed.
		return target == JobStatusCancelled || target == JobStatusFailed
	case JobStatusCompleted, JobStatusCancelled, JobStatusFailed:
		// Terminal states - no further transitions allowed.
		return false
	default:
		return false
	}
}
