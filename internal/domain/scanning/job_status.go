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

	// JobStatusInProgress indicates a job is actively processing tasks.
	JobStatusRunning JobStatus = "RUNNING"

	// JobStatusCompleted indicates all job tasks finished successfully.
	JobStatusCompleted JobStatus = "COMPLETED"

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
	case JobStatusCompleted:
		return 4
	case JobStatusFailed:
		return 5
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
	case JobStatusCompleted:
		return "SCAN_JOB_STATUS_COMPLETED"
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
		return JobStatusCompleted
	case 5:
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
	case "COMPLETED", "SCAN_JOB_STATUS_COMPLETED":
		return JobStatusCompleted
	case "FAILED", "SCAN_JOB_STATUS_FAILED":
		return JobStatusFailed
	default:
		return "" // represents unspecified
	}
}

// ValidateTransition checks if a status transition is valid and returns an error if not.
func (s JobStatus) ValidateTransition(target JobStatus) error {
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
		// From Enumerating, can move to Running or Failed.
		return target == JobStatusRunning || target == JobStatusFailed
	case JobStatusRunning:
		// From Running, can move to Completed or Failed.
		return target == JobStatusCompleted || target == JobStatusFailed
	case JobStatusCompleted, JobStatusFailed:
		// Terminal states - no further transitions allowed.
		return false
	default:
		return false
	}
}
