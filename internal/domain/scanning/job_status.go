package scanning

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
