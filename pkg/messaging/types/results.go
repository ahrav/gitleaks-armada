package types

// ScanJobStatus represents the current state of a scan job in the system.
// It is used to track the lifecycle of a scan from queuing through completion.
type ScanJobStatus string

const (
	// ScanJobStatusUnspecified indicates an invalid or unknown status.
	ScanJobStatusUnspecified ScanJobStatus = "UNSPECIFIED"
	// ScanJobStatusQueued indicates the scan is waiting to be processed.
	ScanJobStatusQueued ScanJobStatus = "QUEUED"
	// ScanJobStatusRunning indicates the scan is actively being processed.
	ScanJobStatusRunning ScanJobStatus = "RUNNING"
	// ScanJobStatusCompleted indicates the scan finished successfully.
	ScanJobStatusCompleted ScanJobStatus = "COMPLETED"
	// ScanJobStatusFailed indicates the scan encountered an error.
	ScanJobStatusFailed ScanJobStatus = "FAILED"
)

// Finding represents a single secret or sensitive data match discovered during a scan.
// It contains the location and context of the finding to help users investigate and remediate.
type Finding struct {
	FilePath    string
	LineNumber  int32
	Line        string
	Fingerprint string // Unique identifier for deduplication
	Match       string
	AuthorEmail string

	// RawFinding contains scan-specific metadata like commit hash and commit message.
	// It uses a generic map to allow flexible storage of different finding types.
	RawFinding map[string]any
}

// ScanResult encapsulates the complete results of a scan operation.
// It includes any findings discovered and the final status of the scan.
type ScanResult struct {
	TaskID   string
	Findings []Finding
	Status   ScanJobStatus
	Error    string // Contains error details when Status is Failed
}
