package events

// EventType represents a domain event category, enabling type-safe event routing and handling.
// It allows the system to distinguish between different kinds of events like task creation,
// scan progress updates, and rule changes.
type EventType string

// Domain event type constants.
// These describe "something happened" in your scanning system.
const (
	EventTypeScanProgressUpdated EventType = "ScanProgressUpdated"
	EventTypeScanResultReceived  EventType = "ScanResultReceived"
	// e.g. "TaskCompleted", "TaskFailed", etc. if desired
)

// PublishOption is a function type that modifies PublishParams.
// It enables flexible configuration of event publishing behavior through functional options.
type PublishOption func(*PublishParams)

// PublishParams contains configuration options for publishing domain events.
// It encapsulates parameters that may affect how events are routed and processed.
type PublishParams struct {
	// Key is used as a partition key to control event routing and ordering.
	Key string
	// Headers contain metadata key-value pairs attached to the event.
	Headers map[string]string
}

// WithKey returns a PublishOption that sets the partition key for event routing.
// The key helps ensure related events are processed in order by the same consumer.
func WithKey(key string) PublishOption {
	return func(p *PublishParams) { p.Key = key }
}

// WithHeaders returns a PublishOption that attaches metadata headers to an event.
// Headers provide additional context and control over event processing.
func WithHeaders(headers map[string]string) PublishOption {
	return func(p *PublishParams) { p.Headers = headers }
}

// ScanProgress provides information about an ongoing scan operation.
type ScanProgress struct {
	TaskID          string
	PercentComplete float32           // Overall scan progress (0-100)
	ItemsProcessed  int64             // Number of items (e.g., files) processed
	TotalItems      int64             // Total number of items to process
	Metadata        map[string]string // Additional progress information
}

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
