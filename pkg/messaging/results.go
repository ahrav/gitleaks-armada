package messaging

type ScanStatus string

const (
	ScanStatusUnspecified ScanStatus = "UNSPECIFIED" // Initial or unknown state
	ScanStatusSuccess     ScanStatus = "SUCCESS"     // Scan completed successfully
	ScanStatusError       ScanStatus = "ERROR"       // Scan failed
)

// Finding represents a single secret or sensitive data match discovered during scanning.
type Finding struct {
	Location   string  // Where the secret was found (e.g., file path)
	LineNumber int32   // Line number in the source file
	SecretType string  // Category of secret (e.g., "API Key", "Password")
	Match      string  // The actual text that matched
	Confidence float64 // Probability that this is a true positive
}

// ScanResult contains the findings and status from a completed scan task.
type ScanResult struct {
	TaskID   string    // References the original Task
	Findings []Finding // List of discovered secrets
	Status   ScanStatus
	Error    string // Description of failure if Status is ERROR
}
