package messaging

import (
	"fmt"

	pb "github.com/ahrav/gitleaks-armada/proto/scanner"
)

type Task struct {
	TaskID      string            // Unique identifier for the task
	ResourceURI string            // Location of the resource to scan
	Metadata    map[string]string // Additional context for task processing
	Credentials *TaskCredentials  // Authentication credentials for the resource
}

type ScanStatus string

const (
	ScanStatusUnspecified ScanStatus = "UNSPECIFIED" // Initial or unknown state
	ScanStatusSuccess     ScanStatus = "SUCCESS"     // Scan completed successfully
	ScanStatusError       ScanStatus = "ERROR"       // Scan failed

// Task represents a unit of scanning work to be processed by workers.
// It contains the necessary information to locate and scan a resource.
// ScanStatus represents the completion state of a scan operation.

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

// ScanProgress provides information about an ongoing scan operation.
type ScanProgress struct {
	TaskID          string
	PercentComplete float32           // Overall scan progress (0-100)
	ItemsProcessed  int64             // Number of items (e.g., files) processed
	TotalItems      int64             // Total number of items to process
	Metadata        map[string]string // Additional progress information
}

// CredentialType represents the supported authentication mechanisms for scanning targets.
type CredentialType string

const (
	// CredentialTypeUnspecified indicates no credential type was provided
	CredentialTypeUnspecified CredentialType = ""
	// CredentialTypeUnauthenticated is used for public resources that don't require auth
	CredentialTypeUnauthenticated CredentialType = "unauthenticated"
	// CredentialTypeGitHub authenticates against GitHub using a personal access token
	CredentialTypeGitHub CredentialType = "github"
	// CredentialTypeS3 authenticates against AWS S3 using access credentials
	CredentialTypeS3 CredentialType = "s3"
)

// TaskCredentials encapsulates authentication details for a specific target.
// Values stores credential data in a type-safe way.
type TaskCredentials struct {
	Type   CredentialType
	Values map[string]any
}

// CreateCredentials constructs the appropriate credential type based on the provided config.
// Returns an error if required fields are missing or the type is unsupported.
func CreateCredentials(credType CredentialType, config map[string]any) (*TaskCredentials, error) {
	switch credType {
	case CredentialTypeUnauthenticated:
		return NewUnauthenticatedCredentials(), nil

	case CredentialTypeGitHub:
		token, ok := config["auth_token"].(string)
		if !ok {
			return nil, fmt.Errorf("github credentials require auth_token")
		}
		return NewGitHubCredentials(token), nil

	case CredentialTypeS3:
		accessKey, _ := config["access_key"].(string)
		secretKey, _ := config["secret_key"].(string)
		sessionToken, _ := config["session_token"].(string)
		return NewS3Credentials(accessKey, secretKey, sessionToken), nil

	default:
		return nil, fmt.Errorf("unsupported credential type: %s", credType)
	}
}

// NewUnauthenticatedCredentials creates credentials for accessing public resources.
func NewUnauthenticatedCredentials() *TaskCredentials {
	return &TaskCredentials{Type: CredentialTypeUnauthenticated}
}

// NewGitHubCredentials creates credentials for GitHub authentication.
func NewGitHubCredentials(token string) *TaskCredentials {
	return &TaskCredentials{
		Type: CredentialTypeGitHub,
		Values: map[string]any{
			"auth_token": token,
		},
	}
}

// NewS3Credentials creates credentials for AWS S3 authentication.
func NewS3Credentials(accessKey, secretKey, session string) *TaskCredentials {
	return &TaskCredentials{
		Type: CredentialTypeS3,
		Values: map[string]any{
			"access_key":    accessKey,
			"secret_key":    secretKey,
			"session_token": session,
		},
	}
}

// ToProto converts credentials to their protobuf representation for transmission.
// Returns nil for unsupported credential types.
func (c *TaskCredentials) ToProto() *pb.TaskCredentials {
	switch c.Type {
	case CredentialTypeGitHub:
		return &pb.TaskCredentials{
			Auth: &pb.TaskCredentials_Github{
				Github: &pb.GitHubCredentials{
					AuthToken: c.Values["auth_token"].(string),
				},
			},
		}
	case CredentialTypeS3:
		return &pb.TaskCredentials{
			Auth: &pb.TaskCredentials_S3{
				S3: &pb.S3Credentials{
					AccessKey:    c.Values["access_key"].(string),
					SecretKey:    c.Values["secret_key"].(string),
					SessionToken: c.Values["session_token"].(string),
				},
			},
		}
	default:
		return nil
	}
}
