// Package dtos provides data transfer objects for the scanning service.
package dtos

import (
	"fmt"
	"strconv"

	"github.com/google/uuid"

	"github.com/ahrav/gitleaks-armada/internal/domain/enumeration"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
)

// SourceType identifies the external system containing resources to be scanned.
// This determines how authentication and access will be handled.
type SourceType string

const (
	// SourceTypeUnspecified indicates no source type was provided.
	SourceTypeUnspecified SourceType = "UNSPECIFIED"
	// SourceTypeGitHub represents GitHub repositories as scan targets.
	SourceTypeGitHub SourceType = "GITHUB"
	// SourceTypeURL represents a URL as a scan target.
	SourceTypeURL SourceType = "URL"
	// SourceTypeS3 represents AWS S3 buckets as scan targets.
	SourceTypeS3 SourceType = "S3"
	// ...
)

// CredentialType identifies the authentication mechanism used to access scan targets.
type CredentialType string

const (
	// CredentialTypeUnknown indicates the credential type could not be determined.
	CredentialTypeUnknown CredentialType = "UNKNOWN"
	// CredentialTypeUnauthenticated is used for public resources requiring no auth.
	CredentialTypeUnauthenticated CredentialType = "UNAUTHENTICATED"
	// CredentialTypeGitHub authenticates against GitHub using a personal access token.
	CredentialTypeGitHub CredentialType = "GITHUB"
	// CredentialTypeS3 authenticates against AWS S3 using access credentials.
	CredentialTypeS3 CredentialType = "S3"
	// CredentialTypeURL authenticates against a URL using a personal access token.
	CredentialTypeURL CredentialType = "URL"
)

// ScanCredentials encapsulates authentication details needed to access a scan target.
// The Values map stores credential data in a type-safe way based on the CredentialType.
type ScanCredentials struct {
	Type   CredentialType
	Values map[string]any
}

// ScanRequest contains all information needed to initiate a security scan of a resource.
// It acts as a data transfer object between the API layer and scanning service.
type ScanRequest struct {
	// TaskID uniquely identifies this scan operation.
	TaskID uuid.UUID
	// SourceType determines which external system contains the target resource.
	SourceType SourceType
	// JobID groups related scan tasks together.
	JobID uuid.UUID
	// SessionID groups related scan tasks together.
	SessionID uuid.UUID
	// ResourceURI is the location of the target to be scanned.
	ResourceURI string
	// Metadata provides additional context for scan processing.
	Metadata map[string]string
	// Credentials contains authentication details for accessing the resource.
	Credentials ScanCredentials
}

// NewScanRequestFromEnumerationTask creates a new ScanRequest from an enumeration TaskCreatedEvent.
// This handles the translation between enumeration and scanning domains.
func NewScanRequestFromEnumerationTask(task *enumeration.TaskCreatedEvent) *ScanRequest {
	if task == nil {
		return nil
	}

	return &ScanRequest{
		TaskID:      task.Task.ID,
		JobID:       task.JobID,
		SourceType:  toScanningSourceType(task.Task.SourceType),
		SessionID:   task.Task.SessionID(),
		ResourceURI: task.Task.ResourceURI(),
		Metadata:    task.Task.Metadata(),
		Credentials: toScanningCredentials(task.Task.Credentials()),
	}
}

// NewScanRequestFromResumeEvent creates a new ScanRequest from a TaskResumeEvent.
// This is an internal conversion within the scanning domain.
func NewScanRequestFromResumeEvent(evt *scanning.TaskResumeEvent) (*ScanRequest, error) {
	checkpointJSON, err := evt.Checkpoint.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal checkpoint: %v", err)
	}

	return &ScanRequest{
		TaskID:      evt.TaskID,
		JobID:       evt.JobID,
		SourceType:  toScanningSourceType(evt.SourceType),
		ResourceURI: evt.ResourceURI,
		Metadata: map[string]string{
			"sequence_num": strconv.FormatInt(int64(evt.SequenceNum), 10),
			"checkpoint":   string(checkpointJSON),
		},
	}, nil
}

// toScanningSourceType maps domain source types to scanning domain equivalents.
func toScanningSourceType(e shared.SourceType) SourceType {
	switch e {
	case shared.SourceTypeGitHub:
		return SourceTypeGitHub
	case shared.SourceTypeS3:
		return SourceTypeS3
	case shared.SourceTypeURL:
		return SourceTypeURL
	default:
		return SourceTypeUnspecified
	}
}

// toScanningCredentials converts domain credentials to scanning domain credentials.
func toScanningCredentials(creds *enumeration.TaskCredentials) ScanCredentials {
	if creds == nil {
		return ScanCredentials{Type: CredentialTypeUnknown}
	}
	return ScanCredentials{
		Type:   toScanningCredentialType(creds.Type),
		Values: creds.Values,
	}
}

// toScanningCredentialType maps domain credential types to scanning domain equivalents.
func toScanningCredentialType(ec enumeration.CredentialType) CredentialType {
	switch ec {
	case enumeration.CredentialTypeUnauthenticated:
		return CredentialTypeUnauthenticated
	case enumeration.CredentialTypeGitHub:
		return CredentialTypeGitHub
	case enumeration.CredentialTypeS3:
		return CredentialTypeS3
	case enumeration.CredentialTypeURL:
		return CredentialTypeURL
	default:
		return CredentialTypeUnknown
	}
}
