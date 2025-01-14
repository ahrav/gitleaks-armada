// Package dtos provides data transfer objects for the scanning service.
package dtos

import "github.com/google/uuid"

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
	// SessionID groups related scan tasks together.
	SessionID uuid.UUID
	// ResourceURI is the location of the target to be scanned.
	ResourceURI string
	// Metadata provides additional context for scan processing.
	Metadata map[string]string
	// Credentials contains authentication details for accessing the resource.
	Credentials ScanCredentials
}
