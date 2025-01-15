// Package acl provides anti-corruption layer functionality for translating between domain boundaries.
package acl

import (
	"github.com/ahrav/gitleaks-armada/internal/app/scanning/dtos"
	"github.com/ahrav/gitleaks-armada/internal/domain/enumeration"
	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
)

// EnumerationACL translates enumeration domain objects into scanning domain DTOs.
// It acts as an anti-corruption layer to maintain clean domain boundaries and prevent
// leakage of domain concepts between contexts.
type EnumerationACL struct{}

// ToScanRequest converts an enumeration.Task into a scanning domain ScanRequest.
// This translation allows the scanning domain to remain decoupled from enumeration
// domain concepts while preserving all necessary scanning information.
func (acl EnumerationACL) ToScanRequest(task *enumeration.Task) *dtos.ScanRequest {
	if task == nil {
		return nil
	}

	return &dtos.ScanRequest{
		TaskID:      task.TaskID,
		SourceType:  toScanningSourceType(task.SourceType),
		SessionID:   task.SessionID(),
		ResourceURI: task.ResourceURI(),
		Metadata:    task.Metadata(),
		Credentials: toScanningCredentials(task.Credentials()),
	}
}

// toScanningSourceType maps enumeration domain source types to their scanning domain equivalents.
// This internal translation ensures the scanning domain remains isolated from enumeration concepts.
func toScanningSourceType(e shared.SourceType) dtos.SourceType {
	switch e {
	case shared.SourceTypeGitHub:
		return dtos.SourceTypeGitHub
	case shared.SourceTypeS3:
		return dtos.SourceTypeS3
	case shared.SourceTypeURL:
		return dtos.SourceTypeURL
	default:
		return dtos.SourceTypeUnspecified
	}
}

// toScanningCredentials converts enumeration domain credentials to scanning domain credentials.
// Returns unknown credential type if nil credentials are provided.
func toScanningCredentials(creds *enumeration.TaskCredentials) dtos.ScanCredentials {
	if creds == nil {
		return dtos.ScanCredentials{Type: dtos.CredentialTypeUnknown}
	}
	return dtos.ScanCredentials{
		Type:   toScanningCredentialType(creds.Type),
		Values: creds.Values,
	}
}

// toScanningCredentialType maps enumeration domain credential types to scanning domain equivalents.
// Returns unknown credential type for unrecognized enumeration credential types.
func toScanningCredentialType(ec enumeration.CredentialType) dtos.CredentialType {
	switch ec {
	case enumeration.CredentialTypeUnauthenticated:
		return dtos.CredentialTypeUnauthenticated
	case enumeration.CredentialTypeGitHub:
		return dtos.CredentialTypeGitHub
	case enumeration.CredentialTypeS3:
		return dtos.CredentialTypeS3
	case enumeration.CredentialTypeURL:
		return dtos.CredentialTypeURL
	default:
		return dtos.CredentialTypeUnknown
	}
}
