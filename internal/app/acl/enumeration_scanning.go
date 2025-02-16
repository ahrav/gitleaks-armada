// Package acl provides anti-corruption layers for translating between domains
package acl

import (
	"github.com/google/uuid"

	"github.com/ahrav/gitleaks-armada/internal/domain/enumeration"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
)

// EnumerationToScanningTranslator converts enumeration domain objects to scanning domain objects.
type EnumerationToScanningTranslator struct{}

// TranslationResult contains both the scanning task and its associated credentials.
type TranslationResult struct {
	Task        *scanning.Task
	Credentials scanning.Credentials
	Metadata    map[string]string
}

// ToScanningTask converts an enumeration Task to a translation result.
// The translation result contains the scanning task, credentials, and metadata.
func (EnumerationToScanningTranslator) Translate(jobID uuid.UUID, enumTask *enumeration.Task) TranslationResult {
	// Create the core scanning task (focused on execution state).
	task := scanning.NewScanTask(
		jobID,
		enumTask.ID,
		enumTask.ResourceURI(),
	)
	creds := toScanningCredentials(enumTask.Credentials())

	return TranslationResult{Task: task, Credentials: creds, Metadata: enumTask.Metadata()}
}

// toScanningCredentials converts enumeration credentials to scanning credentials.
func toScanningCredentials(creds *enumeration.TaskCredentials) scanning.Credentials {
	if creds == nil {
		return scanning.NewCredentials(scanning.CredentialTypeUnknown, nil)
	}
	return scanning.NewCredentials(
		toScanningCredentialType(creds.Type),
		creds.Values,
	)
}

// toScanningCredentialType maps enumeration credential types to scanning domain equivalents.
func toScanningCredentialType(ec enumeration.CredentialType) scanning.CredentialType {
	switch ec {
	case enumeration.CredentialTypeUnauthenticated:
		return scanning.CredentialTypeUnauthenticated
	case enumeration.CredentialTypeGitHub:
		return scanning.CredentialTypeGitHub
	case enumeration.CredentialTypeS3:
		return scanning.CredentialTypeS3
	case enumeration.CredentialTypeURL:
		return scanning.CredentialTypeURL
	default:
		return scanning.CredentialTypeUnknown
	}
}
