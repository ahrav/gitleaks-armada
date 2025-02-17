// Package acl provides anti-corruption layers for translating between domains
package acl

import (
	"github.com/google/uuid"

	"github.com/ahrav/gitleaks-armada/internal/domain/enumeration"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
)

// EnumerationToScanningTranslator converts enumeration domain objects to scanning domain objects.
type EnumerationToScanningTranslator struct{}

// TranslationResult contains both the scanning task and its associated metadata.
type TranslationResult struct {
	Task     *scanning.Task
	Auth     scanning.Auth
	Metadata map[string]string
}

// Translate converts an enumeration Task to a translation result.
// The translation result contains the scanning task, auth configuration, and metadata.
func (EnumerationToScanningTranslator) Translate(jobID uuid.UUID, enumTask *enumeration.Task) TranslationResult {
	// Convert auth if present.
	var auth scanning.Auth
	if enumCreds := enumTask.Credentials(); enumCreds != nil {
		domainAuth := scanning.NewAuth(
			string(toScanningAuthType(enumCreds.Type)),
			enumCreds.Values,
		)
		auth = domainAuth
	}

	// Create the core scanning task.
	task := scanning.NewScanTask(
		jobID,
		enumTask.SourceType,
		enumTask.ID,
		enumTask.ResourceURI(),
	)

	return TranslationResult{
		Task:     task,
		Auth:     auth,
		Metadata: enumTask.Metadata(),
	}
}

// toScanningAuthType maps enumeration auth types to scanning domain equivalents.
func toScanningAuthType(ec enumeration.CredentialType) scanning.AuthType {
	switch ec {
	case enumeration.CredentialTypeNone:
		return scanning.AuthTypeNone
	case enumeration.CredentialTypeToken:
		return scanning.AuthTypeToken
	case enumeration.CredentialTypeAWS:
		return scanning.AuthTypeAWS
	case enumeration.CredentialTypeBasic:
		return scanning.AuthTypeBasic
	case enumeration.CredentialTypeOAuth:
		return scanning.AuthTypeOAuth
	default:
		return scanning.AuthTypeUnknown
	}
}
