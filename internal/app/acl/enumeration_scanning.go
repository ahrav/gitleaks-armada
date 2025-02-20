// Package acl provides anti-corruption layers for translating between domains
package acl

import (
	"context"

	"github.com/google/uuid"

	"github.com/ahrav/gitleaks-armada/internal/domain/enumeration"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
)

// EnumerationToScanningTranslator converts enumeration domain objects to scanning domain objects.
type EnumerationToScanningTranslator struct{}

// Translate converts an enumeration Task to a scanning result.
// The translation result contains the scanning task, auth configuration, and metadata.
func (EnumerationToScanningTranslator) Translate(jobID uuid.UUID, enumTask *enumeration.Task) scanning.TranslationResult {
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

	return scanning.TranslationResult{
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

func (e EnumerationToScanningTranslator) TranslateEnumerationResultToScanning(
	ctx context.Context,
	enumResult enumeration.EnumerationResult,
	jobID uuid.UUID,
) *scanning.ScanningResult {
	scanTargetsCh := make(chan []uuid.UUID, 1)
	tasksCh := make(chan scanning.TranslationResult, 1)
	errCh := make(chan error, 1)

	allChannelsClosed := func() bool {
		return scanTargetsCh == nil && tasksCh == nil && errCh == nil
	}

	go func() {
		defer func() {
			close(scanTargetsCh)
			close(tasksCh)
			close(errCh)
			// TODO: Use a logger here.
		}()

		for {
			if allChannelsClosed() {
				break
			}

			select {
			case <-ctx.Done():
				errCh <- ctx.Err()
				return

			case targets, ok := <-enumResult.ScanTargetsCh:
				if !ok {
					enumResult.ScanTargetsCh = nil
					continue
				}
				scanTargetsCh <- targets // No translation needed on uuid.UUID

			case enumTask, ok := <-enumResult.TasksCh:
				if !ok {
					enumResult.TasksCh = nil
					continue
				}
				// Translate from enumeration.Task → scanning.Task.
				tasksCh <- e.Translate(jobID, enumTask)

			case errVal, ok := <-enumResult.ErrCh:
				if !ok {
					enumResult.ErrCh = nil
					continue
				}
				errCh <- errVal
			}
		}
	}()

	return &scanning.ScanningResult{
		ScanTargetsCh: scanTargetsCh,
		TasksCh:       tasksCh,
		ErrCh:         errCh,
	}
}
