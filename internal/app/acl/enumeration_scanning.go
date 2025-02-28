// Package acl provides anti-corruption layers for translating between domains
package acl

import (
	"context"

	"github.com/ahrav/gitleaks-armada/internal/domain/enumeration"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/pkg/common/uuid"
)

// EnumerationToScanningTranslator converts enumeration domain objects to scanning domain objects.
type EnumerationToScanningTranslator struct{}

func (e EnumerationToScanningTranslator) TranslateEnumerationResultToScanning(
	ctx context.Context,
	enumResult enumeration.EnumerationResult,
	jobID uuid.UUID,
	auth scanning.Auth,
	metadata map[string]string,
) *scanning.ScanningResult {
	scanTargetsCh := make(chan []uuid.UUID, 10)
	tasksCh := make(chan scanning.TranslationResult, 10)
	errCh := make(chan error, 10)

	allChannelsClosed := func() bool {
		return enumResult.ScanTargetsCh == nil && enumResult.TasksCh == nil && enumResult.ErrCh == nil
	}

	go func() {
		defer func() {
			close(scanTargetsCh)
			close(tasksCh)
			close(errCh)
			// TODO: Use a logger here.
		}()

		for {
			select {
			case <-ctx.Done():
				errCh <- ctx.Err()
				return

			case targets, ok := <-enumResult.ScanTargetsCh:
				if !ok {
					enumResult.ScanTargetsCh = nil
					if allChannelsClosed() {
						return
					}
					continue
				}
				scanTargetsCh <- targets // No translation needed on uuid.UUID

			case enumTask, ok := <-enumResult.TasksCh:
				if !ok {
					enumResult.TasksCh = nil
					if allChannelsClosed() {
						return
					}
					continue
				}
				// Only translate the task-specific field.
				taskResult := scanning.TranslationResult{
					Task: scanning.NewScanTask(jobID, enumTask.SourceType, enumTask.ID, enumTask.ResourceURI()),
				}
				tasksCh <- taskResult

			case errVal, ok := <-enumResult.ErrCh:
				if !ok {
					enumResult.ErrCh = nil
					if allChannelsClosed() {
						return
					}
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
		Auth:          auth,
		Metadata:      metadata,
	}
}
