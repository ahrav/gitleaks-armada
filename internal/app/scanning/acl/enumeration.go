// Package acl provides anti-corruption layer functionality for translating between domain boundaries.
package acl

import (
	"github.com/ahrav/gitleaks-armada/internal/app/scanning/dtos"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
)

// EnumerationACL translates enumeration domain objects into scanning domain DTOs.
// It acts as an anti-corruption layer to maintain clean domain boundaries and prevent
// leakage of domain concepts between contexts.
type EnumerationACL struct{}

// ToScanRequest converts a scanning.TaskCreatedEvent into a scanning domain ScanRequest.
// This translation allows the scanning domain to remain decoupled from enumeration
// domain concepts while preserving all necessary scanning information.
func (acl EnumerationACL) ToScanRequest(task *scanning.TaskCreatedEvent) *dtos.ScanRequest {
	return dtos.NewScanRequestFromScanningTask(task)
}
