package storage

import (
	"context"

	"github.com/ahrav/gitleaks-armada/pkg/events/types"
)

// RulesStorage provides persistent storage for Gitleaks rules.
type RulesStorage interface {
	// SaveRule persists a single rule and its allowlists to storage.
	SaveRule(ctx context.Context, rule types.GitleaksRule) error
}
