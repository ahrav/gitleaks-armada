package storage

import (
	"context"

	"github.com/ahrav/gitleaks-armada/pkg/messaging"
)

// RulesStorage provides persistent storage for Gitleaks rules.
type RulesStorage interface {
	// SaveRule persists a single rule and its allowlists to storage.
	SaveRule(ctx context.Context, rule messaging.GitleaksRule) error
}
