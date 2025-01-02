package rules

import "context"

// RulesStorage provides persistent storage for Gitleaks rules.
type RulesStorage interface {
	// SaveRule persists a single rule and its allowlists to storage.
	SaveRule(ctx context.Context, rule GitleaksRule) error
}
