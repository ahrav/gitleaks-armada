package rules

import "context"

// RulesStorage defines the storage interface for persisting Gitleaks scanning rules.
// Implementations of this interface provide durable storage capabilities to maintain
// rule definitions across service restarts and enable rule sharing between components.
type RulesStorage interface {
	// SaveRule persists a single Gitleaks rule and its associated allowlists to storage.
	// It ensures atomic updates of both the rule and its allowlist components to maintain
	// data consistency. Returns an error if the save operation fails.
	SaveRule(ctx context.Context, rule GitleaksRule) error
}
