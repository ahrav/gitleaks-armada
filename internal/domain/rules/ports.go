package rules

import "context"

// RuleService provides domain operations for managing Gitleaks scanning rules.
// It encapsulates business logic for rule validation and persistence.
type RuleService interface {
	// SaveRule validates and persists a Gitleaks rule to storage.
	// It ensures the rule meets domain requirements before saving.
	SaveRule(ctx context.Context, r GitleaksRule) error
}

// RulesStorage defines the storage interface for persisting Gitleaks scanning rules.
// Implementations of this interface provide durable storage capabilities to maintain
// rule definitions across service restarts and enable rule sharing between components.
type RulesStorage interface {
	// SaveRule persists a single Gitleaks rule and its associated allowlists to storage.
	// It ensures atomic updates of both the rule and its allowlist components to maintain
	// data consistency. Returns an error if the save operation fails.
	SaveRule(ctx context.Context, rule GitleaksRule) error
}

