// Package rules provides functionality for managing and validating Gitleaks scanning rules
// used to detect sensitive information in source code repositories.
package rules

import "context"

// RuleService manages the lifecycle and validation of Gitleaks scanning rules.
// It acts as the primary interface for rule operations, ensuring rules meet
// domain requirements before being persisted.
type RuleService interface {
	// SaveRule stores a validated Gitleaks rule.
	// It performs domain validation before persisting to ensure the rule meets
	// all requirements. Returns an error if validation or persistence fails.
	SaveRule(ctx context.Context, r GitleaksRule) error
}

// RuleRepository provides persistent storage operations for Gitleaks rules.
// A durable storage implementation is required to maintain rule consistency
// across service restarts and enable rule sharing between system components.
type RuleRepository interface {
	// SaveRule atomically persists a Gitleaks rule and its allowlists.
	// Returns an error if the save operation fails.
	SaveRule(ctx context.Context, rule GitleaksRule) error
}
