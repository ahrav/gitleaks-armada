// Package rules provides functionality for managing and validating Gitleaks scanning rules
// used to detect sensitive information in source code repositories.
package rules

import "context"

// Repository provides persistent storage operations for Gitleaks rules.
// A durable storage implementation is required to maintain rule consistency
// across service restarts and enable rule sharing between system components.
type Repository interface {
	// SaveRule atomically persists a Gitleaks rule and its allowlists.
	// Returns an error if the save operation fails.
	SaveRule(ctx context.Context, rule GitleaksRule) error
}
