package rules

import (
	"context"

	"github.com/ahrav/gitleaks-armada/internal/domain/rules"
)

// Service manages the lifecycle and validation of Gitleaks scanning rules.
// It acts as the primary interface for rule operations, ensuring rules meet
// domain requirements before being persisted.
type Service interface {
	// SaveRule stores a validated Gitleaks rule.
	// It performs domain validation before persisting to ensure the rule meets
	// all requirements. Returns an error if validation or persistence fails.
	SaveRule(ctx context.Context, r rules.GitleaksRule) error
}

// service implements the RuleService interface to provide rule management capabilities.
type service struct {
	rulesStorage rules.Repository
	// TODO: other domain-level fields, logger, tracer, etc.
}

// NewService creates a new RuleService instance with the provided storage implementation.
// The storage is used to persist validated rules.
func NewService(rulesStorage rules.Repository) *service {
	return &service{rulesStorage: rulesStorage}
}

// SaveRule implements RuleService.SaveRule by validating and persisting a Gitleaks rule.
// Currently passes through to storage, but is positioned to add domain validations.
func (rs *service) SaveRule(ctx context.Context, r rules.GitleaksRule) error {
	// Possibly do domain validations or transformations
	// e.g., if r.RuleID is empty, return an error
	return rs.rulesStorage.SaveRule(ctx, r)
}
