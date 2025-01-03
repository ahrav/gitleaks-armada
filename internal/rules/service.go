package rules

import (
	"context"

	domain "github.com/ahrav/gitleaks-armada/internal/domain/rules"
)

// ruleService implements the RuleService interface to provide rule management capabilities.
type ruleService struct {
	rulesStorage domain.RulesStorage
	// TODO: other domain-level fields, logger, tracer, etc.
}

// NewRuleService creates a new RuleService instance with the provided storage implementation.
// The storage is used to persist validated rules.
func NewRuleService(rulesStorage domain.RulesStorage) *ruleService {
	return &ruleService{rulesStorage: rulesStorage}
}

// SaveRule implements RuleService.SaveRule by validating and persisting a Gitleaks rule.
// Currently passes through to storage, but is positioned to add domain validations.
func (rs *ruleService) SaveRule(ctx context.Context, r domain.GitleaksRule) error {
	// Possibly do domain validations or transformations
	// e.g., if r.RuleID is empty, return an error
	return rs.rulesStorage.SaveRule(ctx, r)
}
