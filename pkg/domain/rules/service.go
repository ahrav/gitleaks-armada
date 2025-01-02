package rules

import (
	"context"
)

type RuleService struct {
	rulesStorage RulesStorage
	// possibly other domain-level fields
}

func NewRuleService(rulesStorage RulesStorage) *RuleService {
	return &RuleService{rulesStorage: rulesStorage}
}

func (rs *RuleService) SaveRule(ctx context.Context, r GitleaksRule) error {
	// Possibly do domain validations or transformations
	// e.g., if r.RuleID is empty, return an error
	return rs.rulesStorage.SaveRule(ctx, r)
}
