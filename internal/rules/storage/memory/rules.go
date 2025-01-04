package memory

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/ahrav/gitleaks-armada/internal/domain/rules"
)

// Compile-time check that store implements rules.RulesStorage.
var _ rules.RuleRepository = (*store)(nil)

// store provides an in-memory implementation of rules storage.
type store struct{ rules sync.Map }

// NewStore creates a new in-memory rules storage.
func NewStore() *store { return new(store) }

// SaveRule stores a rule in memory. If a rule with the same ID already exists,
// it will be overwritten.
func (s *store) SaveRule(_ context.Context, rule rules.GitleaksRule) error {
	// Deep copy the rule to prevent external modifications
	copied, err := deepCopyRule(rule)
	if err != nil {
		return err
	}

	s.rules.Store(rule.RuleID, copied)
	return nil
}

// GetRule retrieves a rule by its ID. Returns nil if the rule doesn't exist.
func (s *store) GetRule(_ context.Context, ruleID string) (*rules.GitleaksRule, error) {
	value, ok := s.rules.Load(ruleID)
	if !ok {
		return nil, nil
	}

	rule := value.(*rules.GitleaksRule)
	// Deep copy the rule to prevent external modifications
	return deepCopyRule(*rule)
}

// deepCopyRule creates a deep copy of a GitleaksRule to ensure immutability.
func deepCopyRule(rule rules.GitleaksRule) (*rules.GitleaksRule, error) {
	// Use JSON marshaling/unmarshaling for deep copying
	data, err := json.Marshal(rule)
	if err != nil {
		return nil, err
	}

	var copied rules.GitleaksRule
	if err := json.Unmarshal(data, &copied); err != nil {
		return nil, err
	}

	return &copied, nil
}
