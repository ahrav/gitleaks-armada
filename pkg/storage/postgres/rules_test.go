package postgres

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ahrav/gitleaks-armada/pkg/messaging"
)

func TestRulesStorage_SaveRuleset(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := setupTestContainer(t)
	defer cleanup()

	rulesStorage := NewRulesStorage(dbConn, noOpTracer())

	ruleset := messaging.GitleaksRuleSet{
		Rules: []messaging.GitleaksRule{
			{
				RuleID:      "rule-1",
				Description: "test rule",
				Entropy:     3.14,
				SecretGroup: 42,
				Regex:       "test-regex",
				Path:        "some/path",
				Tags:        []string{"tag1"},
				Keywords:    []string{"keyword1", "keyword2"},
				Allowlists: []messaging.GitleaksAllowlist{
					{
						Description:    "Example allowlist",
						MatchCondition: "ANY",
						RegexTarget:    "match",
						Commits:        []string{"c1", "c2"},
						PathRegexes:    []string{"p1"},
						Regexes:        []string{"r1"},
						StopWords:      []string{"s1"},
					},
				},
			},
		},
	}

	ctx := context.Background()
	err := rulesStorage.SaveRuleset(ctx, ruleset)
	require.NoError(t, err)

	// TODO: Add a getter or some other method to verify data was inserted.
	// We don't currently have a getter since we don't have a use case for it yet.
	// Example:
	//   loadedRule, err := someGetRuleMethod(dbConn, "rule-1")
	//   require.NoError(t, err)
	//   require.NotNil(t, loadedRule)
	//   assert.Equal(t, "test rule", loadedRule.Description)
	// etc.

	// TODO: Remove this once we have a getter or some other method to verify data was inserted.
	rows, err := dbConn.Query(ctx, "SELECT rule_id, description FROM rules WHERE rule_id = $1", "rule-1")
	require.NoError(t, err)
	defer rows.Close()

	var count int
	for rows.Next() {
		var rid, desc string
		err := rows.Scan(&rid, &desc)
		require.NoError(t, err)
		assert.Equal(t, "rule-1", rid)
		assert.Equal(t, "test rule", desc)
		count++
	}
	assert.Equal(t, 1, count, "expected one row in the rules table")
}
