package postgres

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ahrav/gitleaks-armada/pkg/messaging"
)

func TestRulesStorage_SaveRuleset(t *testing.T) {
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
						RegexTarget:    "target",
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

	// 5. (Optionally) Query DB to verify data was inserted
	// If you have a getter or some other method, call it. For example:
	//   loadedRule, err := someGetRuleMethod(dbConn, "rule-1")
	//   require.NoError(t, err)
	//   require.NotNil(t, loadedRule)
	//   assert.Equal(t, "test rule", loadedRule.Description)
	// etc.

	// If you don't have a direct getter, you can query with raw SQL or
	// create additional sqlc queries for testing.

	// Example (raw SQL):
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
