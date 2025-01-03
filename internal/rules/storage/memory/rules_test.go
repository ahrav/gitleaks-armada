package memory

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ahrav/gitleaks-armada/internal/domain/rules"
)

func TestInMemoryRulesStorage_SaveRule(t *testing.T) {
	t.Parallel()

	store := NewStore()
	ctx := context.Background()

	rule := rules.GitleaksRule{
		RuleID:      "rule-1",
		Description: "test rule",
		Entropy:     3.14,
		SecretGroup: 42,
		Regex:       "test-regex",
		Path:        "some/path",
		Tags:        []string{"tag1"},
		Keywords:    []string{"keyword1", "keyword2"},
		Allowlists: []rules.GitleaksAllowlist{
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
	}

	err := store.SaveRule(ctx, rule)
	require.NoError(t, err)

	loaded, err := store.GetRule(ctx, rule.RuleID)
	require.NoError(t, err)
	require.NotNil(t, loaded)

	assert.Equal(t, rule.RuleID, loaded.RuleID)
	assert.Equal(t, rule.Description, loaded.Description)
	assert.Equal(t, rule.Entropy, loaded.Entropy)
	assert.Equal(t, rule.SecretGroup, loaded.SecretGroup)
	assert.Equal(t, rule.Regex, loaded.Regex)
	assert.Equal(t, rule.Path, loaded.Path)
	assert.Equal(t, rule.Tags, loaded.Tags)
	assert.Equal(t, rule.Keywords, loaded.Keywords)

	// Verify allowlist.
	require.Len(t, loaded.Allowlists, 1)
	assert.Equal(t, rule.Allowlists[0].Description, loaded.Allowlists[0].Description)
	assert.Equal(t, rule.Allowlists[0].MatchCondition, loaded.Allowlists[0].MatchCondition)
	assert.Equal(t, rule.Allowlists[0].RegexTarget, loaded.Allowlists[0].RegexTarget)
	assert.Equal(t, rule.Allowlists[0].Commits, loaded.Allowlists[0].Commits)
	assert.Equal(t, rule.Allowlists[0].PathRegexes, loaded.Allowlists[0].PathRegexes)
	assert.Equal(t, rule.Allowlists[0].Regexes, loaded.Allowlists[0].Regexes)
	assert.Equal(t, rule.Allowlists[0].StopWords, loaded.Allowlists[0].StopWords)
}

func TestInMemoryRulesStorage_SaveRuleUpdate(t *testing.T) {
	t.Parallel()

	store := NewStore()
	ctx := context.Background()

	// Initial rule.
	rule := rules.GitleaksRule{
		RuleID:      "rule-1",
		Description: "initial description",
		Regex:       "initial-regex",
	}

	err := store.SaveRule(ctx, rule)
	require.NoError(t, err)

	// Update rule.
	rule.Description = "updated description"
	rule.Regex = "updated-regex"
	err = store.SaveRule(ctx, rule)
	require.NoError(t, err)

	// Verify update.
	loaded, err := store.GetRule(ctx, rule.RuleID)
	require.NoError(t, err)
	require.NotNil(t, loaded)

	assert.Equal(t, "updated description", loaded.Description)
	assert.Equal(t, "updated-regex", loaded.Regex)
}

func TestInMemoryRulesStorage_GetNonExistentRule(t *testing.T) {
	t.Parallel()

	store := NewStore()
	ctx := context.Background()

	loaded, err := store.GetRule(ctx, "non-existent")
	require.NoError(t, err)
	assert.Nil(t, loaded)
}

func TestInMemoryRulesStorage_Mutability(t *testing.T) {
	t.Parallel()

	store := NewStore()
	ctx := context.Background()

	rule := rules.GitleaksRule{
		RuleID:   "rule-1",
		Tags:     []string{"tag1"},
		Keywords: []string{"keyword1"},
		Allowlists: []rules.GitleaksAllowlist{
			{
				Commits: []string{"c1"},
			},
		},
	}

	err := store.SaveRule(ctx, rule)
	require.NoError(t, err)

	// Load and modify the rule.
	loaded, err := store.GetRule(ctx, rule.RuleID)
	require.NoError(t, err)
	require.NotNil(t, loaded)

	loaded.Tags = append(loaded.Tags, "tag2")
	loaded.Keywords = append(loaded.Keywords, "keyword2")
	loaded.Allowlists[0].Commits = append(loaded.Allowlists[0].Commits, "c2")

	// Reload and verify original wasn't modified.
	reloaded, err := store.GetRule(ctx, rule.RuleID)
	require.NoError(t, err)
	require.NotNil(t, reloaded)

	assert.Equal(t, []string{"tag1"}, reloaded.Tags)
	assert.Equal(t, []string{"keyword1"}, reloaded.Keywords)
	assert.Equal(t, []string{"c1"}, reloaded.Allowlists[0].Commits)
}
