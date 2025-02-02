package rules

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ahrav/gitleaks-armada/internal/domain/rules"
	pb "github.com/ahrav/gitleaks-armada/proto"
)

func TestGitleaksRuleMessageConversion(t *testing.T) {
	t.Run("successful conversions", func(t *testing.T) {
		domainRule := rules.GitleaksRule{
			RuleID:      "test-rule",
			Description: "Test Description",
			Entropy:     7.5,
			SecretGroup: 1,
			Regex:       "test-regex",
			Path:        "test/path",
			Tags:        []string{"tag1", "tag2"},
			Keywords:    []string{"key1", "key2"},
			Allowlists: []rules.GitleaksAllowlist{
				{
					Description:    "test allowlist",
					MatchCondition: rules.MatchConditionOR,
					Commits:        []string{"commit1", "commit2"},
					PathRegexes:    []string{"path1", "path2"},
					Regexes:        []string{"regex1", "regex2"},
					RegexTarget:    "target",
					StopWords:      []string{"stop1", "stop2"},
				},
			},
		}

		domainMessage := rules.GitleaksRuleMessage{
			GitleaksRule: domainRule,
			Hash:         "test-hash",
		}

		// Test domain to proto conversion.
		protoMessage := GitleaksRulesMessageToProto(domainMessage)
		require.NotNil(t, protoMessage)
		assert.Equal(t, domainMessage.Hash, protoMessage.Hash)

		protoRule := protoMessage.Rule
		assert.Equal(t, domainRule.RuleID, protoRule.RuleId)
		assert.Equal(t, domainRule.Description, protoRule.Description)
		assert.Equal(t, float32(domainRule.Entropy), protoRule.Entropy)
		assert.Equal(t, int32(domainRule.SecretGroup), protoRule.SecretGroup)
		assert.Equal(t, domainRule.Regex, protoRule.Regex)
		assert.Equal(t, domainRule.Path, protoRule.Path)
		assert.Equal(t, domainRule.Tags, protoRule.Tags)
		assert.Equal(t, domainRule.Keywords, protoRule.Keywords)

		require.Len(t, protoRule.Allowlists, 1)
		protoAllowlist := protoRule.Allowlists[0]
		domainAllowlist := domainRule.Allowlists[0]
		assert.Equal(t, domainAllowlist.Description, protoAllowlist.Description)
		assert.Equal(t, pb.AllowlistMatchCondition_ALLOWLIST_MATCH_OR, protoAllowlist.MatchCondition)
		assert.Equal(t, domainAllowlist.Commits, protoAllowlist.Commits)
		assert.Equal(t, domainAllowlist.PathRegexes, protoAllowlist.PathRegexes)
		assert.Equal(t, domainAllowlist.Regexes, protoAllowlist.Regexes)
		assert.Equal(t, domainAllowlist.RegexTarget, protoAllowlist.RegexTarget)
		assert.Equal(t, domainAllowlist.StopWords, protoAllowlist.StopWords)

		// Test proto to domain conversion.
		convertedMessage := ProtoToGitleaksRuleMessage(protoMessage)
		assert.Equal(t, domainMessage.Hash, convertedMessage.Hash)
		assert.Equal(t, domainRule.RuleID, convertedMessage.GitleaksRule.RuleID)
		assert.Equal(t, domainRule.Description, convertedMessage.GitleaksRule.Description)
		assert.Equal(t, domainRule.Entropy, convertedMessage.GitleaksRule.Entropy)
		assert.Equal(t, domainRule.SecretGroup, convertedMessage.GitleaksRule.SecretGroup)
		assert.Equal(t, domainRule.Regex, convertedMessage.GitleaksRule.Regex)
		assert.Equal(t, domainRule.Path, convertedMessage.GitleaksRule.Path)
		assert.Equal(t, domainRule.Tags, convertedMessage.GitleaksRule.Tags)
		assert.Equal(t, domainRule.Keywords, convertedMessage.GitleaksRule.Keywords)

		require.Len(t, convertedMessage.GitleaksRule.Allowlists, 1)
		convertedAllowlist := convertedMessage.GitleaksRule.Allowlists[0]
		assert.Equal(t, domainAllowlist.Description, convertedAllowlist.Description)
		assert.Equal(t, domainAllowlist.MatchCondition, convertedAllowlist.MatchCondition)
		assert.Equal(t, domainAllowlist.Commits, convertedAllowlist.Commits)
		assert.Equal(t, domainAllowlist.PathRegexes, convertedAllowlist.PathRegexes)
		assert.Equal(t, domainAllowlist.Regexes, convertedAllowlist.Regexes)
		assert.Equal(t, domainAllowlist.RegexTarget, convertedAllowlist.RegexTarget)
		assert.Equal(t, domainAllowlist.StopWords, convertedAllowlist.StopWords)
	})
}

func TestAllowlistMatchConditionConversion(t *testing.T) {
	t.Run("valid condition conversions", func(t *testing.T) {
		testCases := []struct {
			name            string
			domainCondition rules.AllowlistMatchCondition
			protoCondition  pb.AllowlistMatchCondition
		}{
			{
				name:            "OR condition",
				domainCondition: rules.MatchConditionOR,
				protoCondition:  pb.AllowlistMatchCondition_ALLOWLIST_MATCH_OR,
			},
			{
				name:            "AND condition",
				domainCondition: rules.MatchConditionAND,
				protoCondition:  pb.AllowlistMatchCondition_ALLOWLIST_MATCH_AND,
			},
			{
				name:            "Unspecified condition",
				domainCondition: rules.MatchConditionUnspecified,
				protoCondition:  pb.AllowlistMatchCondition_ALLOWLIST_MATCH_CONDITION_UNSPECIFIED,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				protoCondition := conditionToProto(tc.domainCondition)
				assert.Equal(t, tc.protoCondition, protoCondition)

				domainCondition := protoToCondition(tc.protoCondition)
				assert.Equal(t, tc.domainCondition, domainCondition)
			})
		}
	})

	t.Run("invalid condition handling", func(t *testing.T) {
		// Test invalid domain condition converts to UNSPECIFIED proto condition.
		invalidDomainCondition := rules.AllowlistMatchCondition("INVALID")
		protoCondition := conditionToProto(invalidDomainCondition)
		assert.Equal(t, pb.AllowlistMatchCondition_ALLOWLIST_MATCH_CONDITION_UNSPECIFIED, protoCondition)

		// Test invalid proto condition converts to MatchConditionUnspecified.
		invalidProtoCondition := pb.AllowlistMatchCondition(-1)
		domainCondition := protoToCondition(invalidProtoCondition)
		assert.Equal(t, rules.MatchConditionUnspecified, domainCondition)
	})
}
