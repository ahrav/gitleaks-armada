package rules

// AllowlistMatchCondition defines how multiple conditions in an allowlist should be combined.
// It determines whether conditions are evaluated with logical OR or AND operations.
type AllowlistMatchCondition string

const (
	// MatchConditionUnspecified indicates no match condition was explicitly set.
	// This helps identify cases where the condition needs to be determined by context.
	MatchConditionUnspecified AllowlistMatchCondition = "UNSPECIFIED"

	// MatchConditionOR indicates conditions should be combined with logical OR.
	// Any single matching condition will result in an allowlist match.
	MatchConditionOR AllowlistMatchCondition = "OR"

	// MatchConditionAND indicates conditions should be combined with logical AND.
	// All conditions must match for an allowlist match to occur.
	MatchConditionAND AllowlistMatchCondition = "AND"
)

// GitleaksAllowlist defines criteria for excluding matches from Gitleaks scanning results.
// It provides multiple ways to identify false positives and intentionally shared secrets.
type GitleaksAllowlist struct {
	// Description explains the purpose of this allowlist entry.
	Description string
	// MatchCondition determines how multiple conditions are combined.
	MatchCondition AllowlistMatchCondition
	// Commits lists specific commit hashes to exclude from scanning.
	Commits []string
	// PathRegexes contains patterns matching file paths to exclude.
	PathRegexes []string
	// Regexes defines patterns to match against the secret content itself.
	Regexes []string
	// RegexTarget specifies which part of the finding to apply regex matches against.
	RegexTarget string
	// StopWords lists exact phrases that indicate a match should be ignored.
	StopWords []string
}
