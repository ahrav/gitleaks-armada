package rules

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
)

// GitleaksRule is a representation of a Gitleaks rule.
type GitleaksRule struct {
	RuleID      string
	Description string
	Entropy     float64
	SecretGroup int
	Regex       string
	Path        string
	Tags        []string
	Keywords    []string
	Allowlists  []GitleaksAllowlist
}

type GitleaksAllowlist struct {
	Description    string
	MatchCondition AllowlistMatchCondition
	Commits        []string
	PathRegexes    []string
	Regexes        []string
	RegexTarget    string
	StopWords      []string
}

type AllowlistMatchCondition string

const (
	MatchConditionUnspecified AllowlistMatchCondition = "UNSPECIFIED"
	MatchConditionOR          AllowlistMatchCondition = "OR"
	MatchConditionAND         AllowlistMatchCondition = "AND"
)

// GitleaksRuleMessage represents a single rule and its metadata for transmission.
type GitleaksRuleMessage struct {
	Rule GitleaksRule
	Hash string // Hash of this specific rule's content
}

// GenerateHash generates a deterministic MD5 hash of the essential rule content.
func (r GitleaksRule) GenerateHash() string {
	h := md5.New()

	h.Write([]byte(r.RuleID))
	h.Write([]byte(r.Regex))
	h.Write([]byte(fmt.Sprintf("%f", r.Entropy)))

	// Include keywords and allowlists in the hash calculation to detect when these
	// components are modified. This ensures we can identify when a rule has been
	// updated with new keywords or allowlist entries, even if the core rule
	// properties remain unchanged.
	for _, keyword := range r.Keywords {
		h.Write([]byte(keyword))
	}

	for _, allowlist := range r.Allowlists {
		h.Write([]byte(allowlist.Description))
		h.Write([]byte(string(allowlist.MatchCondition)))

		for _, commit := range allowlist.Commits {
			h.Write([]byte(commit))
		}
		for _, pathRegex := range allowlist.PathRegexes {
			h.Write([]byte(pathRegex))
		}
		for _, regex := range allowlist.Regexes {
			h.Write([]byte(regex))
		}
		h.Write([]byte(allowlist.RegexTarget))
		for _, stopWord := range allowlist.StopWords {
			h.Write([]byte(stopWord))
		}
	}

	return hex.EncodeToString(h.Sum(nil))
}
