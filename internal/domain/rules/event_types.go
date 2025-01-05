package rules

// GitleaksRuleMessage represents a single rule and its metadata for transmission.
type GitleaksRuleMessage struct {
	GitleaksRule
	Hash string // Hash of this specific rule's content
}
