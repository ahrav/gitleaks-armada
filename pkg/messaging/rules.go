package messaging

import pb "github.com/ahrav/gitleaks-armada/proto/scanner"

// GitleaksRule is your domain representation of a scanning rule.
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

// GitleaksRuleSet is a container for multiple GitleaksRule.
type GitleaksRuleSet struct {
	Rules []GitleaksRule
}

func (rs GitleaksRuleSet) ToProto() *pb.RuleSet {
	protoRules := make([]*pb.Rule, 0, len(rs.Rules))
	for _, r := range rs.Rules {
		protoRules = append(protoRules, ruleToProto(r))
	}
	return &pb.RuleSet{Rules: protoRules}
}

func ruleToProto(r GitleaksRule) *pb.Rule {
	return &pb.Rule{
		RuleId:      r.RuleID,
		Description: r.Description,
		Entropy:     float32(r.Entropy),
		SecretGroup: int32(r.SecretGroup),
		Regex:       r.Regex,
		Path:        r.Path,
		Tags:        r.Tags,
		Keywords:    r.Keywords,
		Allowlists:  allowlistsToProto(r.Allowlists),
	}
}

func allowlistsToProto(aws []GitleaksAllowlist) []*pb.Allowlist {
	protoAws := make([]*pb.Allowlist, 0, len(aws))
	for _, a := range aws {
		protoAws = append(protoAws, &pb.Allowlist{
			Description:    a.Description,
			MatchCondition: conditionToProto(a.MatchCondition),
			Commits:        a.Commits,
			PathRegexes:    a.PathRegexes,
			Regexes:        a.Regexes,
			RegexTarget:    a.RegexTarget,
			StopWords:      a.StopWords,
		})
	}
	return protoAws
}

func conditionToProto(mc AllowlistMatchCondition) pb.AllowlistMatchCondition {
	switch mc {
	case MatchConditionOR:
		return pb.AllowlistMatchCondition_ALLOWLIST_MATCH_OR
	case MatchConditionAND:
		return pb.AllowlistMatchCondition_ALLOWLIST_MATCH_AND
	default:
		return pb.AllowlistMatchCondition_ALLOWLIST_MATCH_CONDITION_UNSPECIFIED
	}
}

func ProtoToGitleaksRuleSet(rs *pb.RuleSet) GitleaksRuleSet {
	rules := make([]GitleaksRule, 0, len(rs.Rules))
	for _, pr := range rs.Rules {
		rules = append(rules, protoToRule(pr))
	}
	return GitleaksRuleSet{Rules: rules}
}

func protoToRule(pr *pb.Rule) GitleaksRule {
	return GitleaksRule{
		RuleID:      pr.RuleId,
		Description: pr.Description,
		Entropy:     float64(pr.Entropy),
		SecretGroup: int(pr.SecretGroup),
		Regex:       pr.Regex,
		Path:        pr.Path,
		Tags:        pr.Tags,
		Keywords:    pr.Keywords,
		Allowlists:  protoToAllowlists(pr.Allowlists),
	}
}

func protoToAllowlists(paws []*pb.Allowlist) []GitleaksAllowlist {
	aws := make([]GitleaksAllowlist, 0, len(paws))
	for _, pa := range paws {
		aws = append(aws, GitleaksAllowlist{
			Description:    pa.Description,
			MatchCondition: protoToCondition(pa.MatchCondition),
			Commits:        pa.Commits,
			PathRegexes:    pa.PathRegexes,
			Regexes:        pa.Regexes,
			RegexTarget:    pa.RegexTarget,
			StopWords:      pa.StopWords,
		})
	}
	return aws
}

func protoToCondition(pc pb.AllowlistMatchCondition) AllowlistMatchCondition {
	switch pc {
	case pb.AllowlistMatchCondition_ALLOWLIST_MATCH_OR:
		return MatchConditionOR
	case pb.AllowlistMatchCondition_ALLOWLIST_MATCH_AND:
		return MatchConditionAND
	default:
		return MatchConditionUnspecified
	}
}
