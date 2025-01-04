package protobuf

import (
	"github.com/ahrav/gitleaks-armada/internal/domain/rules"
	pb "github.com/ahrav/gitleaks-armada/proto/scanner"
)

// GitleaksRulesMessageToProto converts domain.GitleaksRuleMessage -> pb.RuleMessage.
func GitleaksRulesMessageToProto(rm rules.GitleaksRuleMessage) *pb.RuleMessage {
	return &pb.RuleMessage{
		Rule: ruleToProto(rm.GitleaksRule),
		Hash: rm.Hash,
	}
}

// ruleToProto converts domain.GitleaksRule -> pb.Rule.
func ruleToProto(r rules.GitleaksRule) *pb.Rule {
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

// allowlistsToProto converts domain.GitleaksAllowlist -> pb.Allowlist.
func allowlistsToProto(aws []rules.GitleaksAllowlist) []*pb.Allowlist {
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

// conditionToProto maps domain enum -> pb enum.
func conditionToProto(mc rules.AllowlistMatchCondition) pb.AllowlistMatchCondition {
	switch mc {
	case rules.MatchConditionOR:
		return pb.AllowlistMatchCondition_ALLOWLIST_MATCH_OR
	case rules.MatchConditionAND:
		return pb.AllowlistMatchCondition_ALLOWLIST_MATCH_AND
	default:
		return pb.AllowlistMatchCondition_ALLOWLIST_MATCH_CONDITION_UNSPECIFIED
	}
}

// ProtoToGitleaksRuleMessage converts pb.RuleMessage -> domain.GitleaksRuleMessage.
func ProtoToGitleaksRuleMessage(pr *pb.RuleMessage) rules.GitleaksRuleMessage {
	return rules.GitleaksRuleMessage{
		GitleaksRule: protoToRule(pr.Rule),
		Hash:         pr.Hash,
	}
}

func protoToRule(pr *pb.Rule) rules.GitleaksRule {
	return rules.GitleaksRule{
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

func protoToAllowlists(pl []*pb.Allowlist) []rules.GitleaksAllowlist {
	out := make([]rules.GitleaksAllowlist, 0, len(pl))
	for _, pa := range pl {
		out = append(out, rules.GitleaksAllowlist{
			Description:    pa.Description,
			MatchCondition: protoToCondition(pa.MatchCondition),
			Commits:        pa.Commits,
			PathRegexes:    pa.PathRegexes,
			Regexes:        pa.Regexes,
			RegexTarget:    pa.RegexTarget,
			StopWords:      pa.StopWords,
		})
	}
	return out
}

func protoToCondition(pc pb.AllowlistMatchCondition) rules.AllowlistMatchCondition {
	switch pc {
	case pb.AllowlistMatchCondition_ALLOWLIST_MATCH_OR:
		return rules.MatchConditionOR
	case pb.AllowlistMatchCondition_ALLOWLIST_MATCH_AND:
		return rules.MatchConditionAND
	default:
		return rules.MatchConditionUnspecified
	}
}
