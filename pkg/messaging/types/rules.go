package messaging

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"

	pb "github.com/ahrav/gitleaks-armada/proto/scanner"
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

// ToProto converts a single rule message to its protobuf representation.
func (rm GitleaksRuleMessage) ToProto() *pb.RuleMessage {
	return &pb.RuleMessage{
		Rule: ruleToProto(rm.Rule),
		Hash: rm.Hash,
	}
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

func ProtoToGitleaksRuleMessage(pr *pb.RuleMessage) GitleaksRuleMessage {
	return GitleaksRuleMessage{
		Rule: protoToRule(pr.Rule),
		Hash: pr.Hash,
	}
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
