package protobuf

import (
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/ahrav/gitleaks-armada/pkg/messaging"
	pb "github.com/ahrav/gitleaks-armada/proto/scanner"
)

// ScanResultToProto converts a ScanResult to its protobuf representation for wire transfer.
func ScanResultToProto(sr messaging.ScanResult) *pb.ScanResult {
	pbFindings := make([]*pb.Finding, 0, len(sr.Findings))
	for _, f := range sr.Findings {
		pbFindings = append(pbFindings, findingToProto(f))
	}

	return &pb.ScanResult{
		TaskId:   sr.TaskID,
		Findings: pbFindings,
		Status:   scanJobStatusToProto(sr.Status),
		Error:    sr.Error,
	}
}

// findingToProto converts a Finding to its protobuf representation.
func findingToProto(f messaging.Finding) *pb.Finding {
	var pbStruct *structpb.Struct
	if len(f.RawFinding) > 0 {
		pbStruct = structMapToProto(f.RawFinding)
	}

	return &pb.Finding{
		FilePath:    f.FilePath,
		LineNumber:  f.LineNumber,
		Line:        f.Line,
		Fingerprint: f.Fingerprint,
		Match:       f.Match,
		AuthorEmail: f.AuthorEmail,
		RawFinding:  pbStruct,
	}
}

// scanJobStatusToProto converts a domain ScanJobStatus to its protobuf enum equivalent.
func scanJobStatusToProto(ds messaging.ScanJobStatus) pb.ScanJobStatus {
	switch ds {
	case messaging.ScanJobStatusQueued:
		return pb.ScanJobStatus_SCAN_JOB_STATUS_QUEUED
	case messaging.ScanJobStatusRunning:
		return pb.ScanJobStatus_SCAN_JOB_STATUS_RUNNING
	case messaging.ScanJobStatusCompleted:
		return pb.ScanJobStatus_SCAN_JOB_STATUS_COMPLETED
	case messaging.ScanJobStatusFailed:
		return pb.ScanJobStatus_SCAN_JOB_STATUS_FAILED
	default:
		return pb.ScanJobStatus_SCAN_JOB_STATUS_UNSPECIFIED
	}
}

// structMapToProto converts a Go map to a protobuf Struct type.
// This allows arbitrary metadata to be serialized in the protobuf message.
func structMapToProto(m map[string]any) *structpb.Struct {
	pbStruct, err := structpb.NewStruct(m)
	if err != nil {
		// TODO: Handle error or log it.
	}
	return pbStruct
}

// ProtoToScanResult constructs a domain ScanResult from its protobuf representation.
// This enables receiving and processing scan results from the wire format.
func ProtoToScanResult(psr *pb.ScanResult) messaging.ScanResult {
	dFindings := make([]messaging.Finding, 0, len(psr.Findings))
	for _, pf := range psr.Findings {
		dFindings = append(dFindings, protoToFinding(pf))
	}

	return messaging.ScanResult{
		TaskID:   psr.TaskId,
		Findings: dFindings,
		Status:   protoToScanJobStatus(psr.Status),
		Error:    psr.Error,
	}
}

// protoToFinding converts a protobuf Finding message to its domain representation.
func protoToFinding(pf *pb.Finding) messaging.Finding {
	var raw map[string]any
	if pf.RawFinding != nil {
		raw = protoToStructMap(pf.RawFinding)
	}

	return messaging.Finding{
		FilePath:    pf.FilePath,
		LineNumber:  pf.LineNumber,
		Line:        pf.Line,
		Fingerprint: pf.Fingerprint,
		Match:       pf.Match,
		AuthorEmail: pf.AuthorEmail,
		RawFinding:  raw,
	}
}

// protoToScanJobStatus converts a protobuf scan status enum to its domain equivalent.
func protoToScanJobStatus(ps pb.ScanJobStatus) messaging.ScanJobStatus {
	switch ps {
	case pb.ScanJobStatus_SCAN_JOB_STATUS_QUEUED:
		return messaging.ScanJobStatusQueued
	case pb.ScanJobStatus_SCAN_JOB_STATUS_RUNNING:
		return messaging.ScanJobStatusRunning
	case pb.ScanJobStatus_SCAN_JOB_STATUS_COMPLETED:
		return messaging.ScanJobStatusCompleted
	case pb.ScanJobStatus_SCAN_JOB_STATUS_FAILED:
		return messaging.ScanJobStatusFailed
	default:
		return messaging.ScanJobStatusUnspecified
	}
}

// protoToStructMap converts a protobuf Struct to a Go map.
// This allows accessing arbitrary metadata from the protobuf message.
func protoToStructMap(s *structpb.Struct) map[string]any {
	if s == nil {
		return nil
	}
	return s.AsMap()
}

// GitleaksRulesMessageToProto converts a single rule message to its protobuf representation.
func GitleaksRulesMessageToProto(rm messaging.GitleaksRuleMessage) *pb.RuleMessage {
	return &pb.RuleMessage{
		Rule: ruleToProto(rm.Rule),
		Hash: rm.Hash,
	}
}

func ruleToProto(r messaging.GitleaksRule) *pb.Rule {
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

func allowlistsToProto(aws []messaging.GitleaksAllowlist) []*pb.Allowlist {
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

func conditionToProto(mc messaging.AllowlistMatchCondition) pb.AllowlistMatchCondition {
	switch mc {
	case messaging.MatchConditionOR:
		return pb.AllowlistMatchCondition_ALLOWLIST_MATCH_OR
	case messaging.MatchConditionAND:
		return pb.AllowlistMatchCondition_ALLOWLIST_MATCH_AND
	default:
		return pb.AllowlistMatchCondition_ALLOWLIST_MATCH_CONDITION_UNSPECIFIED
	}
}

func ProtoToGitleaksRuleMessage(pr *pb.RuleMessage) messaging.GitleaksRuleMessage {
	return messaging.GitleaksRuleMessage{
		Rule: protoToRule(pr.Rule),
		Hash: pr.Hash,
	}
}

func protoToRule(pr *pb.Rule) messaging.GitleaksRule {
	return messaging.GitleaksRule{
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

func protoToAllowlists(paws []*pb.Allowlist) []messaging.GitleaksAllowlist {
	aws := make([]messaging.GitleaksAllowlist, 0, len(paws))
	for _, pa := range paws {
		aws = append(aws, messaging.GitleaksAllowlist{
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

func protoToCondition(pc pb.AllowlistMatchCondition) messaging.AllowlistMatchCondition {
	switch pc {
	case pb.AllowlistMatchCondition_ALLOWLIST_MATCH_OR:
		return messaging.MatchConditionOR
	case pb.AllowlistMatchCondition_ALLOWLIST_MATCH_AND:
		return messaging.MatchConditionAND
	default:
		return messaging.MatchConditionUnspecified
	}
}
