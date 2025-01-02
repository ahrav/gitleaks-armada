// Package protobuf provides conversion functions between domain types and protobuf messages.
// It enables serialization of domain objects for network transport while maintaining
// a clean separation between internal types and wire formats.
package protobuf

import (
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/ahrav/gitleaks-armada/pkg/events/types"
	pb "github.com/ahrav/gitleaks-armada/proto/scanner"
)

// ToProto converts domain TaskCredentials to their protobuf representation for transmission.
// It handles mapping of supported credential types (GitHub, S3) while gracefully
// handling unsupported types by returning nil.
func ToProto(c *types.TaskCredentials) *pb.TaskCredentials {
	switch c.Type {
	case types.CredentialTypeGitHub:
		return &pb.TaskCredentials{
			Auth: &pb.TaskCredentials_Github{
				Github: &pb.GitHubCredentials{
					AuthToken: c.Values["auth_token"].(string),
				},
			},
		}
	case types.CredentialTypeS3:
		return &pb.TaskCredentials{
			Auth: &pb.TaskCredentials_S3{
				S3: &pb.S3Credentials{
					AccessKey:    c.Values["access_key"].(string),
					SecretKey:    c.Values["secret_key"].(string),
					SessionToken: c.Values["session_token"].(string),
				},
			},
		}
	default:
		return nil
	}
}

// ScanResultToProto converts a domain ScanResult to its protobuf representation.
// This enables serialization of scan findings and metadata for network transport.
func ScanResultToProto(sr types.ScanResult) *pb.ScanResult {
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

// findingToProto converts a domain Finding to its protobuf representation.
// It handles conversion of the raw finding data into a protobuf struct.
func findingToProto(f types.Finding) *pb.Finding {
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

// scanJobStatusToProto maps domain scan status values to their protobuf enum equivalents.
func scanJobStatusToProto(ds types.ScanJobStatus) pb.ScanJobStatus {
	switch ds {
	case types.ScanJobStatusQueued:
		return pb.ScanJobStatus_SCAN_JOB_STATUS_QUEUED
	case types.ScanJobStatusRunning:
		return pb.ScanJobStatus_SCAN_JOB_STATUS_RUNNING
	case types.ScanJobStatusCompleted:
		return pb.ScanJobStatus_SCAN_JOB_STATUS_COMPLETED
	case types.ScanJobStatusFailed:
		return pb.ScanJobStatus_SCAN_JOB_STATUS_FAILED
	default:
		return pb.ScanJobStatus_SCAN_JOB_STATUS_UNSPECIFIED
	}
}

// structMapToProto converts a Go map to a protobuf Struct.
// This enables serialization of arbitrary metadata in protobuf messages.
func structMapToProto(m map[string]any) *structpb.Struct {
	pbStruct, err := structpb.NewStruct(m)
	if err != nil {
		// TODO: Handle error or log it.
	}
	return pbStruct
}

// ProtoToScanResult converts a protobuf ScanResult message to its domain representation.
// This enables processing of scan results received over the network.
func ProtoToScanResult(psr *pb.ScanResult) types.ScanResult {
	dFindings := make([]types.Finding, 0, len(psr.Findings))
	for _, pf := range psr.Findings {
		dFindings = append(dFindings, protoToFinding(pf))
	}

	return types.ScanResult{
		TaskID:   psr.TaskId,
		Findings: dFindings,
		Status:   protoToScanJobStatus(psr.Status),
		Error:    psr.Error,
	}
}

// protoToFinding converts a protobuf Finding message to its domain representation.
func protoToFinding(pf *pb.Finding) types.Finding {
	var raw map[string]any
	if pf.RawFinding != nil {
		raw = protoToStructMap(pf.RawFinding)
	}

	return types.Finding{
		FilePath:    pf.FilePath,
		LineNumber:  pf.LineNumber,
		Line:        pf.Line,
		Fingerprint: pf.Fingerprint,
		Match:       pf.Match,
		AuthorEmail: pf.AuthorEmail,
		RawFinding:  raw,
	}
}

// protoToScanJobStatus maps protobuf scan status enums to their domain equivalents.
func protoToScanJobStatus(ps pb.ScanJobStatus) types.ScanJobStatus {
	switch ps {
	case pb.ScanJobStatus_SCAN_JOB_STATUS_QUEUED:
		return types.ScanJobStatusQueued
	case pb.ScanJobStatus_SCAN_JOB_STATUS_RUNNING:
		return types.ScanJobStatusRunning
	case pb.ScanJobStatus_SCAN_JOB_STATUS_COMPLETED:
		return types.ScanJobStatusCompleted
	case pb.ScanJobStatus_SCAN_JOB_STATUS_FAILED:
		return types.ScanJobStatusFailed
	default:
		return types.ScanJobStatusUnspecified
	}
}

// protoToStructMap converts a protobuf Struct to a Go map.
// This enables access to arbitrary metadata from received protobuf messages.
func protoToStructMap(s *structpb.Struct) map[string]any {
	if s == nil {
		return nil
	}
	return s.AsMap()
}

// GitleaksRulesMessageToProto converts a domain rule message to its protobuf representation.
// This enables transmission of Gitleaks rules configuration over the network.
func GitleaksRulesMessageToProto(rm types.GitleaksRuleMessage) *pb.RuleMessage {
	return &pb.RuleMessage{
		Rule: ruleToProto(rm.Rule),
		Hash: rm.Hash,
	}
}

// ruleToProto converts a domain Gitleaks rule to its protobuf representation.
func ruleToProto(r types.GitleaksRule) *pb.Rule {
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

// allowlistsToProto converts domain allowlists to their protobuf representation.
func allowlistsToProto(aws []types.GitleaksAllowlist) []*pb.Allowlist {
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

// conditionToProto maps domain match conditions to their protobuf enum equivalents.
func conditionToProto(mc types.AllowlistMatchCondition) pb.AllowlistMatchCondition {
	switch mc {
	case types.MatchConditionOR:
		return pb.AllowlistMatchCondition_ALLOWLIST_MATCH_OR
	case types.MatchConditionAND:
		return pb.AllowlistMatchCondition_ALLOWLIST_MATCH_AND
	default:
		return pb.AllowlistMatchCondition_ALLOWLIST_MATCH_CONDITION_UNSPECIFIED
	}
}

// ProtoToGitleaksRuleMessage converts a protobuf rule message to its domain representation.
// This enables processing of received Gitleaks rules configuration.
func ProtoToGitleaksRuleMessage(pr *pb.RuleMessage) types.GitleaksRuleMessage {
	return types.GitleaksRuleMessage{
		Rule: protoToRule(pr.Rule),
		Hash: pr.Hash,
	}
}

// protoToRule converts a protobuf Gitleaks rule to its domain representation.
func protoToRule(pr *pb.Rule) types.GitleaksRule {
	return types.GitleaksRule{
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

// protoToAllowlists converts protobuf allowlists to their domain representation.
func protoToAllowlists(paws []*pb.Allowlist) []types.GitleaksAllowlist {
	aws := make([]types.GitleaksAllowlist, 0, len(paws))
	for _, pa := range paws {
		aws = append(aws, types.GitleaksAllowlist{
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

// protoToCondition maps protobuf match condition enums to their domain equivalents.
func protoToCondition(pc pb.AllowlistMatchCondition) types.AllowlistMatchCondition {
	switch pc {
	case pb.AllowlistMatchCondition_ALLOWLIST_MATCH_OR:
		return types.MatchConditionOR
	case pb.AllowlistMatchCondition_ALLOWLIST_MATCH_AND:
		return types.MatchConditionAND
	default:
		return types.MatchConditionUnspecified
	}
}
