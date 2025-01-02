package protobuf

import (
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/ahrav/gitleaks-armada/pkg/domain"
	pb "github.com/ahrav/gitleaks-armada/proto/scanner"
)

// ScanResultToProto converts domain.ScanResult -> pb.ScanResult.
func ScanResultToProto(sr domain.ScanResult) *pb.ScanResult {
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

// findingToProto converts domain.Finding -> pb.Finding.
func findingToProto(f domain.Finding) *pb.Finding {
	var pbStruct *structpb.Struct
	if len(f.RawFinding) > 0 {
		pbStruct = structMapToProto(f.RawFinding)
	}

	return &pb.Finding{
		Fingerprint: f.Fingerprint,
		FilePath:    f.FilePath,
		LineNumber:  f.LineNumber,
		Line:        f.Line,
		Match:       f.Match,
		AuthorEmail: f.AuthorEmail,
		RawFinding:  pbStruct,
	}
}

// structMapToProto converts a Go map -> protobuf Struct.
func structMapToProto(m map[string]any) *structpb.Struct {
	s, err := structpb.NewStruct(m)
	if err != nil {
		// handle error, or log it
		return nil
	}
	return s
}

// scanJobStatusToProto maps domain scan status -> proto enum.
func scanJobStatusToProto(ds domain.ScanJobStatus) pb.ScanJobStatus {
	switch ds {
	case domain.ScanJobStatusQueued:
		return pb.ScanJobStatus_SCAN_JOB_STATUS_QUEUED
	case domain.ScanJobStatusRunning:
		return pb.ScanJobStatus_SCAN_JOB_STATUS_RUNNING
	case domain.ScanJobStatusCompleted:
		return pb.ScanJobStatus_SCAN_JOB_STATUS_COMPLETED
	case domain.ScanJobStatusFailed:
		return pb.ScanJobStatus_SCAN_JOB_STATUS_FAILED
	default:
		return pb.ScanJobStatus_SCAN_JOB_STATUS_UNSPECIFIED
	}
}

// ProtoToScanResult converts pb.ScanResult -> domain.ScanResult.
func ProtoToScanResult(psr *pb.ScanResult) domain.ScanResult {
	dFindings := make([]domain.Finding, 0, len(psr.Findings))
	for _, pf := range psr.Findings {
		dFindings = append(dFindings, protoToFinding(pf))
	}

	return domain.ScanResult{
		TaskID:   psr.TaskId,
		Findings: dFindings,
		Status:   protoToScanJobStatus(psr.Status),
		Error:    psr.Error,
	}
}

// protoToFinding converts pb.Finding -> domain.Finding.
func protoToFinding(pf *pb.Finding) domain.Finding {
	raw := protoToStructMap(pf.RawFinding)
	return domain.Finding{
		Fingerprint: pf.Fingerprint,
		FilePath:    pf.FilePath,
		LineNumber:  pf.LineNumber,
		Line:        pf.Line,
		Match:       pf.Match,
		AuthorEmail: pf.AuthorEmail,
		RawFinding:  raw,
	}
}

// protoToStructMap converts protobuf Struct -> Go map.
func protoToStructMap(s *structpb.Struct) map[string]any {
	if s == nil {
		return nil
	}
	return s.AsMap()
}

// protoToScanJobStatus maps proto enum -> domain.ScanJobStatus.
func protoToScanJobStatus(ps pb.ScanJobStatus) domain.ScanJobStatus {
	switch ps {
	case pb.ScanJobStatus_SCAN_JOB_STATUS_QUEUED:
		return domain.ScanJobStatusQueued
	case pb.ScanJobStatus_SCAN_JOB_STATUS_RUNNING:
		return domain.ScanJobStatusRunning
	case pb.ScanJobStatus_SCAN_JOB_STATUS_COMPLETED:
		return domain.ScanJobStatusCompleted
	case pb.ScanJobStatus_SCAN_JOB_STATUS_FAILED:
		return domain.ScanJobStatusFailed
	default:
		return domain.ScanJobStatusUnspecified
	}
}
