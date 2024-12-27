package messaging

import (
	"google.golang.org/protobuf/types/known/structpb"

	pb "github.com/ahrav/gitleaks-armada/proto/scanner"
)

// ScanJobStatus represents the current state of a scan job in the system.
// It is used to track the lifecycle of a scan from queuing through completion.
type ScanJobStatus string

const (
	// ScanJobStatusUnspecified indicates an invalid or unknown status.
	ScanJobStatusUnspecified ScanJobStatus = "UNSPECIFIED"
	// ScanJobStatusQueued indicates the scan is waiting to be processed.
	ScanJobStatusQueued ScanJobStatus = "QUEUED"
	// ScanJobStatusRunning indicates the scan is actively being processed.
	ScanJobStatusRunning ScanJobStatus = "RUNNING"
	// ScanJobStatusCompleted indicates the scan finished successfully.
	ScanJobStatusCompleted ScanJobStatus = "COMPLETED"
	// ScanJobStatusFailed indicates the scan encountered an error.
	ScanJobStatusFailed ScanJobStatus = "FAILED"
)

// Finding represents a single secret or sensitive data match discovered during a scan.
// It contains the location and context of the finding to help users investigate and remediate.
type Finding struct {
	FilePath    string
	LineNumber  int32
	Line        string
	Fingerprint string // Unique identifier for deduplication
	Match       string
	AuthorEmail string

	// RawFinding contains scan-specific metadata like commit hash and commit message.
	// It uses a generic map to allow flexible storage of different finding types.
	RawFinding map[string]any
}

// ScanResult encapsulates the complete results of a scan operation.
// It includes any findings discovered and the final status of the scan.
type ScanResult struct {
	TaskID   string
	Findings []Finding
	Status   ScanJobStatus
	Error    string // Contains error details when Status is Failed
}

// ToProto converts a ScanResult to its protobuf representation for wire transfer.
func (sr ScanResult) ToProto() *pb.ScanResult {
	pbFindings := make([]*pb.Finding, 0, len(sr.Findings))
	for _, f := range sr.Findings {
		pbFindings = append(pbFindings, f.toProto())
	}

	return &pb.ScanResult{
		TaskId:   sr.TaskID,
		Findings: pbFindings,
		Status:   scanJobStatusToProto(sr.Status),
		Error:    sr.Error,
	}
}

// toProto converts a Finding to its protobuf representation.
func (f Finding) toProto() *pb.Finding {
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
func scanJobStatusToProto(ds ScanJobStatus) pb.ScanJobStatus {
	switch ds {
	case ScanJobStatusQueued:
		return pb.ScanJobStatus_SCAN_JOB_STATUS_QUEUED
	case ScanJobStatusRunning:
		return pb.ScanJobStatus_SCAN_JOB_STATUS_RUNNING
	case ScanJobStatusCompleted:
		return pb.ScanJobStatus_SCAN_JOB_STATUS_COMPLETED
	case ScanJobStatusFailed:
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
func ProtoToScanResult(psr *pb.ScanResult) ScanResult {
	dFindings := make([]Finding, 0, len(psr.Findings))
	for _, pf := range psr.Findings {
		dFindings = append(dFindings, protoToFinding(pf))
	}

	return ScanResult{
		TaskID:   psr.TaskId,
		Findings: dFindings,
		Status:   protoToScanJobStatus(psr.Status),
		Error:    psr.Error,
	}
}

// protoToFinding converts a protobuf Finding message to its domain representation.
func protoToFinding(pf *pb.Finding) Finding {
	var raw map[string]any
	if pf.RawFinding != nil {
		raw = protoToStructMap(pf.RawFinding)
	}

	return Finding{
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
func protoToScanJobStatus(ps pb.ScanJobStatus) ScanJobStatus {
	switch ps {
	case pb.ScanJobStatus_SCAN_JOB_STATUS_QUEUED:
		return ScanJobStatusQueued
	case pb.ScanJobStatus_SCAN_JOB_STATUS_RUNNING:
		return ScanJobStatusRunning
	case pb.ScanJobStatus_SCAN_JOB_STATUS_COMPLETED:
		return ScanJobStatusCompleted
	case pb.ScanJobStatus_SCAN_JOB_STATUS_FAILED:
		return ScanJobStatusFailed
	default:
		return ScanJobStatusUnspecified
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
