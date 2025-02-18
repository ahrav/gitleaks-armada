package scanning

import (
	"fmt"

	"github.com/google/uuid"

	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
	serializationerrors "github.com/ahrav/gitleaks-armada/internal/infra/eventbus/serialization/errors"
	pb "github.com/ahrav/gitleaks-armada/proto"
)

// JobRequestedEventToProto converts a domain JobRequestedEvent to its protobuf representation
func JobRequestedEventToProto(event scanning.JobRequestedEvent) (*pb.JobRequestedEvent, error) {
	pbTargets := make([]*pb.TargetSpec, 0, len(event.Targets))
	for _, target := range event.Targets {

		pbTarget, err := TargetToProto(target)
		if err != nil {
			return nil, fmt.Errorf("convert target to proto: %w", err)
		}

		pbTargets = append(pbTargets, pbTarget)
	}

	return &pb.JobRequestedEvent{
		JobId:       event.JobID().String(),
		OccurredAt:  event.OccurredAt().UnixNano(),
		Targets:     pbTargets,
		RequestedBy: event.RequestedBy,
	}, nil
}

// TargetToProto converts a domain Target to its protobuf representation
func TargetToProto(target scanning.Target) (*pb.TargetSpec, error) {
	var pbAuth *pb.Auth
	if target.HasAuth() {
		pbAuth = &pb.Auth{
			Type:        string(target.Auth().Type()),
			Credentials: toProtoAny(target.Auth().Credentials()),
		}
	}

	pbTarget := &pb.TargetSpec{
		Name:       target.Name(),
		SourceType: pb.SourceType(target.SourceType()),
		Auth:       pbAuth,
		Metadata:   target.Metadata(),
	}

	// Add source-specific configuration
	switch target.SourceType() {
	case shared.SourceTypeGitHub:
		if gh := target.GitHub(); gh != nil {
			pbTarget.Target = &pb.TargetSpec_Github{
				Github: &pb.GitHubTarget{
					Org:      gh.Org(),
					RepoList: gh.RepoList(),
				},
			}
		}
	case shared.SourceTypeS3:
		if s3 := target.S3(); s3 != nil {
			pbTarget.Target = &pb.TargetSpec_S3{
				S3: &pb.S3Target{
					Bucket: s3.Bucket(),
					Prefix: s3.Prefix(),
					Region: s3.Region(),
				},
			}
		}
	case shared.SourceTypeURL:
		if url := target.URL(); url != nil {
			pbTarget.Target = &pb.TargetSpec_Url{
				Url: &pb.URLTarget{
					Urls: url.URLs(),
				},
			}
		}
	}

	return pbTarget, nil
}

// ProtoToJobRequestedEvent converts a protobuf JobRequestedEvent to its domain representation
func ProtoToJobRequestedEvent(event *pb.JobRequestedEvent) (scanning.JobRequestedEvent, error) {
	if event == nil || len(event.Targets) == 0 {
		return scanning.JobRequestedEvent{}, serializationerrors.ErrNilEvent{EventType: "JobRequestedEvent"}
	}

	targets := make([]scanning.Target, 0, len(event.Targets))
	for _, pbTarget := range event.Targets {

		target, err := ProtoToTarget(pbTarget)
		if err != nil {
			return scanning.JobRequestedEvent{}, fmt.Errorf("convert proto to target: %w", err)
		}

		targets = append(targets, target)
	}

	return scanning.NewJobRequestedEvent(
		uuid.MustParse(event.JobId),
		targets,
		event.RequestedBy,
	), nil
}

// ProtoToTarget converts a protobuf TargetSpec to its domain representation
func ProtoToTarget(pbTarget *pb.TargetSpec) (scanning.Target, error) {
	if pbTarget == nil {
		return scanning.Target{}, serializationerrors.ErrNilEvent{EventType: "TargetSpec"}
	}

	var auth *scanning.Auth
	if pbTarget.Auth != nil {
		domainAuth := scanning.NewAuth(
			pbTarget.Auth.Type,
			fromProtoAny(pbTarget.Auth.Credentials),
		)
		auth = &domainAuth
	}

	var config scanning.TargetConfig

	// Convert source-specific configuration
	switch t := pbTarget.Target.(type) {
	case *pb.TargetSpec_Github:
		if t.Github != nil {
			config.GitHub = scanning.NewGitHubTarget(
				t.Github.Org,
				t.Github.RepoList,
			)
		}
	case *pb.TargetSpec_S3:
		if t.S3 != nil {
			config.S3 = scanning.NewS3Target(
				t.S3.Bucket,
				t.S3.Prefix,
				t.S3.Region,
			)
		}
	case *pb.TargetSpec_Url:
		if t.Url != nil {
			config.URL = scanning.NewURLTarget(
				t.Url.Urls,
			)
		}
	}

	return scanning.NewTarget(
		pbTarget.Name,
		shared.SourceType(pbTarget.SourceType),
		auth,
		pbTarget.Metadata,
		config,
	), nil
}

// JobCreatedEventToProto converts a domain JobCreatedEvent to its protobuf representation.
func JobCreatedEventToProto(event scanning.JobCreatedEvent) (*pb.JobCreatedEvent, error) {
	targetSpec, err := TargetToProto(event.Target)
	if err != nil {
		return nil, fmt.Errorf("convert target to proto: %w", err)
	}

	return &pb.JobCreatedEvent{
		JobId:      event.Job.JobID().String(),
		Timestamp:  event.OccurredAt().UnixNano(),
		TargetSpec: targetSpec,
		Status:     jobStatusToProto(event.Job.Status()),
	}, nil
}

// jobStatusToProto converts a domain JobStatus to its protobuf representation.
func jobStatusToProto(s scanning.JobStatus) pb.ScanJobStatus {
	switch s {
	case scanning.JobStatusQueued:
		return pb.ScanJobStatus_SCAN_JOB_STATUS_QUEUED
	case scanning.JobStatusEnumerating:
		return pb.ScanJobStatus_SCAN_JOB_STATUS_ENUMERATING
	case scanning.JobStatusRunning:
		return pb.ScanJobStatus_SCAN_JOB_STATUS_RUNNING
	case scanning.JobStatusCompleted:
		return pb.ScanJobStatus_SCAN_JOB_STATUS_COMPLETED
	case scanning.JobStatusFailed:
		return pb.ScanJobStatus_SCAN_JOB_STATUS_FAILED
	default:
		return pb.ScanJobStatus_SCAN_JOB_STATUS_UNSPECIFIED
	}
}

// ProtoToJobCreatedEvent converts a protobuf JobCreatedEvent to its domain representation.
func ProtoToJobCreatedEvent(event *pb.JobCreatedEvent) (scanning.JobCreatedEvent, error) {
	if event == nil || event.TargetSpec == nil {
		return scanning.JobCreatedEvent{}, serializationerrors.ErrNilEvent{EventType: "JobCreatedEvent"}
	}

	target, err := ProtoToTarget(event.TargetSpec)
	if err != nil {
		return scanning.JobCreatedEvent{}, fmt.Errorf("convert proto to target: %w", err)
	}

	job := scanning.NewJobWithStatus(uuid.MustParse(event.JobId), protoToJobStatus(event.Status))
	return scanning.NewJobCreatedEvent(job, target), nil
}

// JobEnumerationCompletedEventToProto converts a domain JobEnumerationCompletedEvent to its protobuf representation.
func JobEnumerationCompletedEventToProto(event scanning.JobEnumerationCompletedEvent) *pb.JobEnumerationCompletedEvent {
	return &pb.JobEnumerationCompletedEvent{
		JobId:      event.JobID.String(),
		Timestamp:  event.OccurredAt().UnixNano(),
		TotalTasks: int32(event.TotalTasks),
	}
}

// ProtoToJobEnumerationCompletedEvent converts a protobuf JobEnumerationCompletedEvent to its domain representation.
func ProtoToJobEnumerationCompletedEvent(event *pb.JobEnumerationCompletedEvent) (scanning.JobEnumerationCompletedEvent, error) {
	if event == nil {
		return scanning.JobEnumerationCompletedEvent{}, serializationerrors.ErrNilEvent{EventType: "JobEnumerationCompletedEvent"}
	}

	jobID, err := uuid.Parse(event.JobId)
	if err != nil {
		return scanning.JobEnumerationCompletedEvent{}, fmt.Errorf("parse job ID: %w", err)
	}

	return scanning.NewJobEnumerationCompletedEvent(
		jobID,
		int(event.TotalTasks),
	), nil
}

// protoToJobStatus converts a protobuf ScanJobStatus to its domain representation.
func protoToJobStatus(s pb.ScanJobStatus) scanning.JobStatus {
	switch s {
	case pb.ScanJobStatus_SCAN_JOB_STATUS_QUEUED:
		return scanning.JobStatusQueued
	case pb.ScanJobStatus_SCAN_JOB_STATUS_ENUMERATING:
		return scanning.JobStatusEnumerating
	case pb.ScanJobStatus_SCAN_JOB_STATUS_RUNNING:
		return scanning.JobStatusRunning
	case pb.ScanJobStatus_SCAN_JOB_STATUS_COMPLETED:
		return scanning.JobStatusCompleted
	case pb.ScanJobStatus_SCAN_JOB_STATUS_FAILED:
		return scanning.JobStatusFailed
	default:
		return "" // represents unspecified
	}
}
