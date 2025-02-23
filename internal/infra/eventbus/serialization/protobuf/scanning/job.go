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
func JobCreatedEventToProto(event scanning.JobScheduledEvent) (*pb.JobCreatedEvent, error) {
	targetSpec, err := TargetToProto(event.Target)
	if err != nil {
		return nil, fmt.Errorf("convert target to proto: %w", err)
	}

	return &pb.JobCreatedEvent{
		JobId:      event.JobID.String(),
		Timestamp:  event.OccurredAt().UnixNano(),
		TargetSpec: targetSpec,
	}, nil
}

// ProtoToJobCreatedEvent converts a protobuf JobCreatedEvent to its domain representation.
func ProtoToJobCreatedEvent(event *pb.JobCreatedEvent) (scanning.JobScheduledEvent, error) {
	if event == nil || event.TargetSpec == nil {
		return scanning.JobScheduledEvent{}, serializationerrors.ErrNilEvent{EventType: "JobCreatedEvent"}
	}

	target, err := ProtoToTarget(event.TargetSpec)
	if err != nil {
		return scanning.JobScheduledEvent{}, fmt.Errorf("convert proto to target: %w", err)
	}

	return scanning.NewJobScheduledEvent(uuid.MustParse(event.JobId), target), nil
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

// JobPausingEventToProto converts a domain JobPausingEvent to its protobuf representation.
func JobPausingEventToProto(event scanning.JobPausingEvent) *pb.JobPausingEvent {
	return &pb.JobPausingEvent{
		JobId:       event.JobID,
		Timestamp:   event.OccurredAt().UnixNano(),
		RequestedBy: event.RequestedBy,
	}
}

// ProtoToJobPausingEvent converts a protobuf JobPausingEvent to its domain representation.
func ProtoToJobPausingEvent(event *pb.JobPausingEvent) (scanning.JobPausingEvent, error) {
	if event == nil {
		return scanning.JobPausingEvent{}, serializationerrors.ErrNilEvent{EventType: "JobPausingEvent"}
	}

	return scanning.NewJobPausingEvent(event.JobId, event.RequestedBy), nil
}

// JobPausedEventToProto converts a domain JobPausedEvent to its protobuf representation.
func JobPausedEventToProto(event scanning.JobPausedEvent) *pb.JobPausedEvent {
	return &pb.JobPausedEvent{
		JobId:       event.JobID,
		Timestamp:   event.OccurredAt().UnixNano(),
		PausedAt:    event.PausedAt.UnixNano(),
		Reason:      event.Reason,
		RequestedBy: event.RequestedBy,
	}
}

// ProtoToJobPausedEvent converts a protobuf JobPausedEvent to its domain representation.
func ProtoToJobPausedEvent(event *pb.JobPausedEvent) (scanning.JobPausedEvent, error) {
	if event == nil {
		return scanning.JobPausedEvent{}, serializationerrors.ErrNilEvent{EventType: "JobPausedEvent"}
	}

	return scanning.NewJobPausedEvent(event.JobId, event.RequestedBy, event.Reason), nil
}
