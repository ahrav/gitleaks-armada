package scanning

import (
	"encoding/json"
	"fmt"

	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
	serializationerrors "github.com/ahrav/gitleaks-armada/internal/infra/eventbus/serialization/errors"
	pb "github.com/ahrav/gitleaks-armada/proto"
	"github.com/google/uuid"
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
		JobId:      event.JobID,
		Timestamp:  event.OccurredAt().UnixNano(),
		TargetSpec: targetSpec,
	}, nil
}

// AuthToProto converts a domain Auth to its protobuf representation
func AuthToProto(auth scanning.Auth) (*pb.Auth, error) {
	configMap := make(map[string]any)
	for k, v := range auth.Credentials() {
		switch val := v.(type) {
		case string:
			configMap[k] = val
		case bool:
			configMap[k] = fmt.Sprintf("%v", val)
		case int:
			configMap[k] = fmt.Sprintf("%d", val)
		case float64:
			configMap[k] = fmt.Sprintf("%f", val)
		default:
			jsonBytes, err := json.Marshal(val)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal complex auth config value: %w", err)
			}
			configMap[k] = string(jsonBytes)
		}
	}

	return &pb.Auth{
		Type:        string(auth.Type()),
		Credentials: toProtoAny(configMap),
	}, nil
}

// ProtoToJobCreatedEvent converts a protobuf JobCreatedEvent to its domain representation
func ProtoToJobCreatedEvent(event *pb.JobCreatedEvent) (scanning.JobCreatedEvent, error) {
	if event == nil || event.TargetSpec == nil {
		return scanning.JobCreatedEvent{}, serializationerrors.ErrNilEvent{EventType: "JobCreatedEvent"}
	}

	target, err := ProtoToTarget(event.TargetSpec)
	if err != nil {
		return scanning.JobCreatedEvent{}, fmt.Errorf("convert proto to target: %w", err)
	}

	return scanning.NewJobCreatedEvent(event.JobId, target), nil
}

// ProtoToAuth converts a protobuf Auth to its domain representation
func ProtoToAuth(pbAuth *pb.Auth) (scanning.Auth, error) {
	if pbAuth == nil {
		return scanning.Auth{}, serializationerrors.ErrNilEvent{EventType: "Auth"}
	}

	configMap := make(map[string]any)
	for k, v := range pbAuth.Credentials {
		configMap[k] = v
	}

	return scanning.NewAuth(pbAuth.Type, configMap), nil
}
