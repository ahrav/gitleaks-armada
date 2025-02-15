package scanning

import (
	"encoding/json"
	"fmt"

	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
	serializationerrors "github.com/ahrav/gitleaks-armada/internal/infra/eventbus/serialization/errors"
	pb "github.com/ahrav/gitleaks-armada/proto"
)

// JobRequestedEventToProto converts a domain JobRequestedEvent to its protobuf representation
func JobRequestedEventToProto(event scanning.JobRequestedEvent) (*pb.JobRequestedEvent, error) {
	// Convert targets to proto
	pbTargets := make([]*pb.TargetSpec, 0, len(event.Targets))
	for _, target := range event.Targets {
		pbTarget, err := TargetToProto(target)
		if err != nil {
			return nil, fmt.Errorf("convert target to proto: %w", err)
		}
		pbTargets = append(pbTargets, pbTarget)
	}

	// Convert auth map to proto
	pbAuth := make(map[string]*pb.AuthConfig)
	for key, auth := range event.Auth {
		pbAuthConfig, err := AuthToProto(auth)
		if err != nil {
			return nil, fmt.Errorf("convert auth to proto: %w", err)
		}
		pbAuth[key] = pbAuthConfig
	}

	return &pb.JobRequestedEvent{
		EventId:     event.EventID(),
		OccurredAt:  event.OccurredAt().UnixNano(),
		Targets:     pbTargets,
		Auth:        pbAuth,
		RequestedBy: event.RequestedBy,
	}, nil
}

// ProtoToJobRequestedEvent converts a protobuf JobRequestedEvent to its domain representation
func ProtoToJobRequestedEvent(event *pb.JobRequestedEvent) (scanning.JobRequestedEvent, error) {
	if event == nil {
		return scanning.JobRequestedEvent{}, serializationerrors.ErrNilEvent{EventType: "JobRequestedEvent"}
	}

	// Convert proto targets to domain
	targets := make([]scanning.Target, 0, len(event.Targets))
	for _, pbTarget := range event.Targets {
		target, err := ProtoToTarget(pbTarget)
		if err != nil {
			return scanning.JobRequestedEvent{}, fmt.Errorf("convert proto to target: %w", err)
		}
		targets = append(targets, target)
	}

	// Convert proto auth to domain
	auth := make(map[string]scanning.Auth)
	for key, pbAuth := range event.Auth {
		authConfig, err := ProtoToAuth(pbAuth)
		if err != nil {
			return scanning.JobRequestedEvent{}, fmt.Errorf("convert proto to auth: %w", err)
		}
		auth[key] = authConfig
	}

	return scanning.NewJobRequestedEvent(
		targets,
		auth,
		event.RequestedBy,
	), nil
}

// JobCreatedEventToProto converts a domain JobCreatedEvent to its protobuf representation.
func JobCreatedEventToProto(event scanning.JobCreatedEvent) (*pb.JobCreatedEvent, error) {
	targetSpec, err := TargetToProto(event.Target)
	if err != nil {
		return nil, fmt.Errorf("convert target to proto: %w", err)
	}

	authConfig, err := AuthToProto(event.Auth)
	if err != nil {
		return nil, fmt.Errorf("convert auth to proto: %w", err)
	}

	return &pb.JobCreatedEvent{
		JobId:      event.JobID,
		Timestamp:  event.OccurredAt().UnixNano(),
		TargetSpec: targetSpec,
		AuthConfig: authConfig,
	}, nil
}

// TargetToProto converts a domain Target to its protobuf representation
func TargetToProto(target scanning.Target) (*pb.TargetSpec, error) {
	return &pb.TargetSpec{
		Name:       target.Name(),
		SourceType: pb.SourceType(target.SourceType()),
		AuthRef:    target.AuthID(),
		Metadata:   target.Metadata(),
	}, nil
}

// AuthToProto converts a domain Auth to its protobuf representation
func AuthToProto(auth scanning.Auth) (*pb.AuthConfig, error) {
	configMap := make(map[string]string)
	for k, v := range auth.Config() {
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

	return &pb.AuthConfig{
		Type:   auth.Type(),
		Config: configMap,
	}, nil
}

// ProtoToJobCreatedEvent converts a protobuf JobCreatedEvent to its domain representation
func ProtoToJobCreatedEvent(event *pb.JobCreatedEvent) (scanning.JobCreatedEvent, error) {
	if event == nil {
		return scanning.JobCreatedEvent{}, serializationerrors.ErrNilEvent{EventType: "JobCreatedEvent"}
	}

	target, err := ProtoToTarget(event.TargetSpec)
	if err != nil {
		return scanning.JobCreatedEvent{}, fmt.Errorf("convert proto to target: %w", err)
	}

	auth, err := ProtoToAuth(event.AuthConfig)
	if err != nil {
		return scanning.JobCreatedEvent{}, fmt.Errorf("convert proto to auth: %w", err)
	}

	return scanning.NewJobCreatedEvent(event.JobId, target, auth), nil
}

// ProtoToTarget converts a protobuf TargetSpec to its domain representation
func ProtoToTarget(pbTarget *pb.TargetSpec) (scanning.Target, error) {
	if pbTarget == nil {
		return scanning.Target{}, serializationerrors.ErrNilEvent{EventType: "TargetSpec"}
	}

	return scanning.NewTarget(
		pbTarget.Name,
		shared.SourceType(pbTarget.SourceType),
		pbTarget.AuthRef,
		pbTarget.Metadata,
	), nil
}

// ProtoToAuth converts a protobuf AuthConfig to its domain representation
func ProtoToAuth(pbAuth *pb.AuthConfig) (scanning.Auth, error) {
	if pbAuth == nil {
		return scanning.Auth{}, serializationerrors.ErrNilEvent{EventType: "AuthConfig"}
	}

	configMap := make(map[string]any)
	for k, v := range pbAuth.Config {
		configMap[k] = v // Keep as string for now, could add type inference if needed
	}

	return scanning.NewAuth(pbAuth.Type, configMap), nil
}
