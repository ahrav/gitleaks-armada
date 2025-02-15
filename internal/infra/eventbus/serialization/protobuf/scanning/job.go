package scanning

import (
	"encoding/json"
	"fmt"

	"github.com/ahrav/gitleaks-armada/internal/config"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	serializationerrors "github.com/ahrav/gitleaks-armada/internal/infra/eventbus/serialization/errors"
	serdeConfig "github.com/ahrav/gitleaks-armada/internal/infra/eventbus/serialization/protobuf/config"
	pb "github.com/ahrav/gitleaks-armada/proto"
)

// JobCreatedEventToProto converts a domain JobCreatedEvent to its protobuf representation.
func JobCreatedEventToProto(event scanning.JobCreatedEvent) (*pb.JobCreatedEvent, error) {
	targetSpec, err := serdeConfig.TargetSpecToProto(event.TargetSpec)
	if err != nil {
		return nil, err
	}

	authConfig, err := AuthConfigToProto(event.AuthConfig)
	if err != nil {
		return nil, err
	}

	return &pb.JobCreatedEvent{
		JobId:      event.JobID,
		Timestamp:  event.OccurredAt().UnixNano(),
		TargetSpec: targetSpec,
		AuthConfig: authConfig,
	}, nil
}

// AuthConfigToProto converts a domain AuthConfig to its protobuf representation.
func AuthConfigToProto(cfg config.AuthConfig) (*pb.AuthConfig, error) {
	// Convert the generic map[string]any to map[string]string.
	configMap := make(map[string]string)
	for k, v := range cfg.Config {
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
			// TODO: Handle complex types.
			jsonBytes, err := json.Marshal(val)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal complex auth config value: %w", err)
			}
			configMap[k] = string(jsonBytes)
		}
	}

	return &pb.AuthConfig{
		Type:   cfg.Type,
		Config: configMap,
	}, nil
}

// ProtoToJobCreatedEvent converts a protobuf JobCreatedEvent to its domain representation.
func ProtoToJobCreatedEvent(event *pb.JobCreatedEvent) (scanning.JobCreatedEvent, error) {
	if event == nil {
		return scanning.JobCreatedEvent{}, serializationerrors.ErrNilEvent{EventType: "JobCreated"}
	}

	targetSpec, err := serdeConfig.ProtoToTargetSpec(event.TargetSpec)
	if err != nil {
		return scanning.JobCreatedEvent{}, err
	}

	authConfig, err := ProtoToAuthConfig(event.AuthConfig)
	if err != nil {
		return scanning.JobCreatedEvent{}, err
	}

	return scanning.NewJobCreatedEvent(event.JobId, targetSpec, authConfig), nil
}

// ProtoToAuthConfig converts a protobuf AuthConfig to its domain representation.
func ProtoToAuthConfig(pbAuth *pb.AuthConfig) (config.AuthConfig, error) {
	if pbAuth == nil {
		return config.AuthConfig{}, serializationerrors.ErrNilEvent{EventType: "AuthConfig"}
	}

	// Convert the string map back to map[string]any.
	configMap := make(map[string]any)
	for k, v := range pbAuth.Config {
		// TODO: Attempt to parse the string back into its original type.
		configMap[k] = v
	}

	return config.AuthConfig{
		Type:   pbAuth.Type,
		Config: configMap,
	}, nil
}
