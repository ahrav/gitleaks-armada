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
	pbTargets := make([]*pb.TargetSpec, 0, len(event.Targets))
	for _, target := range event.Targets {
		pbTarget, err := TargetToProto(target)
		if err != nil {
			return nil, fmt.Errorf("convert target to proto: %w", err)
		}
		pbTargets = append(pbTargets, pbTarget)
	}

	return &pb.JobRequestedEvent{
		EventId:     event.EventID(),
		OccurredAt:  event.OccurredAt().UnixNano(),
		Targets:     pbTargets,
		RequestedBy: event.RequestedBy,
	}, nil
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
		targets,
		event.RequestedBy,
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

// TargetToProto converts a domain Target to its protobuf representation
func TargetToProto(target scanning.Target) (*pb.TargetSpec, error) {
	var pbAuth *pb.Auth
	if target.HasAuth() {
		pbAuth = &pb.Auth{
			Type:        string(target.Auth().Type()),
			Credentials: toProtoAny(target.Auth().Credentials()),
		}
	}

	return &pb.TargetSpec{
		Name:       target.Name(),
		SourceType: pb.SourceType(target.SourceType()),
		Auth:       pbAuth,
		Metadata:   target.Metadata(),
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

	return scanning.NewTarget(
		pbTarget.Name,
		shared.SourceType(pbTarget.SourceType),
		auth,
		pbTarget.Metadata,
	), nil
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

// Helper functions for value conversion
// func toProtoAny(m map[string]any) map[string]*structpb.Value {
// 	if m == nil {
// 		return nil
// 	}

// 	result := make(map[string]*structpb.Value, len(m))
// 	for k, v := range m {
// 		val, err := structpb.NewValue(v)
// 		if err != nil {
// 			// If we can't convert directly, try JSON marshaling
// 			b, err := json.Marshal(v)
// 			if err != nil {
// 				continue // Skip this value if we can't marshal it
// 			}
// 			val = structpb.NewStringValue(string(b))
// 		}
// 		result[k] = val
// 	}
// 	return result
// }

// func fromProtoAny(m map[string]*structpb.Value) map[string]any {
// 	if m == nil {
// 		return nil
// 	}

// 	result := make(map[string]any, len(m))
// 	for k, v := range m {
// 		if v == nil {
// 			continue
// 		}

// 		switch v.Kind.(type) {
// 		case *structpb.Value_StringValue,
// 			*structpb.Value_NumberValue,
// 			*structpb.Value_BoolValue:
// 			result[k] = v.AsInterface()
// 		case *structpb.Value_StructValue:
// 			if s := v.GetStructValue(); s != nil {
// 				result[k] = s.AsMap()
// 			}
// 		case *structpb.Value_ListValue:
// 			if l := v.GetListValue(); l != nil {
// 				var arr []any
// 				for _, item := range l.Values {
// 					arr = append(arr, item.AsInterface())
// 				}
// 				result[k] = arr
// 			}
// 		default:
// 			if str := v.GetStringValue(); str != "" {
// 				var val any
// 				if err := json.Unmarshal([]byte(str), &val); err == nil {
// 					result[k] = val
// 				}
// 			}
// 		}
// 	}
// 	return result
// }
