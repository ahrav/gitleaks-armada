package serialization

import (
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/ahrav/gitleaks-armada/internal/domain/enumeration"
	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/domain/rules"
	"github.com/ahrav/gitleaks-armada/internal/domain/task"
	"github.com/ahrav/gitleaks-armada/internal/infra/eventbus/serialization/protobuf"
	pb "github.com/ahrav/gitleaks-armada/proto/scanner"
)

// SerializeFunc converts a domain object into a serialized byte slice.
type SerializeFunc func(payload any) ([]byte, error)

// DeserializeFunc converts a serialized byte slice back into a domain object.
type DeserializeFunc func(data []byte) (any, error)

// Global registries map event types to their serialization functions.
// This allows for dynamic dispatch based on event type at runtime.
var (
	serializerRegistry   = map[events.EventType]SerializeFunc{}
	deserializerRegistry = map[events.EventType]DeserializeFunc{}
)

// RegisterSerializeFunc registers a serialization function for a given event type.
// This enables the system to properly encode domain objects when publishing events.
func RegisterSerializeFunc(eventType events.EventType, fn SerializeFunc) {
	serializerRegistry[eventType] = fn
}

// RegisterDeserializeFunc registers a deserialization function for a given event type.
// This enables the system to properly decode events back into domain objects when consuming them.
func RegisterDeserializeFunc(eventType events.EventType, fn DeserializeFunc) {
	deserializerRegistry[eventType] = fn
}

// SerializePayload converts a domain object into bytes using the registered serializer for its event type.
// Returns an error if no serializer is registered for the given event type.
func SerializePayload(eventType events.EventType, payload any) ([]byte, error) {
	fn, ok := serializerRegistry[eventType]
	if !ok {
		return nil, fmt.Errorf("no serializer registered for eventType=%s", eventType)
	}
	return fn(payload)
}

// DeserializePayload converts bytes back into a domain object using the registered deserializer for its event type.
// Returns an error if no deserializer is registered for the given event type.
func DeserializePayload(eventType events.EventType, data []byte) (any, error) {
	fn, ok := deserializerRegistry[eventType]
	if !ok {
		return nil, fmt.Errorf("no deserializer registered for eventType=%s", eventType)
	}
	return fn(data)
}

// RegisterEventSerializers initializes the serialization system by registering handlers for all supported event types.
// This must be called during system startup before any event processing can occur.
func RegisterEventSerializers() {
	RegisterSerializeFunc(enumeration.EventTypeTaskCreated, serializeTaskCreated)
	RegisterDeserializeFunc(enumeration.EventTypeTaskCreated, deserializeTaskCreated)

	RegisterSerializeFunc(enumeration.EventTypeTaskBatchCreated, serializeTaskBatchCreated)
	RegisterDeserializeFunc(enumeration.EventTypeTaskBatchCreated, deserializeTaskBatchCreated)

	RegisterSerializeFunc(rules.EventTypeRuleUpdated, serializeRuleUpdated)
	RegisterDeserializeFunc(rules.EventTypeRuleUpdated, deserializeRuleUpdated)

	RegisterSerializeFunc(events.EventTypeScanProgressUpdated, serializeScanProgressUpdated)
	RegisterDeserializeFunc(events.EventTypeScanProgressUpdated, deserializeScanProgressUpdated)

	RegisterSerializeFunc(events.EventTypeScanResultReceived, serializeScanResultReceived)
	RegisterDeserializeFunc(events.EventTypeScanResultReceived, deserializeScanResultReceived)
}

// serializeTaskCreated converts a domain.Task to protobuf bytes.
func serializeTaskCreated(payload any) ([]byte, error) {
	dTask, ok := payload.(task.Task)
	if !ok {
		return nil, fmt.Errorf("serializeTask: payload is not domain.Task")
	}
	pbTask := protobuf.TaskToProto(dTask)
	return proto.Marshal(pbTask)
}

// deserializeTaskCreated converts protobuf bytes back into a domain.Task.
func deserializeTaskCreated(data []byte) (any, error) {
	var pbTask pb.ScanTask
	if err := proto.Unmarshal(data, &pbTask); err != nil {
		return nil, fmt.Errorf("unmarshal ScanTask: %w", err)
	}
	return protobuf.ProtoToTask(&pbTask), nil
}

func serializeTaskBatchCreated(payload any) ([]byte, error) {
	batch, ok := payload.(task.TaskBatch)
	if !ok {
		return nil, fmt.Errorf("serializeTaskBatch: payload is not domain.TaskBatch")
	}
	// Convert []domain.Task -> repeated pb.ScanTask
	pbBatch := &pb.BatchScanTask{} // you'll define this message in your proto
	for _, t := range batch.Tasks {
		pbBatch.Tasks = append(pbBatch.Tasks, protobuf.TaskToProto(t))
	}
	return proto.Marshal(pbBatch)
}

func deserializeTaskBatchCreated(data []byte) (any, error) {
	var pbBatch pb.BatchScanTask
	if err := proto.Unmarshal(data, &pbBatch); err != nil {
		return nil, fmt.Errorf("unmarshal TaskBatch: %w", err)
	}
	// convert pbBatch.Tasks -> []domain.Task
	var tasks []task.Task
	for _, pt := range pbBatch.Tasks {
		tasks = append(tasks, protobuf.ProtoToTask(pt))
	}
	return task.TaskBatch{Tasks: tasks}, nil
}

// serializeRuleUpdated converts a domain.GitleaksRuleMessage to protobuf bytes.
func serializeRuleUpdated(payload any) ([]byte, error) {
	ruleMsg, ok := payload.(rules.GitleaksRuleMessage)
	if !ok {
		return nil, fmt.Errorf("serializeRule: not GitleaksRuleMessage")
	}
	pbRule := protobuf.GitleaksRulesMessageToProto(ruleMsg)
	return proto.Marshal(pbRule)
}

// deserializeRuleUpdated converts protobuf bytes back into a domain.GitleaksRuleMessage.
func deserializeRuleUpdated(data []byte) (any, error) {
	var pbRule pb.RuleMessage
	if err := proto.Unmarshal(data, &pbRule); err != nil {
		return nil, fmt.Errorf("unmarshal RuleMessage: %w", err)
	}
	return protobuf.ProtoToGitleaksRuleMessage(&pbRule), nil
}

// serializeScanProgressUpdated converts a domain.ScanProgress to protobuf bytes.
func serializeScanProgressUpdated(payload any) ([]byte, error) {
	sp, ok := payload.(events.ScanProgress)
	if !ok {
		return nil, fmt.Errorf("serializeScanProgress: not ScanProgress")
	}
	pbProg := protobuf.ScanProgressToProto(sp)
	return proto.Marshal(pbProg)
}

// deserializeScanProgressUpdated converts protobuf bytes back into a domain.ScanProgress.
func deserializeScanProgressUpdated(data []byte) (any, error) {
	var pbProg pb.ScanProgress
	if err := proto.Unmarshal(data, &pbProg); err != nil {
		return nil, fmt.Errorf("unmarshal ScanProgress: %w", err)
	}
	return protobuf.ProtoToScanProgress(&pbProg), nil
}

// serializeScanResultReceived converts a domain.ScanResult to protobuf bytes.
func serializeScanResultReceived(payload any) ([]byte, error) {
	sr, ok := payload.(events.ScanResult)
	if !ok {
		return nil, fmt.Errorf("serializeScanResult: not ScanResult")
	}
	pbSr := protobuf.ScanResultToProto(sr)
	return proto.Marshal(pbSr)
}

// deserializeScanResultReceived converts protobuf bytes back into a domain.ScanResult.
func deserializeScanResultReceived(data []byte) (any, error) {
	var pbSr pb.ScanResult
	if err := proto.Unmarshal(data, &pbSr); err != nil {
		return nil, fmt.Errorf("unmarshal ScanResult: %w", err)
	}
	return protobuf.ProtoToScanResult(&pbSr), nil
}
