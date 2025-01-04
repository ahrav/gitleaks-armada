// Package serialization provides a registry-based system for serializing and deserializing
// domain events in the event bus infrastructure. It acts as a translation layer between
// domain objects and their protobuf wire format representations.
//
// The package implements a registry pattern where serialization/deserialization functions
// are registered for each event type. This approach:
//   - Maintains a clean separation between domain models and their wire formats
//   - Centralizes all serialization logic in one place
//   - Allows for type-safe conversion between domain and protobuf models
//   - Enables easy addition of new event types without modifying existing code
//
// This package enables reliable event-driven communication between
// different components of the system while keeping the domain layer clean of
// serialization concerns.
package serialization

import (
	"fmt"

	"google.golang.org/protobuf/proto"

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

// TODO: Figure out if init function is the best way to do this.
func init() {
	RegisterEventSerializers()
}

// RegisterEventSerializers initializes the serialization system by registering handlers for all supported event types.
// This must be called during system startup before any event processing can occur.
func RegisterEventSerializers() {
	RegisterSerializeFunc(task.EventTypeTaskCreated, serializeTaskCreated)
	RegisterDeserializeFunc(task.EventTypeTaskCreated, deserializeTaskCreated)

	RegisterSerializeFunc(rules.EventTypeRuleUpdated, serializeRuleUpdated)
	RegisterDeserializeFunc(rules.EventTypeRuleUpdated, deserializeRuleUpdated)
}

// serializeTaskCreated converts a TaskCreatedEvent to protobuf bytes.
func serializeTaskCreated(payload any) ([]byte, error) {
	event, ok := payload.(task.TaskCreatedEvent)
	if !ok {
		return nil, fmt.Errorf("serializeTaskCreated: payload is not TaskCreatedEvent, got %T", payload)
	}
	pbTask := protobuf.TaskToProto(event.Task)
	return proto.Marshal(pbTask)
}

// deserializeTaskCreated converts protobuf bytes back into a TaskCreatedEvent.
func deserializeTaskCreated(data []byte) (any, error) {
	var pbTask pb.ScanTask
	if err := proto.Unmarshal(data, &pbTask); err != nil {
		return nil, fmt.Errorf("unmarshal ScanTask: %w", err)
	}
	t := protobuf.ProtoToTask(&pbTask)
	return task.NewTaskCreatedEvent(t), nil
}

// serializeRuleUpdated converts a RuleUpdatedEvent to protobuf bytes.
func serializeRuleUpdated(payload any) ([]byte, error) {
	event, ok := payload.(rules.RuleUpdatedEvent)
	if !ok {
		return nil, fmt.Errorf("serializeRuleUpdated: payload is not RuleUpdatedEvent, got %T", payload)
	}
	pbRule := protobuf.GitleaksRulesMessageToProto(event.Rule)
	return proto.Marshal(pbRule)
}

// deserializeRuleUpdated converts protobuf bytes back into a RuleUpdatedEvent.
func deserializeRuleUpdated(data []byte) (any, error) {
	var pbRule pb.RuleMessage
	if err := proto.Unmarshal(data, &pbRule); err != nil {
		return nil, fmt.Errorf("unmarshal RuleMessage: %w", err)
	}
	ruleMsg := protobuf.ProtoToGitleaksRuleMessage(&pbRule)
	return rules.NewRuleUpdatedEvent(ruleMsg), nil
}
