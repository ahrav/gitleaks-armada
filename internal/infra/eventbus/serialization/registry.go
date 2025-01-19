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

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	"github.com/ahrav/gitleaks-armada/internal/domain/enumeration"
	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/domain/rules"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	serdeEnum "github.com/ahrav/gitleaks-armada/internal/infra/eventbus/serialization/protobuf/enumeration"
	serdeRules "github.com/ahrav/gitleaks-armada/internal/infra/eventbus/serialization/protobuf/rules"
	serdeScanning "github.com/ahrav/gitleaks-armada/internal/infra/eventbus/serialization/protobuf/scanning"
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

// UnmarshalUniversalEnvelope takes the raw bytes from Kafka, unmarshals the
// UniversalEnvelope proto, and returns:
//   - the actual event type (like "TASK_STARTED")
//   - the domain payload bytes (the second-level content)
//   - any error encountered
func UnmarshalUniversalEnvelope(kafkaValue []byte) (events.EventType, []byte, error) {
	var ue pb.UniversalEnvelope
	if err := proto.Unmarshal(kafkaValue, &ue); err != nil {
		return "", nil, fmt.Errorf("failed to unmarshal universal envelope: %w", err)
	}

	actualEventType := events.EventType(ue.EventType)
	return actualEventType, ue.Payload, nil
}

// SerializeEventEnvelope converts a domain object into a serialized event envelope.
// It first serializes the domain object into bytes using the registered serializer for its event type,
// then constructs a UniversalEnvelope with the event type and the serialized payload,
// and finally marshals the envelope into a byte slice using Protocol Buffers.
func SerializeEventEnvelope(eType events.EventType, domainObj any) ([]byte, error) {
	domainBytes, err := SerializePayload(eType, domainObj)
	if err != nil {
		return nil, fmt.Errorf("serialize domain payload: %w", err)
	}

	envelope := pb.UniversalEnvelope{
		EventType: string(eType), // Store the exact event type as a string, e.g., "TASK_STARTED"
		Payload:   domainBytes,
	}

	return proto.Marshal(&envelope)
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
	// Enumeration.
	RegisterSerializeFunc(enumeration.EventTypeTaskCreated, serializeEnumerationTaskCreated)
	RegisterDeserializeFunc(enumeration.EventTypeTaskCreated, deserializeEnumerationTaskCreated)

	// Scanning.
	RegisterSerializeFunc(scanning.EventTypeTaskStarted, serializeTaskStarted)
	RegisterDeserializeFunc(scanning.EventTypeTaskStarted, deserializeTaskStarted)

	// Rules.
	RegisterSerializeFunc(rules.EventTypeRulesUpdated, serializeRuleUpdated)
	RegisterDeserializeFunc(rules.EventTypeRulesUpdated, deserializeRuleUpdated)

	RegisterSerializeFunc(rules.EventTypeRulesRequested, serializeRuleRequested)
	RegisterDeserializeFunc(rules.EventTypeRulesRequested, deserializeRuleRequested)

	RegisterSerializeFunc(rules.EventTypeRulesPublished, serializeRulePublishingCompleted)
	RegisterDeserializeFunc(rules.EventTypeRulesPublished, deserializeRulePublishingCompleted)
}

// serializeEnumerationTaskCreated converts a TaskCreatedEvent to protobuf bytes.
func serializeEnumerationTaskCreated(payload any) ([]byte, error) {
	event, ok := payload.(enumeration.TaskCreatedEvent)
	if !ok {
		return nil, fmt.Errorf("serializeEnumerationTaskCreated: payload is not TaskCreatedEvent, got %T", payload)
	}
	pbTask := serdeEnum.TaskToProto(event.Task, event.JobID)
	return proto.Marshal(pbTask)
}

// deserializeEnumerationTaskCreated converts protobuf bytes back into a TaskCreatedEvent.
func deserializeEnumerationTaskCreated(data []byte) (any, error) {
	var pbTask pb.EnumerationTask
	if err := proto.Unmarshal(data, &pbTask); err != nil {
		return nil, fmt.Errorf("unmarshal EnumerationTask: %w", err)
	}
	t := serdeEnum.ProtoToTask(&pbTask)
	return enumeration.NewTaskCreatedEvent(uuid.MustParse(pbTask.JobId), t), nil
}

// serializeRuleUpdated converts a RuleUpdatedEvent to protobuf bytes.
func serializeRuleUpdated(payload any) ([]byte, error) {
	event, ok := payload.(rules.RuleUpdatedEvent)
	if !ok {
		return nil, fmt.Errorf("serializeRuleUpdated: payload is not RuleUpdatedEvent, got %T", payload)
	}
	pbRule := serdeRules.GitleaksRulesMessageToProto(event.Rule)
	return proto.Marshal(pbRule)
}

// deserializeRuleUpdated converts protobuf bytes back into a RuleUpdatedEvent.
func deserializeRuleUpdated(data []byte) (any, error) {
	var pbRule pb.RuleMessage
	if err := proto.Unmarshal(data, &pbRule); err != nil {
		return nil, fmt.Errorf("unmarshal RuleMessage: %w", err)
	}
	ruleMsg := serdeRules.ProtoToGitleaksRuleMessage(&pbRule)
	return rules.NewRuleUpdatedEvent(ruleMsg), nil
}

// serializeTaskStarted converts a TaskStartedEvent to protobuf bytes.
func serializeTaskStarted(payload any) ([]byte, error) {
	event, ok := payload.(scanning.TaskStartedEvent)
	if !ok {
		return nil, fmt.Errorf("serializeTaskStarted: payload is not TaskStartedEvent, got %T", payload)
	}

	pbEvent := serdeScanning.TaskStartedEventToProto(event)
	return proto.Marshal(pbEvent)
}

// deserializeTaskStarted converts protobuf bytes back into a TaskStartedEvent.
func deserializeTaskStarted(data []byte) (any, error) {
	var pbEvent pb.TaskStartedEvent
	if err := proto.Unmarshal(data, &pbEvent); err != nil {
		return nil, fmt.Errorf("unmarshal TaskStartedEvent: %w", err)
	}

	event, err := serdeScanning.ProtoToTaskStartedEvent(&pbEvent)
	if err != nil {
		return nil, fmt.Errorf("convert proto to domain event: %w", err)
	}

	return event, nil
}

// serializeRuleRequested converts a RuleRequestedEvent to protobuf bytes.
func serializeRuleRequested(payload any) ([]byte, error) {
	_, ok := payload.(rules.RuleRequestedEvent)
	if !ok {
		return nil, fmt.Errorf("serializeRuleRequested: payload is not RuleRequestedEvent, got %T", payload)
	}
	return proto.Marshal(&pb.RuleRequestedEvent{})
}

// deserializeRuleRequested converts protobuf bytes back into a RuleRequestedEvent.
func deserializeRuleRequested(data []byte) (any, error) {
	var pbEvent pb.RuleRequestedEvent
	if err := proto.Unmarshal(data, &pbEvent); err != nil {
		return nil, fmt.Errorf("unmarshal RuleRequestedEvent: %w", err)
	}
	return rules.NewRuleRequestedEvent(), nil
}

// serializeRulePublishingCompleted converts a RulePublishingCompletedEvent to protobuf bytes.
func serializeRulePublishingCompleted(payload any) ([]byte, error) {
	_, ok := payload.(rules.RulePublishingCompletedEvent)
	if !ok {
		return nil, fmt.Errorf("serializeRulePublishingCompleted: payload is not RulePublishingCompletedEvent, got %T", payload)
	}
	return proto.Marshal(&pb.RulePublishingCompletedEvent{})
}

// deserializeRulePublishingCompleted converts protobuf bytes back into a RulePublishingCompletedEvent.
func deserializeRulePublishingCompleted(data []byte) (any, error) {
	var pbEvent pb.RulePublishingCompletedEvent
	if err := proto.Unmarshal(data, &pbEvent); err != nil {
		return nil, fmt.Errorf("unmarshal RulePublishingCompletedEvent: %w", err)
	}
	return rules.NewRulePublishingCompletedEvent(), nil
}
