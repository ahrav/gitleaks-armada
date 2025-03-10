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
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	serdeRules "github.com/ahrav/gitleaks-armada/internal/infra/eventbus/serialization/protobuf/rules"
	serdeScanning "github.com/ahrav/gitleaks-armada/internal/infra/eventbus/serialization/protobuf/scanning"
	pb "github.com/ahrav/gitleaks-armada/proto"
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

// registerSerializeFunc registers a serialization function for a given event type.
// This enables the system to properly encode domain objects when publishing events.
func registerSerializeFunc(eventType events.EventType, fn SerializeFunc) {
	serializerRegistry[eventType] = fn
}

// registerDeserializeFunc registers a deserialization function for a given event type.
// This enables the system to properly decode events back into domain objects when consuming them.
func registerDeserializeFunc(eventType events.EventType, fn DeserializeFunc) {
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
	registerEventSerializers()
}

// registerEventSerializers initializes the serialization system by registering handlers for all supported event types.
// This must be called during system startup before any event processing can occur.
func registerEventSerializers() {
	// Scanning.
	// ------------------------------------------------------------------------------------------------

	// Job events.
	registerSerializeFunc(scanning.EventTypeJobRequested, serializeJobRequested)
	registerDeserializeFunc(scanning.EventTypeJobRequested, deserializeJobRequested)

	registerSerializeFunc(scanning.EventTypeJobScheduled, serializeJobCreated)
	registerDeserializeFunc(scanning.EventTypeJobScheduled, deserializeJobCreated)

	// Job Pausing/Paused events.
	registerSerializeFunc(scanning.EventTypeJobPausing, serializeJobPausing)
	registerDeserializeFunc(scanning.EventTypeJobPausing, deserializeJobPausing)

	registerSerializeFunc(scanning.EventTypeJobPaused, serializeJobPaused)
	registerDeserializeFunc(scanning.EventTypeJobPaused, deserializeJobPaused)

	// Job Resuming event.
	registerSerializeFunc(scanning.EventTypeJobResuming, serializeJobResuming)
	registerDeserializeFunc(scanning.EventTypeJobResuming, deserializeJobResuming)

	// Job Cancelling/Cancelled events.
	registerSerializeFunc(scanning.EventTypeJobCancelling, serializeJobCancelling)
	registerDeserializeFunc(scanning.EventTypeJobCancelling, deserializeJobCancelling)

	registerSerializeFunc(scanning.EventTypeJobCancelled, serializeJobCancelled)
	registerDeserializeFunc(scanning.EventTypeJobCancelled, deserializeJobCancelled)

	// Task events.
	registerSerializeFunc(scanning.EventTypeTaskCreated, serializeTaskCreated)
	registerDeserializeFunc(scanning.EventTypeTaskCreated, deserializeTaskCreated)

	registerSerializeFunc(scanning.EventTypeTaskStarted, serializeTaskStarted)
	registerDeserializeFunc(scanning.EventTypeTaskStarted, deserializeTaskStarted)

	registerSerializeFunc(scanning.EventTypeJobEnumerationCompleted, serializeJobEnumerationCompleted)
	registerDeserializeFunc(scanning.EventTypeJobEnumerationCompleted, deserializeJobEnumerationCompleted)

	registerSerializeFunc(scanning.EventTypeTaskProgressed, serializeTaskProgressed)
	registerDeserializeFunc(scanning.EventTypeTaskProgressed, deserializeTaskProgressed)

	registerSerializeFunc(scanning.EventTypeTaskCompleted, serializeTaskCompleted)
	registerDeserializeFunc(scanning.EventTypeTaskCompleted, deserializeTaskCompleted)

	registerSerializeFunc(scanning.EventTypeTaskFailed, serializeTaskFailed)
	registerDeserializeFunc(scanning.EventTypeTaskFailed, deserializeTaskFailed)

	registerSerializeFunc(scanning.EventTypeTaskResume, serializeTaskResume)
	registerDeserializeFunc(scanning.EventTypeTaskResume, deserializeTaskResume)

	registerSerializeFunc(scanning.EventTypeTaskJobMetric, serializeTaskJobMetric)
	registerDeserializeFunc(scanning.EventTypeTaskJobMetric, deserializeTaskJobMetric)

	registerSerializeFunc(scanning.EventTypeTaskHeartbeat, serializeTaskHeartbeat)
	registerDeserializeFunc(scanning.EventTypeTaskHeartbeat, deserializeTaskHeartbeat)

	// Task Pausing/Paused events.
	registerSerializeFunc(scanning.EventTypeTaskPaused, serializeTaskPaused)
	registerDeserializeFunc(scanning.EventTypeTaskPaused, deserializeTaskPaused)

	// Task Cancelled events.
	registerSerializeFunc(scanning.EventTypeTaskCancelled, serializeTaskCancelled)
	registerDeserializeFunc(scanning.EventTypeTaskCancelled, deserializeTaskCancelled)

	// Scanner events
	registerSerializeFunc(scanning.EventTypeScannerRegistered, serializeScannerRegistered)
	registerDeserializeFunc(scanning.EventTypeScannerRegistered, deserializeScannerRegistered)

	registerSerializeFunc(scanning.EventTypeScannerHeartbeat, serializeScannerHeartbeat)
	registerDeserializeFunc(scanning.EventTypeScannerHeartbeat, deserializeScannerHeartbeat)

	registerSerializeFunc(scanning.EventTypeScannerStatusChanged, serializeScannerStatusChanged)
	registerDeserializeFunc(scanning.EventTypeScannerStatusChanged, deserializeScannerStatusChanged)

	registerSerializeFunc(scanning.EventTypeScannerDeregistered, serializeScannerDeregistered)
	registerDeserializeFunc(scanning.EventTypeScannerDeregistered, deserializeScannerDeregistered)

	// Rules.
	// ------------------------------------------------------------------------------------------------
	registerSerializeFunc(rules.EventTypeRulesUpdated, serializeRuleUpdated)
	registerDeserializeFunc(rules.EventTypeRulesUpdated, deserializeRuleUpdated)

	registerSerializeFunc(rules.EventTypeRulesRequested, serializeRuleRequested)
	registerDeserializeFunc(rules.EventTypeRulesRequested, deserializeRuleRequested)

	registerSerializeFunc(rules.EventTypeRulesPublished, serializeRulePublishingCompleted)
	registerDeserializeFunc(rules.EventTypeRulesPublished, deserializeRulePublishingCompleted)
}

// serializeJobRequested converts a JobRequestedEvent to protobuf bytes
func serializeJobRequested(payload any) ([]byte, error) {
	event, ok := payload.(scanning.JobRequestedEvent)
	if !ok {
		return nil, fmt.Errorf("serializeJobRequested: payload is not JobRequestedEvent, got %T", payload)
	}

	pbEvent, err := serdeScanning.JobRequestedEventToProto(event)
	if err != nil {
		return nil, fmt.Errorf("convert to proto: %w", err)
	}

	return proto.Marshal(pbEvent)
}

// deserializeJobRequested converts protobuf bytes back into a JobRequestedEvent
func deserializeJobRequested(data []byte) (any, error) {
	var pbEvent pb.JobRequestedEvent
	if err := proto.Unmarshal(data, &pbEvent); err != nil {
		return nil, fmt.Errorf("unmarshal JobRequestedEvent: %w", err)
	}

	event, err := serdeScanning.ProtoToJobRequestedEvent(&pbEvent)
	if err != nil {
		return nil, fmt.Errorf("convert proto to domain event: %w", err)
	}

	return event, nil
}

// serializeJobCreated converts a JobCreatedEvent to protobuf bytes.
func serializeJobCreated(payload any) ([]byte, error) {
	event, ok := payload.(scanning.JobScheduledEvent)
	if !ok {
		return nil, fmt.Errorf("serializeJobCreated: payload is not JobCreatedEvent, got %T", payload)
	}

	pbEvent, err := serdeScanning.JobCreatedEventToProto(event)
	if err != nil {
		return nil, fmt.Errorf("convert domain to proto: %w", err)
	}
	return proto.Marshal(pbEvent)
}

// deserializeJobCreated converts protobuf bytes back into a JobCreatedEvent.
func deserializeJobCreated(data []byte) (any, error) {
	var pbEvent pb.JobCreatedEvent
	if err := proto.Unmarshal(data, &pbEvent); err != nil {
		return nil, fmt.Errorf("unmarshal JobCreatedEvent: %w", err)
	}

	event, err := serdeScanning.ProtoToJobCreatedEvent(&pbEvent)
	if err != nil {
		return nil, fmt.Errorf("convert proto to domain: %w", err)
	}
	return event, nil
}

// serializeJobPausing converts a JobPausingEvent to protobuf bytes.
func serializeJobPausing(payload any) ([]byte, error) {
	event, ok := payload.(scanning.JobPausingEvent)
	if !ok {
		return nil, fmt.Errorf("serializeJobPausing: payload is not JobPausingEvent, got %T", payload)
	}

	pbEvent := serdeScanning.JobPausingEventToProto(event)
	return proto.Marshal(pbEvent)
}

// deserializeJobPausing converts protobuf bytes back into a JobPausingEvent.
func deserializeJobPausing(data []byte) (any, error) {
	var pbEvent pb.JobPausingEvent
	if err := proto.Unmarshal(data, &pbEvent); err != nil {
		return nil, fmt.Errorf("unmarshal JobPausingEvent: %w", err)
	}

	event, err := serdeScanning.ProtoToJobPausingEvent(&pbEvent)
	if err != nil {
		return nil, fmt.Errorf("convert proto to domain event: %w", err)
	}

	return event, nil
}

// serializeJobPaused converts a JobPausedEvent to protobuf bytes.
func serializeJobPaused(payload any) ([]byte, error) {
	event, ok := payload.(scanning.JobPausedEvent)
	if !ok {
		return nil, fmt.Errorf("serializeJobPaused: payload is not JobPausedEvent, got %T", payload)
	}

	pbEvent := serdeScanning.JobPausedEventToProto(event)
	return proto.Marshal(pbEvent)
}

// deserializeJobPaused converts protobuf bytes back into a JobPausedEvent.
func deserializeJobPaused(data []byte) (any, error) {
	var pbEvent pb.JobPausedEvent
	if err := proto.Unmarshal(data, &pbEvent); err != nil {
		return nil, fmt.Errorf("unmarshal JobPausedEvent: %w", err)
	}

	event, err := serdeScanning.ProtoToJobPausedEvent(&pbEvent)
	if err != nil {
		return nil, fmt.Errorf("convert proto to domain event: %w", err)
	}

	return event, nil
}

// serializeJobResuming converts a JobResumingEvent to protobuf bytes.
func serializeJobResuming(payload any) ([]byte, error) {
	event, ok := payload.(scanning.JobResumingEvent)
	if !ok {
		return nil, fmt.Errorf("serializeJobResuming: payload is not JobResumingEvent, got %T", payload)
	}

	pbEvent := serdeScanning.JobResumingEventToProto(event)
	return proto.Marshal(pbEvent)
}

// deserializeJobResuming converts protobuf bytes back into a JobResumingEvent.
func deserializeJobResuming(data []byte) (any, error) {
	var pbEvent pb.JobResumingEvent
	if err := proto.Unmarshal(data, &pbEvent); err != nil {
		return nil, fmt.Errorf("unmarshal JobResumingEvent: %w", err)
	}

	event, err := serdeScanning.ProtoToJobResumingEvent(&pbEvent)
	if err != nil {
		return nil, fmt.Errorf("convert proto to domain event: %w", err)
	}

	return event, nil
}

// serializeJobCancelling converts a JobCancellingEvent to protobuf bytes.
func serializeJobCancelling(payload any) ([]byte, error) {
	event, ok := payload.(scanning.JobCancellingEvent)
	if !ok {
		return nil, fmt.Errorf("serializeJobCancelling: payload is not JobCancellingEvent, got %T", payload)
	}

	pbEvent := serdeScanning.JobCancellingEventToProto(event)
	return proto.Marshal(pbEvent)
}

// deserializeJobCancelling converts protobuf bytes back into a JobCancellingEvent.
func deserializeJobCancelling(data []byte) (any, error) {
	var pbEvent pb.JobCancellingEvent
	if err := proto.Unmarshal(data, &pbEvent); err != nil {
		return nil, fmt.Errorf("unmarshal JobCancellingEvent: %w", err)
	}

	event, err := serdeScanning.ProtoToJobCancellingEvent(&pbEvent)
	if err != nil {
		return nil, fmt.Errorf("convert proto to domain event: %w", err)
	}

	return event, nil
}

// serializeJobCancelled converts a JobCancelledEvent to protobuf bytes.
func serializeJobCancelled(payload any) ([]byte, error) {
	event, ok := payload.(scanning.JobCancelledEvent)
	if !ok {
		return nil, fmt.Errorf("serializeJobCancelled: payload is not JobCancelledEvent, got %T", payload)
	}

	pbEvent := serdeScanning.JobCancelledEventToProto(event)
	return proto.Marshal(pbEvent)
}

// deserializeJobCancelled converts protobuf bytes back into a JobCancelledEvent.
func deserializeJobCancelled(data []byte) (any, error) {
	var pbEvent pb.JobCancelledEvent
	if err := proto.Unmarshal(data, &pbEvent); err != nil {
		return nil, fmt.Errorf("unmarshal JobCancelledEvent: %w", err)
	}

	event, err := serdeScanning.ProtoToJobCancelledEvent(&pbEvent)
	if err != nil {
		return nil, fmt.Errorf("convert proto to domain event: %w", err)
	}

	return event, nil
}

// serializeTaskCreated converts a TaskCreatedEvent to protobuf bytes.
func serializeTaskCreated(payload any) ([]byte, error) {
	event, ok := payload.(*scanning.TaskCreatedEvent)
	if !ok {
		return nil, fmt.Errorf("serializeTaskCreated: payload is not TaskCreatedEvent, got %T", payload)
	}

	pbEvent := serdeScanning.TaskCreatedEventToProto(event)
	return proto.Marshal(pbEvent)
}

// deserializeTaskCreated converts protobuf bytes back into a TaskCreatedEvent.
func deserializeTaskCreated(data []byte) (any, error) {
	var pbEvent pb.TaskCreatedEvent
	if err := proto.Unmarshal(data, &pbEvent); err != nil {
		return nil, fmt.Errorf("unmarshal TaskCreatedEvent: %w", err)
	}

	event, err := serdeScanning.ProtoToTaskCreatedEvent(&pbEvent)
	if err != nil {
		return nil, fmt.Errorf("convert proto to domain event: %w", err)
	}

	return event, nil
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

// serializeJobEnumerationCompleted converts a JobEnumerationCompletedEvent to protobuf bytes.
func serializeJobEnumerationCompleted(payload any) ([]byte, error) {
	event, ok := payload.(scanning.JobEnumerationCompletedEvent)
	if !ok {
		return nil, fmt.Errorf("serializeJobEnumerationCompleted: payload is not JobEnumerationCompletedEvent, got %T", payload)
	}

	pbEvent := serdeScanning.JobEnumerationCompletedEventToProto(event)
	return proto.Marshal(pbEvent)
}

// deserializeJobEnumerationCompleted converts protobuf bytes back into a JobEnumerationCompletedEvent.
func deserializeJobEnumerationCompleted(data []byte) (any, error) {
	var pbEvent pb.JobEnumerationCompletedEvent
	if err := proto.Unmarshal(data, &pbEvent); err != nil {
		return nil, fmt.Errorf("unmarshal JobEnumerationCompletedEvent: %w", err)
	}

	event, err := serdeScanning.ProtoToJobEnumerationCompletedEvent(&pbEvent)
	if err != nil {
		return nil, fmt.Errorf("convert proto to domain event: %w", err)
	}

	return event, nil
}

// serializeTaskProgressed converts a TaskProgressedEvent to protobuf bytes
func serializeTaskProgressed(payload any) ([]byte, error) {
	event, ok := payload.(scanning.TaskProgressedEvent)
	if !ok {
		return nil, fmt.Errorf("serializeTaskProgressed: payload is not TaskProgressedEvent, got %T", payload)
	}

	pbEvent := serdeScanning.TaskProgressedEventToProto(event)
	return proto.Marshal(pbEvent)
}

// deserializeTaskProgressed converts protobuf bytes back into a TaskProgressedEvent
func deserializeTaskProgressed(data []byte) (any, error) {
	var pbEvent pb.TaskProgressedEvent
	if err := proto.Unmarshal(data, &pbEvent); err != nil {
		return nil, fmt.Errorf("unmarshal TaskProgressedEvent: %w", err)
	}

	event, err := serdeScanning.ProtoToTaskProgressedEvent(&pbEvent)
	if err != nil {
		return nil, fmt.Errorf("convert proto to domain event: %w", err)
	}

	return event, nil
}

// serializeTaskCompleted converts a TaskCompletedEvent to protobuf bytes.
func serializeTaskCompleted(payload any) ([]byte, error) {
	event, ok := payload.(scanning.TaskCompletedEvent)
	if !ok {
		return nil, fmt.Errorf("serializeTaskCompleted: payload is not TaskCompletedEvent, got %T", payload)
	}

	pbEvent := serdeScanning.TaskCompletedEventToProto(event)
	return proto.Marshal(pbEvent)
}

// deserializeTaskCompleted converts protobuf bytes back into a TaskCompletedEvent.
func deserializeTaskCompleted(data []byte) (any, error) {
	var pbEvent pb.TaskCompletedEvent
	if err := proto.Unmarshal(data, &pbEvent); err != nil {
		return nil, fmt.Errorf("unmarshal TaskCompletedEvent: %w", err)
	}

	event, err := serdeScanning.ProtoToTaskCompletedEvent(&pbEvent)
	if err != nil {
		return nil, fmt.Errorf("convert proto to domain event: %w", err)
	}

	return event, nil
}

// serializeTaskFailed converts a TaskFailedEvent to protobuf bytes.
func serializeTaskFailed(payload any) ([]byte, error) {
	event, ok := payload.(scanning.TaskFailedEvent)
	if !ok {
		return nil, fmt.Errorf("serializeTaskFailed: payload is not TaskFailedEvent, got %T", payload)
	}

	pbEvent := serdeScanning.TaskFailedEventToProto(event)
	return proto.Marshal(pbEvent)
}

// deserializeTaskFailed converts protobuf bytes back into a TaskFailedEvent.
func deserializeTaskFailed(data []byte) (any, error) {
	var pbEvent pb.TaskFailedEvent
	if err := proto.Unmarshal(data, &pbEvent); err != nil {
		return nil, fmt.Errorf("unmarshal TaskFailedEvent: %w", err)
	}

	event, err := serdeScanning.ProtoToTaskFailedEvent(&pbEvent)
	if err != nil {
		return nil, fmt.Errorf("convert proto to domain event: %w", err)
	}

	return event, nil
}

// serializeTaskResume converts a TaskResumeEvent to protobuf bytes.
func serializeTaskResume(payload any) ([]byte, error) {
	event, ok := payload.(*scanning.TaskResumeEvent)
	if !ok {
		return nil, fmt.Errorf("serializeTaskResume: payload is not TaskResumeEvent, got %T", payload)
	}

	pbEvent, err := serdeScanning.TaskResumeEventToProto(event)
	if err != nil {
		return nil, fmt.Errorf("convert domain to proto: %w", err)
	}
	return proto.Marshal(pbEvent)
}

// deserializeTaskResume converts protobuf bytes back into a TaskResumeEvent.
func deserializeTaskResume(data []byte) (any, error) {
	var pbEvent pb.TaskResumeEvent
	if err := proto.Unmarshal(data, &pbEvent); err != nil {
		return nil, fmt.Errorf("unmarshal TaskResumeEvent: %w", err)
	}

	event, err := serdeScanning.ProtoToTaskResumeEvent(&pbEvent)
	if err != nil {
		return nil, fmt.Errorf("convert proto to domain event: %w", err)
	}

	return event, nil
}

// serializeTaskJobMetric converts a TaskJobMetricEvent to protobuf bytes.
func serializeTaskJobMetric(payload any) ([]byte, error) {
	event, ok := payload.(scanning.TaskJobMetricEvent)
	if !ok {
		return nil, fmt.Errorf("serializeTaskJobMetric: payload is not TaskJobMetricEvent, got %T", payload)
	}

	pbEvent := serdeScanning.TaskJobMetricEventToProto(event)
	return proto.Marshal(pbEvent)
}

// deserializeTaskJobMetric converts protobuf bytes back into a TaskJobMetricEvent.
func deserializeTaskJobMetric(data []byte) (any, error) {
	var pbEvent pb.TaskJobMetricEvent
	if err := proto.Unmarshal(data, &pbEvent); err != nil {
		return nil, fmt.Errorf("unmarshal TaskJobMetricEvent: %w", err)
	}

	event, err := serdeScanning.ProtoToTaskJobMetricEvent(&pbEvent)
	if err != nil {
		return nil, fmt.Errorf("convert proto to domain event: %w", err)
	}

	return event, nil
}

// serializeTaskHeartbeat converts a TaskHeartbeatEvent to protobuf bytes.
func serializeTaskHeartbeat(payload any) ([]byte, error) {
	event, ok := payload.(scanning.TaskHeartbeatEvent)
	if !ok {
		return nil, fmt.Errorf("serializeTaskHeartbeat: payload is not TaskHeartbeatEvent, got %T", payload)
	}

	pbEvent := serdeScanning.TaskHeartbeatEventToProto(event)
	return proto.Marshal(pbEvent)
}

// deserializeTaskHeartbeat converts protobuf bytes back into a TaskHeartbeatEvent.
func deserializeTaskHeartbeat(data []byte) (any, error) {
	var pbEvent pb.TaskHeartbeatEvent
	if err := proto.Unmarshal(data, &pbEvent); err != nil {
		return nil, fmt.Errorf("unmarshal TaskHeartbeatEvent: %w", err)
	}

	event, err := serdeScanning.ProtoToTaskHeartbeatEvent(&pbEvent)
	if err != nil {
		return nil, fmt.Errorf("convert proto to domain event: %w", err)
	}

	return event, nil
}

// serializeTaskPaused converts a TaskPausedEvent to protobuf bytes.
func serializeTaskPaused(payload any) ([]byte, error) {
	event, ok := payload.(scanning.TaskPausedEvent)
	if !ok {
		return nil, fmt.Errorf("serializeTaskPaused: payload is not TaskPausedEvent, got %T", payload)
	}

	pbEvent := serdeScanning.TaskPausedEventToProto(event)
	return proto.Marshal(pbEvent)
}

// deserializeTaskPaused converts protobuf bytes back into a TaskPausedEvent.
func deserializeTaskPaused(data []byte) (any, error) {
	var pbEvent pb.TaskPausedEvent
	if err := proto.Unmarshal(data, &pbEvent); err != nil {
		return nil, fmt.Errorf("unmarshal TaskPausedEvent: %w", err)
	}

	event, err := serdeScanning.ProtoToTaskPausedEvent(&pbEvent)
	if err != nil {
		return nil, fmt.Errorf("convert proto to domain event: %w", err)
	}

	return event, nil
}

// serializeTaskCancelled converts a TaskCancelledEvent to protobuf bytes.
func serializeTaskCancelled(payload any) ([]byte, error) {
	event, ok := payload.(scanning.TaskCancelledEvent)
	if !ok {
		return nil, fmt.Errorf("unexpected payload type: %T", payload)
	}
	protoEvent := serdeScanning.TaskCancelledEventToProto(event)
	return proto.Marshal(protoEvent)
}

// deserializeTaskCancelled converts protobuf bytes back into a TaskCancelledEvent.
func deserializeTaskCancelled(data []byte) (any, error) {
	var protoEvent pb.TaskCancelledEvent
	if err := proto.Unmarshal(data, &protoEvent); err != nil {
		return nil, fmt.Errorf("failed to unmarshal TaskCancelledEvent: %w", err)
	}
	return serdeScanning.ProtoToTaskCancelledEvent(&protoEvent)
}

func serializeScannerRegistered(payload any) ([]byte, error) {
	event, ok := payload.(scanning.ScannerRegisteredEvent)
	if !ok {
		return nil, fmt.Errorf("expected ScannerRegisteredEvent, got %T", payload)
	}

	pbEvent := serdeScanning.ScannerRegisteredEventToProto(event)
	return proto.Marshal(pbEvent)
}

func deserializeScannerRegistered(data []byte) (any, error) {
	var pbEvent pb.ScannerRegisteredEvent
	if err := proto.Unmarshal(data, &pbEvent); err != nil {
		return nil, fmt.Errorf("failed to unmarshal ScannerRegisteredEvent: %w", err)
	}

	return serdeScanning.ProtoToScannerRegisteredEvent(&pbEvent)
}

func serializeScannerHeartbeat(payload any) ([]byte, error) {
	event, ok := payload.(scanning.ScannerHeartbeatEvent)
	if !ok {
		return nil, fmt.Errorf("expected ScannerHeartbeatEvent, got %T", payload)
	}

	pbEvent := serdeScanning.ScannerHeartbeatEventToProto(event)
	return proto.Marshal(pbEvent)
}

func deserializeScannerHeartbeat(data []byte) (any, error) {
	var pbEvent pb.ScannerHeartbeatEvent
	if err := proto.Unmarshal(data, &pbEvent); err != nil {
		return nil, fmt.Errorf("failed to unmarshal ScannerHeartbeatEvent: %w", err)
	}

	return serdeScanning.ProtoToScannerHeartbeatEvent(&pbEvent)
}

func serializeScannerStatusChanged(payload any) ([]byte, error) {
	event, ok := payload.(scanning.ScannerStatusChangedEvent)
	if !ok {
		return nil, fmt.Errorf("expected ScannerStatusChangedEvent, got %T", payload)
	}

	pbEvent := serdeScanning.ScannerStatusChangedEventToProto(event)
	return proto.Marshal(pbEvent)
}

func deserializeScannerStatusChanged(data []byte) (any, error) {
	var pbEvent pb.ScannerStatusChangedEvent
	if err := proto.Unmarshal(data, &pbEvent); err != nil {
		return nil, fmt.Errorf("failed to unmarshal ScannerStatusChangedEvent: %w", err)
	}

	return serdeScanning.ProtoToScannerStatusChangedEvent(&pbEvent)
}

func serializeScannerDeregistered(payload any) ([]byte, error) {
	event, ok := payload.(scanning.ScannerDeregisteredEvent)
	if !ok {
		return nil, fmt.Errorf("expected ScannerDeregisteredEvent, got %T", payload)
	}

	pbEvent := serdeScanning.ScannerDeregisteredEventToProto(event)
	return proto.Marshal(pbEvent)
}

func deserializeScannerDeregistered(data []byte) (any, error) {
	var pbEvent pb.ScannerDeregisteredEvent
	if err := proto.Unmarshal(data, &pbEvent); err != nil {
		return nil, fmt.Errorf("failed to unmarshal ScannerDeregisteredEvent: %w", err)
	}

	return serdeScanning.ProtoToScannerDeregisteredEvent(&pbEvent)
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
