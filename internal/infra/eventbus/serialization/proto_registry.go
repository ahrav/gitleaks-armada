// Package serialization provides functions for serializing and deserializing domain events.
// This file specifically handles conversion between domain events and gRPC protocol buffer messages.
package serialization

import (
	"fmt"
	"time"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/domain/rules"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	pbrules "github.com/ahrav/gitleaks-armada/internal/infra/eventbus/serialization/protobuf/rules"
	pbscanning "github.com/ahrav/gitleaks-armada/internal/infra/eventbus/serialization/protobuf/scanning"
	"github.com/ahrav/gitleaks-armada/pkg/common/uuid"
	pb "github.com/ahrav/gitleaks-armada/proto"
)

// ProtoSerializeFunc converts a domain event to a protocol buffer message.
type ProtoSerializeFunc func(payload any) (any, error)

// ProtoDeserializeFunc converts a protocol buffer message to a domain event.
type ProtoDeserializeFunc func(message any) (any, error)

var (
	protoSerializers   = make(map[events.EventType]ProtoSerializeFunc)
	protoDeserializers = make(map[events.EventType]ProtoDeserializeFunc)
)

// registerProtoSerializeFunc registers a function for serializing domain events to protocol buffer messages.
func registerProtoSerializeFunc(eventType events.EventType, fn ProtoSerializeFunc) {
	protoSerializers[eventType] = fn
}

// registerProtoDeserializeFunc registers a function for deserializing protocol buffer messages to domain events.
// The messageType parameter is a string identifier for the message type (e.g., "heartbeat", "scanner_registered").
func registerProtoDeserializeFunc(eventType events.EventType, fn ProtoDeserializeFunc) {
	protoDeserializers[eventType] = fn
}

// DomainEventToProto converts a domain event to a protocol buffer message.
func DomainEventToProto(eventType events.EventType, payload any) (any, error) {
	serialize, ok := protoSerializers[eventType]
	if !ok {
		return nil, fmt.Errorf("no proto serializer registered for event type: %s", eventType)
	}

	return serialize(payload)
}

// ProtoToDomainEvent converts a protocol buffer message to a domain event.
func ProtoToDomainEvent(eventType events.EventType, message any) (any, error) {
	deserialize, ok := protoDeserializers[eventType]
	if !ok {
		return nil, fmt.Errorf("no proto deserializer registered for event type: %s", eventType)
	}

	return deserialize(message)
}

// Register all proto serialization/deserialization functions.
func registerProtoSerializers() {
	// Scanner related events.
	registerProtoSerializeFunc(scanning.EventTypeScannerHeartbeat, ScannerHeartbeatEventToProto)
	registerProtoSerializeFunc(scanning.EventTypeScannerRegistered, ScannerRegisteredEventToProto)
	registerProtoSerializeFunc(scanning.EventTypeScannerStatusChanged, ScannerStatusChangedEventToProto)
	registerProtoSerializeFunc(scanning.EventTypeScannerDeregistered, ScannerDeregisteredEventToProto)

	// Scanner related deserialization functions.
	registerProtoDeserializeFunc(scanning.EventTypeScannerHeartbeat, ProtoToScannerHeartbeatEvent)
	registerProtoDeserializeFunc(scanning.EventTypeScannerRegistered, ProtoToScannerRegisteredEvent)
	registerProtoDeserializeFunc(scanning.EventTypeScannerStatusChanged, ProtoToScannerStatusChangedEvent)
	registerProtoDeserializeFunc(scanning.EventTypeScannerDeregistered, ProtoToScannerDeregisteredEvent)

	// Task related events.
	registerProtoSerializeFunc(scanning.EventTypeTaskCreated, TaskCreatedEventToProto)
	registerProtoSerializeFunc(scanning.EventTypeTaskStarted, TaskStartedEventToProto)
	registerProtoSerializeFunc(scanning.EventTypeTaskProgressed, TaskProgressedEventToProto)
	registerProtoSerializeFunc(scanning.EventTypeTaskCompleted, TaskCompletedEventToProto)
	registerProtoSerializeFunc(scanning.EventTypeTaskFailed, TaskFailedEventToProto)
	registerProtoSerializeFunc(scanning.EventTypeTaskPaused, TaskPausedEventToProto)
	registerProtoSerializeFunc(scanning.EventTypeTaskCancelled, TaskCancelledEventToProto)
	registerProtoSerializeFunc(scanning.EventTypeTaskResume, TaskResumeEventToProto)
	registerProtoSerializeFunc(scanning.EventTypeTaskHeartbeat, TaskHeartbeatEventToProto)
	registerProtoSerializeFunc(scanning.EventTypeTaskJobMetric, TaskJobMetricEventToProto)

	// Task related deserialization functions.
	registerProtoDeserializeFunc(scanning.EventTypeTaskStarted, ProtoToTaskStartedEvent)
	registerProtoDeserializeFunc(scanning.EventTypeTaskProgressed, ProtoToTaskProgressedEvent)
	registerProtoDeserializeFunc(scanning.EventTypeTaskCompleted, ProtoToTaskCompletedEvent)
	registerProtoDeserializeFunc(scanning.EventTypeTaskFailed, ProtoToTaskFailedEvent)
	registerProtoDeserializeFunc(scanning.EventTypeTaskPaused, ProtoToTaskPausedEvent)
	registerProtoDeserializeFunc(scanning.EventTypeTaskCancelled, ProtoToTaskCancelledEvent)

	// Job related events.
	registerProtoSerializeFunc(scanning.EventTypeJobRequested, JobRequestedEventToProto)
	registerProtoSerializeFunc(scanning.EventTypeJobScheduled, JobCreatedEventToProto)
	registerProtoSerializeFunc(scanning.EventTypeJobEnumerationCompleted, JobEnumerationCompletedEventToProto)
	registerProtoSerializeFunc(scanning.EventTypeJobPausing, JobPausingEventToProto)
	registerProtoSerializeFunc(scanning.EventTypeJobPaused, JobPausedEventToProto)
	registerProtoSerializeFunc(scanning.EventTypeJobResuming, JobResumingEventToProto)
	registerProtoSerializeFunc(scanning.EventTypeJobCancelling, JobCancellingEventToProto)
	registerProtoSerializeFunc(scanning.EventTypeJobCancelled, JobCancelledEventToProto)

	// Rule related events.
	registerProtoSerializeFunc(rules.EventTypeRulesUpdated, RuleUpdatedEventToProto)
	registerProtoSerializeFunc(rules.EventTypeRulesRequested, RuleRequestedEventToProto)
	registerProtoSerializeFunc(rules.EventTypeRulesPublished, RulePublishedEventToProto)

	// Rule related deserialization functions.
	registerProtoDeserializeFunc(rules.EventTypeRulesUpdated, ProtoToRuleUpdatedEvent)
	registerProtoDeserializeFunc(rules.EventTypeRulesRequested, ProtoToRuleRequestedEvent)
	registerProtoDeserializeFunc(rules.EventTypeRulesPublished, ProtoToRulePublishedEvent)

	// System related events.
	registerProtoSerializeFunc(events.EventType("SystemNotification"), SystemNotificationToProto)

	// Add serializer for MessageAck event - using string literal to avoid circular imports.
	registerProtoSerializeFunc(events.EventType("MessageAck"), MessageAckToProto)
	registerProtoDeserializeFunc(events.EventType("MessageAck"), ProtoToMessageAck)
}

// Initialize the registry when the package is loaded.
func init() { registerProtoSerializers() }

// Serialization functions for domain events to protocol buffers

// ScannerHeartbeatEventToProto converts a ScannerHeartbeatEvent to a protocol buffer message.
func ScannerHeartbeatEventToProto(payload any) (any, error) {
	event, ok := payload.(scanning.ScannerHeartbeatEvent)
	if !ok {
		return nil, fmt.Errorf("payload is not a ScannerHeartbeatEvent: %T", payload)
	}

	return pbscanning.ScannerHeartbeatEventToProto(event), nil
}

// ScannerRegisteredEventToProto converts a ScannerRegisteredEvent to a protocol buffer message.
func ScannerRegisteredEventToProto(payload any) (any, error) {
	event, ok := payload.(scanning.ScannerRegisteredEvent)
	if !ok {
		return nil, fmt.Errorf("payload is not a ScannerRegisteredEvent: %T", payload)
	}

	return pbscanning.ScannerRegisteredEventToProto(event), nil
}

// ScannerStatusChangedEventToProto converts a ScannerStatusChangedEvent to a protocol buffer message.
func ScannerStatusChangedEventToProto(payload any) (any, error) {
	event, ok := payload.(scanning.ScannerStatusChangedEvent)
	if !ok {
		return nil, fmt.Errorf("payload is not a ScannerStatusChangedEvent: %T", payload)
	}

	return pbscanning.ScannerStatusChangedEventToProto(event), nil
}

// ScannerDeregisteredEventToProto converts a ScannerDeregisteredEvent to a protocol buffer message.
func ScannerDeregisteredEventToProto(payload any) (any, error) {
	event, ok := payload.(scanning.ScannerDeregisteredEvent)
	if !ok {
		return nil, fmt.Errorf("payload is not a ScannerDeregisteredEvent: %T", payload)
	}

	return pbscanning.ScannerDeregisteredEventToProto(event), nil
}

// TaskCreatedEventToProto converts a TaskCreatedEvent to a protocol buffer message.
func TaskCreatedEventToProto(payload any) (any, error) {
	event, ok := payload.(*scanning.TaskCreatedEvent)
	if !ok {
		return nil, fmt.Errorf("payload is not a TaskCreatedEvent: %T", payload)
	}

	return pbscanning.TaskCreatedEventToProto(event), nil
}

// TaskStartedEventToProto converts a TaskStartedEvent to a protocol buffer message.
func TaskStartedEventToProto(payload any) (any, error) {
	event, ok := payload.(scanning.TaskStartedEvent)
	if !ok {
		return nil, fmt.Errorf("payload is not a TaskStartedEvent: %T", payload)
	}

	return pbscanning.TaskStartedEventToProto(event), nil
}

// TaskProgressedEventToProto converts a TaskProgressedEvent to a protocol buffer message.
func TaskProgressedEventToProto(payload any) (any, error) {
	event, ok := payload.(scanning.TaskProgressedEvent)
	if !ok {
		return nil, fmt.Errorf("payload is not a TaskProgressedEvent: %T", payload)
	}

	return pbscanning.TaskProgressedEventToProto(event), nil
}

// TaskCompletedEventToProto converts a TaskCompletedEvent to a protocol buffer message.
func TaskCompletedEventToProto(payload any) (any, error) {
	event, ok := payload.(scanning.TaskCompletedEvent)
	if !ok {
		return nil, fmt.Errorf("payload is not a TaskCompletedEvent: %T", payload)
	}

	return pbscanning.TaskCompletedEventToProto(event), nil
}

// TaskFailedEventToProto converts a TaskFailedEvent to a protocol buffer message.
func TaskFailedEventToProto(payload any) (any, error) {
	event, ok := payload.(scanning.TaskFailedEvent)
	if !ok {
		return nil, fmt.Errorf("payload is not a TaskFailedEvent: %T", payload)
	}

	return pbscanning.TaskFailedEventToProto(event), nil
}

// TaskPausedEventToProto converts a TaskPausedEvent to a protocol buffer message.
func TaskPausedEventToProto(payload any) (any, error) {
	event, ok := payload.(scanning.TaskPausedEvent)
	if !ok {
		return nil, fmt.Errorf("payload is not a TaskPausedEvent: %T", payload)
	}

	return pbscanning.TaskPausedEventToProto(event), nil
}

// TaskCancelledEventToProto converts a TaskCancelledEvent to a protocol buffer message.
func TaskCancelledEventToProto(payload any) (any, error) {
	event, ok := payload.(scanning.TaskCancelledEvent)
	if !ok {
		return nil, fmt.Errorf("payload is not a TaskCancelledEvent: %T", payload)
	}

	return pbscanning.TaskCancelledEventToProto(event), nil
}

// TaskResumeEventToProto converts a TaskResumeEvent to a protocol buffer message.
func TaskResumeEventToProto(payload any) (any, error) {
	event, ok := payload.(*scanning.TaskResumeEvent)
	if !ok {
		return nil, fmt.Errorf("payload is not a TaskResumeEvent: %T", payload)
	}

	return pbscanning.TaskResumeEventToProto(event)
}

// TaskHeartbeatEventToProto converts a TaskHeartbeatEvent to a protocol buffer message.
func TaskHeartbeatEventToProto(payload any) (any, error) {
	event, ok := payload.(scanning.TaskHeartbeatEvent)
	if !ok {
		return nil, fmt.Errorf("payload is not a TaskHeartbeatEvent: %T", payload)
	}

	return pbscanning.TaskHeartbeatEventToProto(event), nil
}

// TaskJobMetricEventToProto converts a TaskJobMetricEvent to a protocol buffer message.
func TaskJobMetricEventToProto(payload any) (any, error) {
	event, ok := payload.(scanning.TaskJobMetricEvent)
	if !ok {
		return nil, fmt.Errorf("payload is not a TaskJobMetricEvent: %T", payload)
	}

	return pbscanning.TaskJobMetricEventToProto(event), nil
}

// JobRequestedEventToProto converts a JobRequestedEvent to a protocol buffer message.
func JobRequestedEventToProto(payload any) (any, error) {
	event, ok := payload.(scanning.JobRequestedEvent)
	if !ok {
		return nil, fmt.Errorf("payload is not a JobRequestedEvent: %T", payload)
	}

	return pbscanning.JobRequestedEventToProto(event)
}

// JobCreatedEventToProto converts a JobCreatedEvent to a protocol buffer message.
func JobCreatedEventToProto(payload any) (any, error) {
	event, ok := payload.(scanning.JobScheduledEvent)
	if !ok {
		return nil, fmt.Errorf("payload is not a JobScheduledEvent: %T", payload)
	}

	return pbscanning.JobCreatedEventToProto(event)
}

// JobEnumerationCompletedEventToProto converts a JobEnumerationCompletedEvent to a protocol buffer message.
func JobEnumerationCompletedEventToProto(payload any) (any, error) {
	event, ok := payload.(scanning.JobEnumerationCompletedEvent)
	if !ok {
		return nil, fmt.Errorf("payload is not a JobEnumerationCompletedEvent: %T", payload)
	}

	return pbscanning.JobEnumerationCompletedEventToProto(event), nil
}

// JobPausingEventToProto converts a JobPausingEvent to a protocol buffer message.
func JobPausingEventToProto(payload any) (any, error) {
	event, ok := payload.(scanning.JobPausingEvent)
	if !ok {
		return nil, fmt.Errorf("payload is not a JobPausingEvent: %T", payload)
	}

	return pbscanning.JobPausingEventToProto(event), nil
}

// JobPausedEventToProto converts a JobPausedEvent to a protocol buffer message.
func JobPausedEventToProto(payload any) (any, error) {
	event, ok := payload.(scanning.JobPausedEvent)
	if !ok {
		return nil, fmt.Errorf("payload is not a JobPausedEvent: %T", payload)
	}

	return pbscanning.JobPausedEventToProto(event), nil
}

// JobResumingEventToProto converts a JobResumingEvent to a protocol buffer message.
func JobResumingEventToProto(payload any) (any, error) {
	event, ok := payload.(scanning.JobResumingEvent)
	if !ok {
		return nil, fmt.Errorf("payload is not a JobResumingEvent: %T", payload)
	}

	return pbscanning.JobResumingEventToProto(event), nil
}

// JobCancellingEventToProto converts a JobCancellingEvent to a protocol buffer message.
func JobCancellingEventToProto(payload any) (any, error) {
	event, ok := payload.(scanning.JobCancellingEvent)
	if !ok {
		return nil, fmt.Errorf("payload is not a JobCancellingEvent: %T", payload)
	}

	return pbscanning.JobCancellingEventToProto(event), nil
}

// JobCancelledEventToProto converts a JobCancelledEvent to a protocol buffer message.
func JobCancelledEventToProto(payload any) (any, error) {
	event, ok := payload.(scanning.JobCancelledEvent)
	if !ok {
		return nil, fmt.Errorf("payload is not a JobCancelledEvent: %T", payload)
	}

	return pbscanning.JobCancelledEventToProto(event), nil
}

// RuleUpdatedEventToProto converts a RuleUpdatedEvent to a protocol buffer message.
func RuleUpdatedEventToProto(payload any) (any, error) {
	event, ok := payload.(rules.RuleUpdatedEvent)
	if !ok {
		return nil, fmt.Errorf("payload is not a RuleUpdatedEvent: %T", payload)
	}

	// Access the Rule directly to convert to proto
	protoMsg := pbrules.GitleaksRulesMessageToProto(event.Rule)
	return protoMsg, nil
}

// RuleRequestedEventToProto converts a RuleRequestedEvent to a protocol buffer message.
// The RuleRequestedEvent is triggered by the controller to distribute rules to all scanners.
// This is NOT a request from scanners for rules, but rather an internal event in the
// controller that initiates the process of pushing rules to all connected scanners.
func RuleRequestedEventToProto(payload any) (any, error) {
	_, ok := payload.(rules.RuleRequestedEvent)
	if !ok {
		return nil, fmt.Errorf("payload is not a RuleRequestedEvent: %T", payload)
	}

	// The RuleRequestedEvent doesn't carry any payload data
	// It's an internal event in the controller that triggers rule distribution
	// to all connected scanners via the established streams
	return &pb.RuleRequestedEvent{}, nil
}

// RulePublishedEventToProto converts a RulePublishedEvent to a protocol buffer message.
func RulePublishedEventToProto(payload any) (any, error) {
	_, ok := payload.(rules.RulePublishingCompletedEvent)
	if !ok {
		return nil, fmt.Errorf("payload is not a RulePublishingCompletedEvent: %T", payload)
	}

	return &pb.RulePublishingCompletedEvent{}, nil
}

// SystemNotificationToProto handles system notifications which are already in proto form.
func SystemNotificationToProto(payload any) (any, error) {
	notification, ok := payload.(*pb.SystemNotification)
	if !ok {
		return nil, fmt.Errorf("payload is not a SystemNotification: %T", payload)
	}
	return notification, nil
}

// MessageAckToProto converts a MessageAcknowledgment to its proto representation.
// In this case, the MessageAcknowledgment is already in proto form, so we simply pass it through.
func MessageAckToProto(payload any) (any, error) {
	ack, ok := payload.(*pb.MessageAcknowledgment)
	if !ok {
		return nil, fmt.Errorf("payload is not a MessageAcknowledgment: %T", payload)
	}
	return ack, nil
}

// Deserialization functions for protocol buffers to domain events

// ProtoToScannerHeartbeatEvent converts a protocol buffer message to a ScannerHeartbeatEvent.
func ProtoToScannerHeartbeatEvent(message any) (any, error) {
	heartbeat, ok := message.(*pb.ScannerHeartbeatEvent)
	if !ok {
		return nil, fmt.Errorf("message is not a ScannerHeartbeatEvent: %T", message)
	}

	// Create a metrics map from the metrics field
	metrics := heartbeat.Metrics

	// Convert status directly from proto enum
	status := scanning.ScannerStatusFromProtoEnum(heartbeat.Status)

	scannerID, err := uuid.Parse(heartbeat.ScannerId)
	if err != nil {
		return nil, fmt.Errorf("invalid scanner ID: %w", err)
	}

	return scanning.NewScannerHeartbeatEvent(
		scannerID,
		heartbeat.ScannerName,
		status,
		metrics,
	), nil
}

// ProtoToScannerRegisteredEvent converts a protocol buffer message to a ScannerRegisteredEvent.
func ProtoToScannerRegisteredEvent(message any) (any, error) {
	reg, ok := message.(*pb.ScannerRegisteredEvent)
	if !ok {
		return nil, fmt.Errorf("message is not a ScannerRegisteredEvent: %T", message)
	}

	scannerID, err := uuid.Parse(reg.ScannerId)
	if err != nil {
		return nil, fmt.Errorf("invalid scanner ID: %w", err)
	}

	// Create a scanner registration event with available fields
	return scanning.NewScannerRegisteredEvent(
		scannerID,
		reg.ScannerName,              // ID
		reg.Version,                  // Version
		reg.Capabilities,             // Capabilities
		reg.Hostname,                 // Host name from request (corrected order)
		"",                           // IP Address (not provided in proto)
		reg.GroupName,                // Group name
		reg.Tags,                     // Tags from request
		scanning.ScannerStatusOnline, // Default to Online status
	), nil
}

// ProtoToScannerStatusChangedEvent converts a protocol buffer message to a ScannerStatusChangedEvent.
func ProtoToScannerStatusChangedEvent(message any) (any, error) {
	status, ok := message.(*pb.ScannerStatusChangedEvent)
	if !ok {
		return nil, fmt.Errorf("message is not a ScannerStatusChangedEvent: %T", message)
	}

	// Convert statuses using the proper domain model functions
	oldStatus := scanning.ScannerStatusFromProtoEnum(status.PreviousStatus)
	newStatus := scanning.ScannerStatusFromProtoEnum(status.NewStatus)

	scannerID, err := uuid.Parse(status.ScannerId)
	if err != nil {
		return nil, fmt.Errorf("invalid scanner ID: %w", err)
	}

	return scanning.NewScannerStatusChangedEvent(
		scannerID,
		status.ScannerName,
		oldStatus,
		newStatus,
		status.Reason,
	), nil
}

// ProtoToScannerDeregisteredEvent converts a protocol buffer message to a ScannerDeregisteredEvent.
func ProtoToScannerDeregisteredEvent(message any) (any, error) {
	dereg, ok := message.(*pb.ScannerDeregisteredEvent)
	if !ok {
		return nil, fmt.Errorf("message is not a ScannerDeregisteredEvent: %T", message)
	}

	scannerID, err := uuid.Parse(dereg.ScannerId)
	if err != nil {
		return nil, fmt.Errorf("invalid scanner ID: %w", err)
	}

	return scanning.NewScannerDeregisteredEvent(
		scannerID,
		dereg.ScannerName,
		dereg.Reason,
	), nil
}

// ProtoToTaskStartedEvent converts a protocol buffer message to a TaskStartedEvent.
func ProtoToTaskStartedEvent(message any) (any, error) {
	taskStarted, ok := message.(*pb.TaskStartedEvent)
	if !ok {
		return nil, fmt.Errorf("message is not a TaskStartedEvent: %T", message)
	}

	// Convert string IDs to UUIDs
	jobID, err := uuid.Parse(taskStarted.JobId)
	if err != nil {
		return nil, fmt.Errorf("invalid job ID: %w", err)
	}
	taskID, err := uuid.Parse(taskStarted.TaskId)
	if err != nil {
		return nil, fmt.Errorf("invalid task ID: %w", err)
	}

	scannerID, err := uuid.Parse(taskStarted.ScannerId)
	if err != nil {
		return nil, fmt.Errorf("invalid scanner ID: %w", err)
	}

	// Convert the task started event to domain event
	return scanning.NewTaskStartedEvent(
		jobID,
		taskID,
		scannerID,
		taskStarted.ResourceUri,
	), nil
}

// ProtoToTaskProgressedEvent converts a protocol buffer message to a TaskProgressedEvent.
func ProtoToTaskProgressedEvent(message any) (any, error) {
	taskProgressed, ok := message.(*pb.TaskProgressedEvent)
	if !ok {
		return nil, fmt.Errorf("message is not a TaskProgressedEvent: %T", message)
	}

	// Convert string IDs to UUIDs
	taskID, err := uuid.Parse(taskProgressed.TaskId)
	if err != nil {
		return nil, fmt.Errorf("invalid task ID: %w", err)
	}

	jobID, err := uuid.Parse(taskProgressed.JobId)
	if err != nil {
		return nil, fmt.Errorf("invalid job ID: %w", err)
	}

	// Create a Progress struct using the constructor
	progress := scanning.NewProgress(
		taskID,
		jobID,
		taskProgressed.SequenceNum,
		time.Unix(0, taskProgressed.Timestamp), // Convert timestamp to time.Time
		taskProgressed.ItemsProcessed,
		taskProgressed.ErrorCount,
		taskProgressed.Message,
		nil, // No progress details in proto
		nil, // No checkpoint in proto
	)

	// Convert the task progressed event to domain event
	return scanning.NewTaskProgressedEvent(progress), nil
}

// ProtoToTaskCompletedEvent converts a protocol buffer message to a TaskCompletedEvent.
func ProtoToTaskCompletedEvent(message any) (any, error) {
	taskCompleted, ok := message.(*pb.TaskCompletedEvent)
	if !ok {
		return nil, fmt.Errorf("message is not a TaskCompletedEvent: %T", message)
	}

	// Convert string IDs to UUIDs
	jobID, err := uuid.Parse(taskCompleted.JobId)
	if err != nil {
		return nil, fmt.Errorf("invalid job ID: %w", err)
	}
	taskID, err := uuid.Parse(taskCompleted.TaskId)
	if err != nil {
		return nil, fmt.Errorf("invalid task ID: %w", err)
	}

	// Convert the task completed event to domain event
	return scanning.NewTaskCompletedEvent(
		jobID,
		taskID,
	), nil
}

// ProtoToTaskFailedEvent converts a protocol buffer message to a TaskFailedEvent.
func ProtoToTaskFailedEvent(message any) (any, error) {
	taskFailed, ok := message.(*pb.TaskFailedEvent)
	if !ok {
		return nil, fmt.Errorf("message is not a TaskFailedEvent: %T", message)
	}

	// Convert string IDs to UUIDs
	jobID, err := uuid.Parse(taskFailed.JobId)
	if err != nil {
		return nil, fmt.Errorf("invalid job ID: %w", err)
	}
	taskID, err := uuid.Parse(taskFailed.TaskId)
	if err != nil {
		return nil, fmt.Errorf("invalid task ID: %w", err)
	}

	// Convert the task failed event to domain event
	return scanning.NewTaskFailedEvent(
		jobID,
		taskID,
		taskFailed.Reason,
	), nil
}

// ProtoToTaskPausedEvent converts a protocol buffer message to a TaskPausedEvent.
func ProtoToTaskPausedEvent(message any) (any, error) {
	taskPaused, ok := message.(*pb.TaskPausedEvent)
	if !ok {
		return nil, fmt.Errorf("message is not a TaskPausedEvent: %T", message)
	}

	// Convert string IDs to UUIDs
	jobID, err := uuid.Parse(taskPaused.JobId)
	if err != nil {
		return nil, fmt.Errorf("invalid job ID: %w", err)
	}
	taskID, err := uuid.Parse(taskPaused.TaskId)
	if err != nil {
		return nil, fmt.Errorf("invalid task ID: %w", err)
	}

	// Create progress with the constructor if there's progress info in the event
	var progress scanning.Progress
	if taskPaused.Progress != nil {
		progressTaskID, err := uuid.Parse(taskPaused.Progress.TaskId)
		if err != nil {
			return nil, fmt.Errorf("invalid progress task ID: %w", err)
		}

		progressJobID, err := uuid.Parse(taskPaused.Progress.JobId)
		if err != nil {
			return nil, fmt.Errorf("invalid progress job ID: %w", err)
		}

		progress = scanning.NewProgress(
			progressTaskID,
			progressJobID,
			taskPaused.Progress.SequenceNum,
			time.Unix(0, taskPaused.Progress.Timestamp),
			taskPaused.Progress.ItemsProcessed,
			taskPaused.Progress.ErrorCount,
			taskPaused.Progress.Message,
			nil, // No progress details
			nil, // No checkpoint
		)
	} else {
		// Create empty progress if none was provided
		progress = scanning.NewProgress(
			taskID,
			jobID,
			0,             // sequence number
			time.Now(),    // timestamp
			0,             // items processed
			0,             // error count
			"Task paused", // message
			nil,           // no progress details
			nil,           // no checkpoint
		)
	}

	// Convert the task paused event to domain event
	return scanning.NewTaskPausedEvent(
		jobID,
		taskID,
		progress,
		taskPaused.RequestedBy,
	), nil
}

// ProtoToTaskCancelledEvent converts a protocol buffer message to a TaskCancelledEvent.
func ProtoToTaskCancelledEvent(message any) (any, error) {
	taskCancelled, ok := message.(*pb.TaskCancelledEvent)
	if !ok {
		return nil, fmt.Errorf("message is not a TaskCancelledEvent: %T", message)
	}

	// Convert string IDs to UUIDs
	jobID, err := uuid.Parse(taskCancelled.JobId)
	if err != nil {
		return nil, fmt.Errorf("invalid job ID: %w", err)
	}
	taskID, err := uuid.Parse(taskCancelled.TaskId)
	if err != nil {
		return nil, fmt.Errorf("invalid task ID: %w", err)
	}

	// Convert the task cancelled event to domain event
	return scanning.NewTaskCancelledEvent(
		jobID,
		taskID,
		taskCancelled.RequestedBy,
	), nil
}

// ProtoToRuleUpdatedEvent converts a protocol buffer message to a RuleUpdatedEvent.
func ProtoToRuleUpdatedEvent(message any) (any, error) {
	msg, ok := message.(*pb.RuleMessage)
	if !ok {
		return nil, fmt.Errorf("message is not a RuleMessage: %T", message)
	}

	// Convert pb.RuleMessage to domain GitleaksRuleMessage using the proper converter
	ruleMsg := pbrules.ProtoToGitleaksRuleMessage(msg)
	return rules.NewRuleUpdatedEvent(ruleMsg), nil
}

// ProtoToRulePublishedEvent converts a protocol buffer message to a RulePublishingCompletedEvent.
func ProtoToRulePublishedEvent(message any) (any, error) {
	_, ok := message.(*pb.RulePublishingCompletedEvent)
	if !ok {
		return nil, fmt.Errorf("message is not a RulePublishingCompletedEvent: %T", message)
	}

	return rules.NewRulePublishingCompletedEvent(), nil
}

// ProtoToRuleRequestedEvent converts a protocol buffer message to a RuleRequestedEvent.
func ProtoToRuleRequestedEvent(message any) (any, error) {
	_, ok := message.(*pb.RuleRequestedEvent)
	if !ok {
		return nil, fmt.Errorf("message is not a RuleRequestedEvent: %T", message)
	}

	return rules.NewRuleRequestedEvent(), nil
}

// ProtoToMessageAck converts a proto MessageAcknowledgment to its domain representation.
// Since we're directly using the proto type in this case, we simply pass it through.
func ProtoToMessageAck(message any) (any, error) {
	ack, ok := message.(*pb.MessageAcknowledgment)
	if !ok {
		return nil, fmt.Errorf("message is not a MessageAcknowledgment: %T", message)
	}
	return ack, nil
}
