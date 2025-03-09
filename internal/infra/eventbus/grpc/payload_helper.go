// Package grpc provides gRPC-based implementations of event bus components.
package grpc

import (
	"context"
	"fmt"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/domain/rules"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/internal/infra/eventbus/serialization"
	pb "github.com/ahrav/gitleaks-armada/proto"
)

// SetGatewayToScannerPayload sets the appropriate payload field in a GatewayToScannerMessage
// based on the event type.
func SetGatewayToScannerPayload(msg *pb.GatewayToScannerMessage, eventType events.EventType, payload any) error {
	switch eventType {
	// Task related events.
	case scanning.EventTypeTaskCreated:
		taskCreated, ok := payload.(*pb.TaskCreatedEvent)
		if !ok {
			return fmt.Errorf("payload is not a TaskCreatedEvent: %T", payload)
		}
		msg.Payload = &pb.GatewayToScannerMessage_TaskCreated{TaskCreated: taskCreated}

	case scanning.EventTypeTaskResume:
		taskResume, ok := payload.(*pb.TaskResumeEvent)
		if !ok {
			return fmt.Errorf("payload is not a TaskResumeEvent: %T", payload)
		}
		msg.Payload = &pb.GatewayToScannerMessage_TaskResume{TaskResume: taskResume}

	case scanning.EventTypeTaskPaused:
		taskPaused, ok := payload.(*pb.TaskPausedEvent)
		if !ok {
			return fmt.Errorf("payload is not a TaskPausedEvent: %T", payload)
		}
		msg.Payload = &pb.GatewayToScannerMessage_TaskPaused{TaskPaused: taskPaused}

	// Job related events.
	case scanning.EventTypeJobPaused:
		jobPaused, ok := payload.(*pb.JobPausedEvent)
		if !ok {
			return fmt.Errorf("payload is not a JobPausedEvent: %T", payload)
		}
		msg.Payload = &pb.GatewayToScannerMessage_JobPaused{JobPaused: jobPaused}

	case scanning.EventTypeJobCancelled:
		jobCancelled, ok := payload.(*pb.JobCancelledEvent)
		if !ok {
			return fmt.Errorf("payload is not a JobCancelledEvent: %T", payload)
		}
		msg.Payload = &pb.GatewayToScannerMessage_JobCancelled{JobCancelled: jobCancelled}

	// Rules related events.
	case rules.EventTypeRulesRequested:
		ruleRequested, ok := payload.(*pb.RuleRequestedEvent)
		if !ok {
			return fmt.Errorf("payload is not a RuleRequestedEvent: %T", payload)
		}
		msg.Payload = &pb.GatewayToScannerMessage_RuleRequested{RuleRequested: ruleRequested}

	case events.EventType("SystemNotification"):
		notification, ok := payload.(*pb.SystemNotification)
		if !ok {
			return fmt.Errorf("payload is not a SystemNotification: %T", payload)
		}
		msg.Payload = &pb.GatewayToScannerMessage_Notification{Notification: notification}

	default:
		return fmt.Errorf("unhandled event type: %s", eventType)
	}

	return nil
}

// SetScannerToGatewayPayload sets the appropriate payload field in a ScannerToGatewayMessage
// based on the event type. This function handles scanner-to-controller direction events.
func SetScannerToGatewayPayload(msg *pb.ScannerToGatewayMessage, eventType events.EventType, payload any) error {
	switch eventType {
	// Scanner lifecycle events - scanner to controller.
	case scanning.EventTypeScannerRegistered:
		registration, ok := payload.(*pb.ScannerRegistrationRequest)
		if !ok {
			return fmt.Errorf("payload is not a ScannerRegistrationRequest: %T", payload)
		}
		msg.Payload = &pb.ScannerToGatewayMessage_Registration{Registration: registration}

	case scanning.EventTypeScannerHeartbeat:
		heartbeat, ok := payload.(*pb.ScannerHeartbeatEvent)
		if !ok {
			return fmt.Errorf("payload is not a ScannerHeartbeatEvent: %T", payload)
		}
		msg.Payload = &pb.ScannerToGatewayMessage_Heartbeat{Heartbeat: heartbeat}

	case scanning.EventTypeScannerStatusChanged:
		statusChanged, ok := payload.(*pb.ScannerStatusChangedEvent)
		if !ok {
			return fmt.Errorf("payload is not a ScannerStatusChangedEvent: %T", payload)
		}
		msg.Payload = &pb.ScannerToGatewayMessage_StatusChanged{StatusChanged: statusChanged}

	case scanning.EventTypeScannerDeregistered:
		deregistered, ok := payload.(*pb.ScannerDeregisteredEvent)
		if !ok {
			return fmt.Errorf("payload is not a ScannerDeregisteredEvent: %T", payload)
		}
		msg.Payload = &pb.ScannerToGatewayMessage_Deregistered{Deregistered: deregistered}

	// Task events - scanner to controller.
	case scanning.EventTypeTaskStarted:
		taskStarted, ok := payload.(*pb.TaskStartedEvent)
		if !ok {
			return fmt.Errorf("payload is not a TaskStartedEvent: %T", payload)
		}
		msg.Payload = &pb.ScannerToGatewayMessage_TaskStarted{TaskStarted: taskStarted}

	case scanning.EventTypeTaskProgressed:
		taskProgressed, ok := payload.(*pb.TaskProgressedEvent)
		if !ok {
			return fmt.Errorf("payload is not a TaskProgressedEvent: %T", payload)
		}
		msg.Payload = &pb.ScannerToGatewayMessage_TaskProgressed{TaskProgressed: taskProgressed}

	case scanning.EventTypeTaskCompleted:
		taskCompleted, ok := payload.(*pb.TaskCompletedEvent)
		if !ok {
			return fmt.Errorf("payload is not a TaskCompletedEvent: %T", payload)
		}
		msg.Payload = &pb.ScannerToGatewayMessage_TaskCompleted{TaskCompleted: taskCompleted}

	case scanning.EventTypeTaskFailed:
		taskFailed, ok := payload.(*pb.TaskFailedEvent)
		if !ok {
			return fmt.Errorf("payload is not a TaskFailedEvent: %T", payload)
		}
		msg.Payload = &pb.ScannerToGatewayMessage_TaskFailed{TaskFailed: taskFailed}

	case scanning.EventTypeTaskPaused:
		taskPaused, ok := payload.(*pb.TaskPausedEvent)
		if !ok {
			return fmt.Errorf("payload is not a TaskPausedEvent: %T", payload)
		}
		msg.Payload = &pb.ScannerToGatewayMessage_TaskPaused{TaskPaused: taskPaused}

	case scanning.EventTypeTaskCancelled:
		taskCancelled, ok := payload.(*pb.TaskCancelledEvent)
		if !ok {
			return fmt.Errorf("payload is not a TaskCancelledEvent: %T", payload)
		}
		msg.Payload = &pb.ScannerToGatewayMessage_TaskCancelled{TaskCancelled: taskCancelled}

	case scanning.EventTypeTaskHeartbeat:
		taskHeartbeat, ok := payload.(*pb.TaskHeartbeatEvent)
		if !ok {
			return fmt.Errorf("payload is not a TaskHeartbeatEvent: %T", payload)
		}
		msg.Payload = &pb.ScannerToGatewayMessage_TaskHeartbeat{TaskHeartbeat: taskHeartbeat}

	case scanning.EventTypeTaskJobMetric:
		taskJobMetric, ok := payload.(*pb.TaskJobMetricEvent)
		if !ok {
			return fmt.Errorf("payload is not a TaskJobMetricEvent: %T", payload)
		}
		msg.Payload = &pb.ScannerToGatewayMessage_TaskJobMetric{TaskJobMetric: taskJobMetric}

	// Rules events - scanner to controller.
	case rules.EventTypeRulesUpdated:
		rulesUpdate, ok := payload.(*pb.RuleMessage)
		if !ok {
			return fmt.Errorf("payload is not a RuleMessage: %T", payload)
		}
		msg.Payload = &pb.ScannerToGatewayMessage_RuleMessage{RuleMessage: rulesUpdate}

	case rules.EventTypeRulesPublished:
		rulesPublished, ok := payload.(*pb.RuleMessage)
		if !ok {
			return fmt.Errorf("payload is not a RuleMessage: %T", payload)
		}
		msg.Payload = &pb.ScannerToGatewayMessage_RuleMessage{RuleMessage: rulesPublished}

	// Acknowledgment event.
	case events.EventType("MessageAcknowledgment"):
		ack, ok := payload.(*pb.MessageAcknowledgment)
		if !ok {
			return fmt.Errorf("payload is not a MessageAcknowledgment: %T", payload)
		}
		msg.Payload = &pb.ScannerToGatewayMessage_Ack{Ack: ack}

	default:
		return fmt.Errorf("unhandled scanner-to-gateway event type: %s", eventType)
	}

	return nil
}

// getScannerToGatewayMessageType determines the type of message contained in a ScannerToGatewayMessage.
// Returns the message type string, the message payload, and any error.
func getScannerToGatewayMessageType(msg *pb.ScannerToGatewayMessage) (MessageType, any, error) {
	switch {
	// Scanner events.
	case msg.GetHeartbeat() != nil:
		return MessageTypeScannerHeartbeat, msg.GetHeartbeat(), nil

	case msg.GetRegistration() != nil:
		return MessageTypeScannerRegistered, msg.GetRegistration(), nil

	case msg.GetStatusChanged() != nil:
		return MessageTypeScannerStatusChanged, msg.GetStatusChanged(), nil

	case msg.GetDeregistered() != nil:
		return MessageTypeScannerDeregistered, msg.GetDeregistered(), nil

	// Task events.
	case msg.GetTaskStarted() != nil:
		return MessageTypeScanTaskStarted, msg.GetTaskStarted(), nil

	case msg.GetTaskProgressed() != nil:
		return MessageTypeScanTaskProgressed, msg.GetTaskProgressed(), nil

	case msg.GetTaskCompleted() != nil:
		return MessageTypeScanTaskCompleted, msg.GetTaskCompleted(), nil

	case msg.GetTaskFailed() != nil:
		return MessageTypeScanTaskFailed, msg.GetTaskFailed(), nil

	case msg.GetTaskPaused() != nil:
		return MessageTypeScanTaskPaused, msg.GetTaskPaused(), nil

	case msg.GetTaskCancelled() != nil:
		return MessageTypeScanTaskCancelled, msg.GetTaskCancelled(), nil

	case msg.GetTaskJobMetric() != nil:
		return MessageTypeScanTaskJobMetric, msg.GetTaskJobMetric(), nil

	case msg.GetTaskHeartbeat() != nil:
		return MessageTypeScanTaskHeartbeat, msg.GetTaskHeartbeat(), nil

	// Acknowledgment.
	case msg.GetAck() != nil:
		return MessageTypeAck, msg.GetAck(), nil

	default:
		return "", nil, fmt.Errorf("unknown message type in ScannerToGatewayMessage")
	}
}

// ExtractScannerMessageInfo processes an incoming ScannerToGatewayMessage by determining its message type,
// converting it to a domain event, and returning the event type and payload.
func ExtractScannerMessageInfo(
	ctx context.Context,
	msg *pb.ScannerToGatewayMessage,
) (events.EventType, any, error) {
	span := trace.SpanFromContext(ctx)
	defer span.End()

	// Determine message type and get the payload.
	messageType, protoMsg, err := getScannerToGatewayMessageType(msg)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return "", nil, err
	}

	span.SetAttributes(attribute.String("message_type", messageType.String()))

	eventType := mapMessageTypeToEventType(messageType)
	if eventType == "" {
		span.SetStatus(codes.Error, "unknown message type")
		return "", nil, fmt.Errorf("unknown message type for event mapping: %s", messageType)
	}

	// For acknowledgment messages, we don't need to convert to domain event.
	if messageType == MessageTypeAck {
		ack, ok := protoMsg.(*pb.MessageAcknowledgment)
		if !ok {
			err := fmt.Errorf("expected MessageAcknowledgment, got %T", protoMsg)
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return "", nil, err
		}

		// Handle special cases for registration acknowledgments.
		if isRegistrationAck(ack) {
			span.SetAttributes(attribute.String("event_type", string(EventTypeScannerRegistrationAck)))
			return EventTypeScannerRegistrationAck, ack, nil
		}

		span.SetAttributes(attribute.String("event_type", string(EventTypeMessageAck)))
		return EventTypeMessageAck, ack, nil
	}

	// Convert proto message to domain event.
	domainEvent, err := serialization.ProtoToDomainEvent(eventType, protoMsg)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return "", nil, fmt.Errorf("failed to convert proto message to domain event: %w", err)
	}

	return eventType, domainEvent, nil
}

// mapMessageTypeToEventType maps a message type string to a domain event type.
func mapMessageTypeToEventType(messageType MessageType) events.EventType {
	switch messageType {
	// Scanner events.
	case MessageTypeScannerHeartbeat:
		return scanning.EventTypeScannerHeartbeat
	case MessageTypeScannerRegistered:
		return scanning.EventTypeScannerRegistered
	case MessageTypeScannerStatusChanged:
		return scanning.EventTypeScannerStatusChanged
	case MessageTypeScannerDeregistered:
		return scanning.EventTypeScannerDeregistered

	// Task events.
	case MessageTypeScanTaskStarted:
		return scanning.EventTypeTaskStarted
	case MessageTypeScanTaskProgressed:
		return scanning.EventTypeTaskProgressed
	case MessageTypeScanTaskCompleted:
		return scanning.EventTypeTaskCompleted
	case MessageTypeScanTaskFailed:
		return scanning.EventTypeTaskFailed
	case MessageTypeScanTaskPaused:
		return scanning.EventTypeTaskPaused
	case MessageTypeScanTaskCancelled:
		return scanning.EventTypeTaskCancelled
	case MessageTypeScanTaskResume:
		return scanning.EventTypeTaskResume
	case MessageTypeScanTaskHeartbeat:
		return scanning.EventTypeTaskHeartbeat
	case MessageTypeScanTaskJobMetric:
		return scanning.EventTypeTaskJobMetric

	// Job events.
	case MessageTypeScanJobPaused:
		return scanning.EventTypeJobPaused
	case MessageTypeScanJobCancelled:
		return scanning.EventTypeJobCancelled

	// Rule events.
	case MessageTypeRulesRequested:
		return rules.EventTypeRulesRequested
	case MessageTypeRulesResponse:
		return rules.EventTypeRulesUpdated

	// System events.
	case MessageTypeSystemNotification:
		return EventTypeSystemNotification
	case MessageTypeAck:
		return EventTypeMessageAck
	case MessageTypeRegistrationResponse:
		return EventTypeScannerRegistrationAck

	default:
		return events.EventType("")
	}
}

// extractGatewayMessageInfo extracts the event type and payload from a GatewayToScannerMessage.
// This is a helper function that identifies the message type and returns the corresponding
// domain event type and message payload without further processing.
func extractGatewayMessageInfo(
	ctx context.Context,
	msg *pb.GatewayToScannerMessage,
) (events.EventType, any, error) {
	span := trace.SpanFromContext(ctx)
	defer span.End()

	// Determine the message type and payload based on the message content.
	var eventType events.EventType
	var payload any

	// Extract the message type and payload.
	switch {
	// Registration acknowledgment (using MessageAcknowledgment)
	case msg.GetAck() != nil && isRegistrationAck(msg.GetAck()):
		span.SetAttributes(attribute.String("message_type", "registration_ack"))
		eventType = EventTypeScannerRegistrationAck
		payload = msg.GetAck()

	// Regular message acknowledgment
	case msg.GetAck() != nil:
		span.SetAttributes(attribute.String("message_type", "ack"))
		eventType = EventTypeMessageAck
		payload = msg.GetAck()

	// Task events.
	case msg.GetTaskCreated() != nil:
		taskCreated := msg.GetTaskCreated()
		eventType = scanning.EventTypeTaskCreated
		payload = taskCreated
		span.SetAttributes(attribute.String("task_id", taskCreated.TaskId))

	case msg.GetTaskResume() != nil:
		taskResume := msg.GetTaskResume()
		eventType = scanning.EventTypeTaskResume
		payload = taskResume
		span.SetAttributes(attribute.String("task_id", taskResume.TaskId))

	case msg.GetTaskPaused() != nil:
		taskPaused := msg.GetTaskPaused()
		eventType = scanning.EventTypeTaskPaused
		payload = taskPaused
		span.SetAttributes(attribute.String("task_id", taskPaused.TaskId))

	// Job control events.
	case msg.GetJobPaused() != nil:
		jobPaused := msg.GetJobPaused()
		eventType = scanning.EventTypeJobPaused
		payload = jobPaused
		span.SetAttributes(attribute.String("job_id", jobPaused.JobId))

	case msg.GetJobCancelled() != nil:
		jobCancelled := msg.GetJobCancelled()
		eventType = scanning.EventTypeJobCancelled
		payload = jobCancelled
		span.SetAttributes(attribute.String("job_id", jobCancelled.JobId))

	// Rules events.
	case msg.GetRuleRequested() != nil:
		ruleRequested := msg.GetRuleRequested()
		eventType = rules.EventTypeRulesRequested
		payload = ruleRequested

	// System messages.
	case msg.GetNotification() != nil:
		notification := msg.GetNotification()
		eventType = events.EventType("system_notification")
		payload = notification

	default:
		err := fmt.Errorf("unknown message type in GatewayToScannerMessage")
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return "", nil, err
	}

	// Call the callback with the event type and payload.
	span.SetAttributes(attribute.String("event_type", string(eventType)))
	span.AddEvent("gateway_message_processed")
	return eventType, payload, nil
}

// isRegistrationAck determines if an acknowledgment is for a registration message
// This is a helper function to differentiate between registration acks and regular acks
func isRegistrationAck(ack *pb.MessageAcknowledgment) bool {
	// Check if the original message ID starts with "register" or contains "registration"
	// or if there's metadata indicating this is a registration ack
	return strings.Contains(ack.OriginalMessageId, "register") ||
		strings.Contains(ack.OriginalMessageId, "registration")
}
