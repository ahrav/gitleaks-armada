// Package grpc provides gRPC-based implementations of event bus components.
package grpc

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/domain/rules"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/internal/infra/eventbus/serialization"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
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
		msg.Payload = &pb.GatewayToScannerMessage_TaskCreated{
			TaskCreated: taskCreated,
		}

	case scanning.EventTypeTaskResume:
		taskResume, ok := payload.(*pb.TaskResumeEvent)
		if !ok {
			return fmt.Errorf("payload is not a TaskResumeEvent: %T", payload)
		}
		msg.Payload = &pb.GatewayToScannerMessage_TaskResume{
			TaskResume: taskResume,
		}

	// Job related events.
	case scanning.EventTypeJobPausing:
		jobPausing, ok := payload.(*pb.JobPausingEvent)
		if !ok {
			return fmt.Errorf("payload is not a JobPausingEvent: %T", payload)
		}
		msg.Payload = &pb.GatewayToScannerMessage_JobPausing{
			JobPausing: jobPausing,
		}

	case scanning.EventTypeJobPaused:
		jobPaused, ok := payload.(*pb.JobPausedEvent)
		if !ok {
			return fmt.Errorf("payload is not a JobPausedEvent: %T", payload)
		}
		msg.Payload = &pb.GatewayToScannerMessage_JobPaused{
			JobPaused: jobPaused,
		}

	case scanning.EventTypeJobResuming:
		jobResuming, ok := payload.(*pb.JobResumingEvent)
		if !ok {
			return fmt.Errorf("payload is not a JobResumingEvent: %T", payload)
		}
		msg.Payload = &pb.GatewayToScannerMessage_JobResuming{
			JobResuming: jobResuming,
		}

	case scanning.EventTypeJobCancelling:
		jobCancelling, ok := payload.(*pb.JobCancellingEvent)
		if !ok {
			return fmt.Errorf("payload is not a JobCancellingEvent: %T", payload)
		}
		msg.Payload = &pb.GatewayToScannerMessage_JobCancelling{
			JobCancelling: jobCancelling,
		}

	case scanning.EventTypeJobCancelled:
		jobCancelled, ok := payload.(*pb.JobCancelledEvent)
		if !ok {
			return fmt.Errorf("payload is not a JobCancelledEvent: %T", payload)
		}
		msg.Payload = &pb.GatewayToScannerMessage_JobCancelled{
			JobCancelled: jobCancelled,
		}

	// Rules and system events.
	case rules.EventTypeRulesUpdated:
		// When controller sends rule updates to scanners
		// This is a push from the controller, not a response to a scanner request
		_, ok := payload.(*pb.RuleMessage)
		if !ok {
			return fmt.Errorf("payload is not a RuleMessage: %T", payload)
		}

		// TODO: In a future revision, we should add a dedicated field in GatewayToScannerMessage
		// for rule updates. Currently using System Notification as a workaround.
		// Create a system notification to deliver the rules update
		msg.Payload = &pb.GatewayToScannerMessage_Notification{
			Notification: &pb.SystemNotification{
				Title:   "Rules Updated",
				Message: "Rule update received",
				Type:    pb.SystemNotification_NOTIFICATION_TYPE_INFO,
			},
		}

	case events.EventType("SystemNotification"):
		notification, ok := payload.(*pb.SystemNotification)
		if !ok {
			return fmt.Errorf("payload is not a SystemNotification: %T", payload)
		}
		msg.Payload = &pb.GatewayToScannerMessage_Notification{
			Notification: notification,
		}

	default:
		return fmt.Errorf("unhandled event type: %s", eventType)
	}

	return nil
}

// GetScannerToGatewayMessageType determines the type of message contained in a ScannerToGatewayMessage.
// Returns the message type string, the message payload, and any error.
func GetScannerToGatewayMessageType(msg *pb.ScannerToGatewayMessage) (string, any, error) {
	switch {
	// Scanner events.
	case msg.GetHeartbeat() != nil:
		return "heartbeat", msg.GetHeartbeat(), nil

	case msg.GetRegistration() != nil:
		return "scanner_registered", msg.GetRegistration(), nil

	case msg.GetStatusChanged() != nil:
		return "status_changed", msg.GetStatusChanged(), nil

	case msg.GetDeregistered() != nil:
		return "deregistered", msg.GetDeregistered(), nil

	// Task events.
	case msg.GetTaskStarted() != nil:
		return "task_started", msg.GetTaskStarted(), nil

	case msg.GetTaskProgressed() != nil:
		return "task_progressed", msg.GetTaskProgressed(), nil

	case msg.GetTaskCompleted() != nil:
		return "task_completed", msg.GetTaskCompleted(), nil

	case msg.GetTaskFailed() != nil:
		return "task_failed", msg.GetTaskFailed(), nil

	case msg.GetTaskPaused() != nil:
		return "task_paused", msg.GetTaskPaused(), nil

	case msg.GetTaskCancelled() != nil:
		return "task_cancelled", msg.GetTaskCancelled(), nil

	// Acknowledgment.
	case msg.GetAck() != nil:
		return "ack", msg.GetAck(), nil

	default:
		return "", nil, fmt.Errorf("unknown message type in ScannerToGatewayMessage")
	}
}

// ProcessIncomingMessage processes an incoming ScannerToGatewayMessage by determining its message type,
// converting it to a domain event, and invoking the provided callback with the event.
func ProcessIncomingMessage(
	ctx context.Context,
	msg *pb.ScannerToGatewayMessage,
	logger *logger.Logger,
	tracer trace.Tracer,
	callback func(ctx context.Context, eventType events.EventType, domainEvent any) error,
) error {
	ctx, span := tracer.Start(ctx, "ProcessIncomingMessage",
		trace.WithAttributes(
			attribute.String("message_id", msg.MessageId),
			attribute.String("scanner_id", msg.ScannerId),
		))
	defer span.End()

	// Determine message type and get the payload.
	messageType, protoMsg, err := GetScannerToGatewayMessageType(msg)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	span.SetAttributes(attribute.String("message_type", messageType))

	eventType := mapMessageTypeToEventType(messageType)
	if eventType == "" {
		span.SetStatus(codes.Error, "unknown message type")
		return fmt.Errorf("unknown message type for event mapping: %s", messageType)
	}

	// Convert proto message to domain event.
	domainEvent, err := serialization.ProtoToDomainEvent(eventType, protoMsg)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("failed to convert proto message to domain event: %w", err)
	}

	// Invoke callback with the domain event.
	if err := callback(ctx, eventType, domainEvent); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("callback error processing domain event: %w", err)
	}

	return nil
}

// mapMessageTypeToEventType maps a message type string to a domain event type.
func mapMessageTypeToEventType(messageType string) events.EventType {
	switch messageType {
	// Scanner events.
	case "heartbeat":
		return scanning.EventTypeScannerHeartbeat
	case "scanner_registered":
		return scanning.EventTypeScannerRegistered
	case "status_changed":
		return scanning.EventTypeScannerStatusChanged
	case "deregistered":
		return scanning.EventTypeScannerDeregistered

	// Task events.
	case "task_started":
		return scanning.EventTypeTaskStarted
	case "task_progressed":
		return scanning.EventTypeTaskProgressed
	case "task_completed":
		return scanning.EventTypeTaskCompleted
	case "task_failed":
		return scanning.EventTypeTaskFailed
	case "task_paused":
		return scanning.EventTypeTaskPaused
	case "task_cancelled":
		return scanning.EventTypeTaskCancelled
	case "task_resume":
		return scanning.EventTypeTaskResume
	case "task_heartbeat":
		return scanning.EventTypeTaskHeartbeat
	case "task_job_metric":
		return scanning.EventTypeTaskJobMetric

	// Job events.
	case "job_requested":
		return scanning.EventTypeJobRequested
	case "job_scheduled":
		return scanning.EventTypeJobScheduled
	case "job_enumeration_completed":
		return scanning.EventTypeJobEnumerationCompleted
	case "job_pausing":
		return scanning.EventTypeJobPausing
	case "job_paused":
		return scanning.EventTypeJobPaused
	case "job_resuming":
		return scanning.EventTypeJobResuming
	case "job_cancelling":
		return scanning.EventTypeJobCancelling
	case "job_cancelled":
		return scanning.EventTypeJobCancelled

	// Rule events.
	case "rules_requested":
		return rules.EventTypeRulesRequested
	case "rules_updated":
		return rules.EventTypeRulesUpdated

	// System events.
	case "system_notification":
		return events.EventType("SystemNotification")

	default:
		return events.EventType("")
	}
}

// MessageTypeFromEventType maps domain event types to proto message types.
// This function is used to determine which field to populate in the protobuf message.
func MessageTypeFromEventType(eventType events.EventType) string {
	switch eventType {
	// Task events
	case scanning.EventTypeTaskCreated:
		return "task_created_event"
	case scanning.EventTypeTaskStarted:
		return "task_started_event"
	case scanning.EventTypeTaskProgressed:
		return "task_progressed_event"
	case scanning.EventTypeTaskCompleted:
		return "task_completed_event"
	case scanning.EventTypeTaskFailed:
		return "task_failed_event"
	case scanning.EventTypeTaskPaused:
		return "task_paused_event"
	case scanning.EventTypeTaskCancelled:
		return "task_cancelled_event"
	case scanning.EventTypeTaskResume:
		return "task_resume_event"
	case scanning.EventTypeTaskHeartbeat:
		return "task_heartbeat_event"
	case scanning.EventTypeTaskJobMetric:
		return "task_job_metric_event"

	// Job events
	case scanning.EventTypeJobRequested:
		return "job_requested_event"
	case scanning.EventTypeJobScheduled:
		return "job_created_event"
	case scanning.EventTypeJobEnumerationCompleted:
		return "job_enumeration_completed_event"
	case scanning.EventTypeJobPausing:
		return "job_pausing_event"
	case scanning.EventTypeJobPaused:
		return "job_paused_event"
	case scanning.EventTypeJobResuming:
		return "job_resuming_event"
	case scanning.EventTypeJobCancelling:
		return "job_cancelling_event"
	case scanning.EventTypeJobCancelled:
		return "job_cancelled_event"

	// Scanner events
	case scanning.EventTypeScannerRegistered:
		return "scanner_registered_event"
	case scanning.EventTypeScannerHeartbeat:
		return "scanner_heartbeat_event"
	case scanning.EventTypeScannerStatusChanged:
		return "scanner_status_changed_event"
	case scanning.EventTypeScannerDeregistered:
		return "scanner_deregistered_event"

	// Rule events
	case rules.EventTypeRulesRequested:
		// Controller initiates rule distribution to all scanners
		return "controller_requests_rules_distribution"
	case rules.EventTypeRulesUpdated:
		// Controller pushes updated rules to all scanners
		return "controller_updates_rules"

	// System events
	case events.EventType("SystemNotification"):
		return "system_notification"

	default:
		return fmt.Sprintf("unknown_event_type_%s", eventType)
	}
}
