package protocol

import (
	pb "github.com/ahrav/gitleaks-armada/proto"
)

// This file contains type definitions that create an abstraction layer between
// the application code and the protobuf-generated types. These wrappers serve
// several purposes:
//
// 1. Abstraction and Decoupling: By using type aliases and interfaces, the rest of
//    the codebase can interact with message types without directly importing protobuf
//    packages, creating a clean separation of concerns.
//
// 2. Testability: The interfaces make it possible to mock the communication layer
//    in tests without needing actual gRPC connections.
//
// 3. Transport Flexibility: While currently using gRPC, the system could be extended
//    to use other communication methods without changing core business logic.
//
// 4. Version Control: When protobuf definitions change, this layer allows for handling
//    those changes with minimal impact on application code.
//
// Together, these abstractions create a boundary between transport mechanisms and
// domain logic, making the codebase more maintainable and adaptable to change.

// GatewayToScannerMessage is a wrapper for the protobuf message type.
// This is the message that goes from the gateway to the scanner.
type GatewayToScannerMessage = pb.GatewayToScannerMessage

// ScannerToGatewayMessage is a wrapper for the protobuf message type.
// This is the message that goes from the scanner to the gateway.
type ScannerToGatewayMessage = pb.ScannerToGatewayMessage

// MessageAck is a wrapper for the protobuf message type.
// This is the message that goes from the gateway to the scanner to acknowledge a message.
type MessageAck = pb.MessageAcknowledgment

// ScannerGatewayStream represents the bidirectional stream between scanner and gateway.
// From the scanner's perspective, this interface provides the correct message direction:
// - Scanner sends ScannerToGatewayMessage TO the gateway (scanner → gateway)
// - Scanner receives GatewayToScannerMessage FROM the gateway (gateway → scanner)
//
// This interface is implemented by the gRPC bidirectional stream clients:
// - pb.ScannerGatewayService_ConnectScannerClient
// - pb.ScannerGatewayService_SubscribeToBroadcastsClient
type ScannerGatewayStream interface {
	// Send sends a ScannerToGatewayMessage from the scanner to the gateway
	Send(message *ScannerToGatewayMessage) error

	// Recv receives a GatewayToScannerMessage from the gateway to the scanner
	Recv() (*GatewayToScannerMessage, error)

	// CloseSend closes the sending direction of the stream
	CloseSend() error
}

// MessageType represents a gRPC message type used in the communication
// between gateway and scanners. It defines the specific category of message
// being transmitted over the gRPC stream.
type MessageType string

// String returns the string representation of the message type.
func (m MessageType) String() string { return string(m) }

const (
	// --------------------------------------------------------------------------
	// Scanner lifecycle message types.
	// --------------------------------------------------------------------------

	// MessageTypeScannerRegistration represents a scanner registration message.
	MessageTypeScannerRegistration MessageType = "scanner_registration"
	// MessageTypeScannerRegistered represents a scanner registered message.
	MessageTypeScannerRegistered MessageType = "scanner_registered"
	// MessageTypeScannerHeartbeat represents a scanner heartbeat message.
	MessageTypeScannerHeartbeat MessageType = "scanner_heartbeat"
	// MessageTypeScannerStatusChanged represents a scanner status change message.
	MessageTypeScannerStatusChanged MessageType = "scanner_status_changed"
	// MessageTypeScannerDeregistered represents a scanner deregistration message.
	MessageTypeScannerDeregistered MessageType = "scanner_deregistered"

	// --------------------------------------------------------------------------
	// Task processing message types.
	// --------------------------------------------------------------------------

	// MessageTypeScanTask represents a task creation message.
	MessageTypeScanTask MessageType = "scan_task"
	// MessageTypeScanTaskStarted represents a task started message.
	MessageTypeScanTaskStarted MessageType = "scan_task_started"
	// MessageTypeScanTaskProgressed represents a task progress update message.
	MessageTypeScanTaskProgressed MessageType = "scan_task_progressed"
	// MessageTypeScanTaskCompleted represents a task completion message.
	MessageTypeScanTaskCompleted MessageType = "scan_task_completed"
	// MessageTypeScanTaskFailed represents a task failure message.
	MessageTypeScanTaskFailed MessageType = "scan_task_failed"
	// MessageTypeScanTaskPaused represents a task paused message.
	MessageTypeScanTaskPaused MessageType = "scan_task_paused"
	// MessageTypeScanTaskCancelled represents a task cancelled message.
	MessageTypeScanTaskCancelled MessageType = "scan_task_cancelled"
	// MessageTypeScanTaskResume represents a task resume message.
	MessageTypeScanTaskResume MessageType = "scan_task_resume"
	// MessageTypeScanTaskHeartbeat represents a task heartbeat message.
	MessageTypeScanTaskHeartbeat MessageType = "scan_task_heartbeat"
	// MessageTypeScanTaskJobMetric represents a task job metric message.
	MessageTypeScanTaskJobMetric MessageType = "scan_task_job_metric"

	// --------------------------------------------------------------------------
	// Rules message types.
	// --------------------------------------------------------------------------

	// MessageTypeRulesRequested represents a rules distribution request message.
	MessageTypeRulesRequested MessageType = "controller_initiated_rule_distribution"
	// MessageTypeRulesResponse represents a rules distribution response message.
	MessageTypeRulesResponse MessageType = "scan_rule"

	// --------------------------------------------------------------------------
	// Job control message types (broadcast)
	// --------------------------------------------------------------------------

	// MessageTypeScanJobPaused represents a job paused broadcast message.
	MessageTypeScanJobPaused MessageType = "scan_job_paused"
	// MessageTypeScanJobCancelled represents a job cancelled broadcast message.
	MessageTypeScanJobCancelled MessageType = "scan_job_cancelled"
	// MessageTypeScanJobPausing represents a job pausing broadcast message.
	MessageTypeScanJobPausing MessageType = "scan_job_pausing"
	// MessageTypeScanJobResuming represents a job resuming broadcast message.
	MessageTypeScanJobResuming MessageType = "scan_job_resuming"
	// MessageTypeScanJobCancelling represents a job cancelling broadcast message.
	MessageTypeScanJobCancelling MessageType = "scan_job_cancelling"

	// --------------------------------------------------------------------------
	// System message types.
	// --------------------------------------------------------------------------

	// MessageTypeAck represents an acknowledgment message.
	MessageTypeAck MessageType = "ack"
	// MessageTypeSystemNotification represents a system notification message.
	MessageTypeSystemNotification MessageType = "system_notification"
	// MessageTypeRegistrationResponse represents a registration response message.
	MessageTypeRegistrationResponse MessageType = "registration_response"
	// MessageTypeUnknown represents an unknown message type.
	MessageTypeUnknown MessageType = "unknown"
)
