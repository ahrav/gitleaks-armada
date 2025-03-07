package grpc

import (
	"fmt"

	pb "github.com/ahrav/gitleaks-armada/proto"
)

// ScannerStreamAdapter adapts a scanner's gRPC stream to the ClientStreamInterface
// expected by the EventBus. This handles the type conversion between the stream
// used by the scanner and the interface expected by our event bus.
//
// The adapter solves a critical message direction mismatch problem:
//
// 1. Message Direction Problem:
//   - In gRPC:
//   - Gateway sends GatewayToScannerMessage TO scanners
//   - Scanners send ScannerToGatewayMessage TO gateway
//   - But ClientStreamInterface expects:
//   - Send(*GatewayToScannerMessage) - Sends TO the gateway (opposite direction)
//   - Recv() (*ScannerToGatewayMessage, error) - Receives FROM the gateway (opposite direction)
//
// 2. The Solution:
//   - This adapter flips message directions for scanner-side use by:
//   - Send(): Converting GatewayToScannerMessage → ScannerToGatewayMessage
//   - Recv(): Converting GatewayToScannerMessage → ScannerToGatewayMessage
//   - Each conversion includes:
//   - Copying basic fields (MessageId, Timestamp, RoutingKey, Headers)
//   - Converting payload types based on message content
//   - Usually converting to acknowledgment messages
//
// 3. Integration:
//   - Used by NewScannerEventBus() to create an EventBus for scanners
//   - Works with payload_helper.go for payload mapping
//   - Works with proto_registry.go for serialization/deserialization
//
// Without this adapter, scanners would need custom code to handle
// the bidirectional gRPC stream directly, rather than using the common
// EventBus interface that's shared with Kafka-based communication.
type ScannerStreamAdapter struct {
	// The underlying gRPC stream.
	Stream pb.ScannerGatewayService_ConnectScannerClient
}

// Send implements ClientStreamInterface.Send by converting from
// GatewayToScannerMessage to ScannerToGatewayMessage.
func (a *ScannerStreamAdapter) Send(message *GatewayToScannerMessage) error {
	// For scanners, we need to reverse the message direction.
	// Convert from Gateway→Scanner to Scanner→Gateway message.

	// Create a new ScannerToGatewayMessage with basic fields.
	outMsg := &ScannerToGatewayMessage{
		MessageId:  message.MessageId,
		Timestamp:  message.Timestamp,
		RoutingKey: message.RoutingKey, // Preserve routing key
	}

	// Copy headers if present
	if len(message.Headers) > 0 {
		outMsg.Headers = make(map[string]string, len(message.Headers))
		for k, v := range message.Headers {
			outMsg.Headers[k] = v
		}
	}

	// Convert the payload based on its type
	// This is the complex part - we need to handle each possible payload type
	// and map it to the appropriate field in the ScannerToGatewayMessage
	switch payload := message.Payload.(type) {
	// Handle registration response - convert to acknowledgment
	case *pb.GatewayToScannerMessage_RegistrationResponse:
		regResp := payload.RegistrationResponse
		outMsg.Payload = &pb.ScannerToGatewayMessage_Ack{
			Ack: &pb.MessageAcknowledgment{
				OriginalMessageId: regResp.ScannerId, // Use scanner ID as the original message ID
				Success:           regResp.Success,
				ErrorMessage:      regResp.Message,
			},
		}

	// Handle task created event - convert to acknowledgment
	case *pb.GatewayToScannerMessage_TaskCreated:
		// Task created needs special handling - scanners typically respond with
		// a task started event once they begin processing
		// The taskCreated variable could be used for additional processing if needed
		outMsg.Payload = &pb.ScannerToGatewayMessage_Ack{
			Ack: &pb.MessageAcknowledgment{
				OriginalMessageId: message.MessageId,
				Success:           true,
			},
		}

	// Handle task resume event - convert to acknowledgment
	case *pb.GatewayToScannerMessage_TaskResume:
		// Similar to task created
		outMsg.Payload = &pb.ScannerToGatewayMessage_Ack{
			Ack: &pb.MessageAcknowledgment{
				OriginalMessageId: message.MessageId,
				Success:           true,
			},
		}

	// Handle job control events - convert to acknowledgments
	case *pb.GatewayToScannerMessage_JobPausing:
		outMsg.Payload = &pb.ScannerToGatewayMessage_Ack{
			Ack: &pb.MessageAcknowledgment{
				OriginalMessageId: message.MessageId,
				Success:           true,
			},
		}

	case *pb.GatewayToScannerMessage_JobPaused:
		outMsg.Payload = &pb.ScannerToGatewayMessage_Ack{
			Ack: &pb.MessageAcknowledgment{
				OriginalMessageId: message.MessageId,
				Success:           true,
			},
		}

	case *pb.GatewayToScannerMessage_JobResuming:
		outMsg.Payload = &pb.ScannerToGatewayMessage_Ack{
			Ack: &pb.MessageAcknowledgment{
				OriginalMessageId: message.MessageId,
				Success:           true,
			},
		}

	case *pb.GatewayToScannerMessage_JobCancelling:
		outMsg.Payload = &pb.ScannerToGatewayMessage_Ack{
			Ack: &pb.MessageAcknowledgment{
				OriginalMessageId: message.MessageId,
				Success:           true,
			},
		}

	case *pb.GatewayToScannerMessage_JobCancelled:
		outMsg.Payload = &pb.ScannerToGatewayMessage_Ack{
			Ack: &pb.MessageAcknowledgment{
				OriginalMessageId: message.MessageId,
				Success:           true,
			},
		}

	// Handle system notification - convert to acknowledgment
	case *pb.GatewayToScannerMessage_Notification:
		outMsg.Payload = &pb.ScannerToGatewayMessage_Ack{
			Ack: &pb.MessageAcknowledgment{
				OriginalMessageId: message.MessageId,
				Success:           true,
			},
		}

	default:
		// For any other message type we don't recognize, create a generic acknowledgment
		return fmt.Errorf("unsupported payload type: %T", message.Payload)
	}

	// Send the converted message through the actual gRPC stream
	return a.Stream.Send(outMsg)
}

// Recv implements ClientStreamInterface.Recv by converting from
// ScannerToGatewayMessage to GatewayToScannerMessage.
func (a *ScannerStreamAdapter) Recv() (*ScannerToGatewayMessage, error) {
	// Receive a message from the gateway (GatewayToScannerMessage)
	inMsg, err := a.Stream.Recv()
	if err != nil {
		return nil, err
	}

	// For scanner side, we need to return the ScannerToGatewayMessage type
	// to match what ClientStreamInterface expects to receive
	// However, we actually received a GatewayToScannerMessage from the gateway

	// Convert to a ScannerToGatewayMessage
	outMsg := &ScannerToGatewayMessage{
		MessageId:  inMsg.MessageId,
		Timestamp:  inMsg.Timestamp,
		RoutingKey: inMsg.RoutingKey, // Preserve routing key
	}

	// Copy headers if present
	if len(inMsg.Headers) > 0 {
		outMsg.Headers = make(map[string]string, len(inMsg.Headers))
		for k, v := range inMsg.Headers {
			outMsg.Headers[k] = v
		}
	}

	// Convert payload based on its type
	// Here we need to map from GatewayToScannerMessage payload types
	// to ScannerToGatewayMessage payload types
	switch payload := inMsg.Payload.(type) {
	// Registration response is typically in response to a registration request
	case *pb.GatewayToScannerMessage_RegistrationResponse:
		regResp := payload.RegistrationResponse
		// Keep as an acknowledgment for registration
		outMsg.Payload = &pb.ScannerToGatewayMessage_Ack{
			Ack: &pb.MessageAcknowledgment{
				OriginalMessageId: inMsg.MessageId,
				Success:           regResp.Success,
				ErrorMessage:      regResp.Message,
			},
		}

	// Task created event - this is an instruction for the scanner to start a task
	case *pb.GatewayToScannerMessage_TaskCreated:
		// Map to an acknowledgment - the actual task started event will be sent
		// by the scanner in response to receiving this task
		outMsg.Payload = &pb.ScannerToGatewayMessage_Ack{
			Ack: &pb.MessageAcknowledgment{
				OriginalMessageId: inMsg.MessageId,
				Success:           true,
			},
		}

	// Task resume event - handled similar to task created
	case *pb.GatewayToScannerMessage_TaskResume:
		outMsg.Payload = &pb.ScannerToGatewayMessage_Ack{
			Ack: &pb.MessageAcknowledgment{
				OriginalMessageId: inMsg.MessageId,
				Success:           true,
			},
		}

	// Job control events - map to acknowledgments
	case *pb.GatewayToScannerMessage_JobPausing,
		*pb.GatewayToScannerMessage_JobPaused,
		*pb.GatewayToScannerMessage_JobResuming,
		*pb.GatewayToScannerMessage_JobCancelling,
		*pb.GatewayToScannerMessage_JobCancelled:
		outMsg.Payload = &pb.ScannerToGatewayMessage_Ack{
			Ack: &pb.MessageAcknowledgment{
				OriginalMessageId: inMsg.MessageId,
				Success:           true,
			},
		}

	// System notification - map to acknowledgment
	case *pb.GatewayToScannerMessage_Notification:
		outMsg.Payload = &pb.ScannerToGatewayMessage_Ack{
			Ack: &pb.MessageAcknowledgment{
				OriginalMessageId: inMsg.MessageId,
				Success:           true,
			},
		}

	default:
		// For any other message type we don't recognize
		return nil, fmt.Errorf("unsupported incoming payload type: %T", inMsg.Payload)
	}

	return outMsg, nil
}

// CloseSend implements ClientStreamInterface.CloseSend.
func (a *ScannerStreamAdapter) CloseSend() error {
	return a.Stream.CloseSend()
}
