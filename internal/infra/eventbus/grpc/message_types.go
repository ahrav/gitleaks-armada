package grpc

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

// ScannerGatewayStream represents the bidirectional stream between scanner and gateway.
// It abstracts the underlying stream implementation to support both direct gRPC usage
// and potential future transport mechanisms.
type ScannerGatewayStream interface {
	// Send sends a message to the remote endpoint
	Send(message *ScannerToGatewayMessage) error
	// Recv receives a message from the remote endpoint
	Recv() (*GatewayToScannerMessage, error)
	// CloseSend closes the sending direction of the stream
	CloseSend() error
}

// ClientStreamInterface is used by the EventBus to communicate with the stream.
// For scanner-side implementation, this will be an adapter over the gRPC stream.
type ClientStreamInterface interface {
	// Send sends a message to the gateway
	Send(message *GatewayToScannerMessage) error
	// Recv receives a message from the gateway
	Recv() (*ScannerToGatewayMessage, error)
	// CloseSend closes the sending direction of the stream
	CloseSend() error
}
