package connections

import (
	"google.golang.org/grpc"

	"github.com/ahrav/gitleaks-armada/internal/infra/messaging/protocol"
)

// GatewayScannerStream represents the bidirectional stream between the gateway and a scanner.
// From the gateway's perspective, this interface provides the correct message direction:
// - Gateway sends GatewayToScannerMessage TO the scanner (gateway → scanner)
// - Gateway receives ScannerToGatewayMessage FROM the scanner (scanner → gateway)
//
// This interface is implemented by the gRPC bidirectional stream clients:
// - pb.ScannerGatewayService_ConnectScannerClient
// - pb.ScannerGatewayService_SubscribeToBroadcastsClient
type GatewayScannerStream interface {
	// Send sends a GatewayToScannerMessage from the gateway to the scanner.
	Send(message *protocol.GatewayToScannerMessage) error

	// Recv receives a ScannerToGatewayMessage from the scanner to the gateway.
	Recv() (*protocol.ScannerToGatewayMessage, error)

	// Embed the ServerStream interface to get all other required methods.
	grpc.ServerStream
}
