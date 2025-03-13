// Package gateway implements the scanner gateway service.
package gateway

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	grpcbus "github.com/ahrav/gitleaks-armada/internal/infra/eventbus/grpc"
	"github.com/ahrav/gitleaks-armada/internal/infra/eventbus/serialization"
	"github.com/ahrav/gitleaks-armada/pkg/common/uuid"
	pb "github.com/ahrav/gitleaks-armada/proto"
)

// convertToScannerMessage converts a domain event to a scanner message.
//
// This method is a key part of the gateway→scanner reliability model:
//   - It generates a unique message ID for each outgoing message
//   - This ID allows scanners to acknowledge receipt and processing
//   - All messages sent via this method are considered critical commands
//     that require acknowledgment from scanners
//
// The message ID tracking is critical for the acknowledgment system,
// as it creates a correlation between outgoing commands and their acknowledgments,
// similar to how Kafka maintains message offsets but implemented at the application level.
func (s *Service) convertToScannerMessage(
	ctx context.Context,
	evt events.EventEnvelope,
) (*pb.GatewayToScannerMessage, error) {
	span := trace.SpanFromContext(ctx)
	defer span.End()

	// Create the base message.
	msg := &pb.GatewayToScannerMessage{
		MessageId: uuid.New().String(),
		Timestamp: s.timeProvider.Now().UnixNano(),
	}

	protoPayload, err := serialization.DomainEventToProto(evt.Type, evt.Payload)
	if err != nil {
		span.RecordError(err)
		s.metrics.IncTranslationErrors(ctx, "outgoing")
		return nil, fmt.Errorf("failed to convert domain event to proto: %w", err)
	}

	if err := grpcbus.SetGatewayToScannerPayload(msg, evt.Type, protoPayload); err != nil {
		span.RecordError(err)
		s.metrics.IncTranslationErrors(ctx, "outgoing")
		return nil, fmt.Errorf("failed to set gateway message payload: %w", err)
	}
	span.AddEvent("conversion_complete")

	return msg, nil
}
