package tracing

import (
	"context"

	"github.com/IBM/sarama"
	"go.opentelemetry.io/otel"
)

// InjectTraceContext propagates the current trace context into Kafka message headers.
// This enables distributed tracing across producer-consumer boundaries by ensuring
// trace context flows with the message through the Kafka broker.
func InjectTraceContext(ctx context.Context, msg *sarama.ProducerMessage) {
	carrier := &MessageCarrier{Headers: msg.Headers}
	otel.GetTextMapPropagator().Inject(ctx, carrier)

	// Type assert back to []sarama.RecordHeader for producer message.
	// This is necessary because the Headers field in sarama.ProducerMessage
	// is of type interface{}, which can be either []sarama.RecordHeader or []*sarama.RecordHeader.
	if headers, ok := carrier.Headers.([]sarama.RecordHeader); ok {
		msg.Headers = headers
	}
}

// ExtractTraceContext retrieves trace context from Kafka message headers and returns
// a new context containing the extracted trace information. This allows consumers
// to continue the distributed trace that was started by the producer.
func ExtractTraceContext(ctx context.Context, msg *sarama.ConsumerMessage) context.Context {
	carrier := &MessageCarrier{Headers: msg.Headers}
	return otel.GetTextMapPropagator().Extract(ctx, carrier)
}
