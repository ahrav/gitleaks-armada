package tracing

import (
	"context"

	"github.com/IBM/sarama"
	"go.opentelemetry.io/otel"
)

// InjectTraceContext adds the current trace context to Kafka message headers
func InjectTraceContext(ctx context.Context, msg *sarama.ProducerMessage) {
	carrier := &MessageCarrier{Headers: msg.Headers}
	otel.GetTextMapPropagator().Inject(ctx, carrier)
	msg.Headers = carrier.Headers
}

// ExtractTraceContext retrieves trace context from Kafka message headers
func ExtractTraceContext(ctx context.Context, msg *sarama.ConsumerMessage) context.Context {
	var headers []sarama.RecordHeader
	if msg.Headers != nil {
		for _, h := range msg.Headers {
			headers = append(headers, *h)
		}
	}
	carrier := &MessageCarrier{Headers: headers}
	return otel.GetTextMapPropagator().Extract(ctx, carrier)
}
