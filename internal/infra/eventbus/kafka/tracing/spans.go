package tracing

import (
	"context"

	"github.com/IBM/sarama"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// StartProducerSpan creates a new span for producing messages
func StartProducerSpan(ctx context.Context, topic string, tracer trace.Tracer) (context.Context, trace.Span) {
	return tracer.Start(ctx, "kafka.produce",
		trace.WithAttributes(
			attribute.String("messaging.system", "kafka"),
			attribute.String("messaging.destination", topic),
			attribute.String("messaging.operation", "publish"),
		),
	)
}

// StartConsumerSpan creates a new span for consuming messages
func StartConsumerSpan(ctx context.Context, msg *sarama.ConsumerMessage, tracer trace.Tracer) (context.Context, trace.Span) {
	return tracer.Start(ctx, "kafka.consume",
		trace.WithAttributes(
			attribute.String("messaging.system", "kafka"),
			attribute.String("messaging.destination", msg.Topic),
			attribute.String("messaging.operation", "process"),
			attribute.Int64("messaging.kafka.partition", int64(msg.Partition)),
			attribute.Int64("messaging.kafka.offset", msg.Offset),
		),
	)
}
