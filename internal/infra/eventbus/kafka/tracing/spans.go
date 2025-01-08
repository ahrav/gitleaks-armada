package tracing

import (
	"context"

	"github.com/IBM/sarama"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"go.opentelemetry.io/otel/trace"
)

// StartProducerSpan creates a new span for producing messages
func StartProducerSpan(ctx context.Context, topic string, tracer trace.Tracer) (context.Context, trace.Span) {
	return tracer.Start(ctx, "kafka.produce",
		trace.WithAttributes(
			semconv.MessagingSystemKafka,
			semconv.MessagingDestinationName(topic),
			semconv.MessagingOperationPublish,
		),
	)
}

// StartConsumerSpan creates a new span for consuming messages
func StartConsumerSpan(ctx context.Context, msg *sarama.ConsumerMessage, tracer trace.Tracer) (context.Context, trace.Span) {
	return tracer.Start(ctx, "kafka.consume",
		trace.WithAttributes(
			semconv.MessagingSystemKafka,
			semconv.MessagingDestinationName(msg.Topic),
			semconv.MessagingOperationReceive,
			semconv.MessagingKafkaDestinationPartition(int(msg.Partition)),
			semconv.MessagingKafkaMessageOffset(int(msg.Offset)),
		),
	)
}
