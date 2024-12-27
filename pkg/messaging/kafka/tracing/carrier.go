// Package tracing provides functionality for propagating distributed tracing context
// through Kafka message headers, enabling end-to-end tracing across message boundaries.
package tracing

import (
	"github.com/IBM/sarama"
)

// MessageCarrier implements propagation.TextMapCarrier to enable distributed tracing
// context propagation through Kafka message headers. It handles both pointer and
// non-pointer header types to support both producer and consumer message formats.
type MessageCarrier struct {
	// Headers stores Kafka record headers in either []sarama.RecordHeader or
	// []*sarama.RecordHeader format, depending on whether the carrier is used
	// for producing or consuming messages.
	Headers any
}

// Get retrieves a header value by key from the Kafka message headers. It returns
// an empty string if the key is not found. This method is required to implement
// the TextMapCarrier interface for OpenTelemetry context propagation.
func (mc *MessageCarrier) Get(key string) string {
	switch h := mc.Headers.(type) {
	case []sarama.RecordHeader:
		for _, header := range h {
			if string(header.Key) == key {
				return string(header.Value)
			}
		}
	case []*sarama.RecordHeader:
		for _, header := range h {
			if string(header.Key) == key {
				return string(header.Value)
			}
		}
	}
	return ""
}

// Set adds or updates a header key-value pair in the Kafka message headers. This
// method is required to implement the TextMapCarrier interface for OpenTelemetry
// context propagation. It handles initialization of headers for new messages.
func (mc *MessageCarrier) Set(key, value string) {
	header := sarama.RecordHeader{
		Key:   []byte(key),
		Value: []byte(value),
	}

	switch h := mc.Headers.(type) {
	case []sarama.RecordHeader:
		mc.Headers = append(h, header)
	case []*sarama.RecordHeader:
		mc.Headers = append(h, &header)
	case nil:
		// Initialize as non-pointer slice since this is a new producer message
		mc.Headers = []sarama.RecordHeader{header}
	}
}

// Keys returns all header keys present in the message. This method is required to
// implement the TextMapCarrier interface for OpenTelemetry context propagation.
// It returns nil if no headers are present.
func (mc *MessageCarrier) Keys() []string {
	switch h := mc.Headers.(type) {
	case []sarama.RecordHeader:
		out := make([]string, len(h))
		for i, header := range h {
			out[i] = string(header.Key)
		}
		return out
	case []*sarama.RecordHeader:
		out := make([]string, len(h))
		for i, header := range h {
			out[i] = string(header.Key)
		}
		return out
	}
	return nil
}
