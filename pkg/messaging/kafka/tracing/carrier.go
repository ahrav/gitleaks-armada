package tracing

import (
	"github.com/IBM/sarama"
)

// MessageCarrier implements propagation.TextMapCarrier for Kafka message headers
type MessageCarrier struct {
	Headers []sarama.RecordHeader
}

func (mc *MessageCarrier) Get(key string) string {
	for _, h := range mc.Headers {
		if string(h.Key) == key {
			return string(h.Value)
		}
	}
	return ""
}

func (mc *MessageCarrier) Set(key, value string) {
	mc.Headers = append(mc.Headers, sarama.RecordHeader{
		Key:   []byte(key),
		Value: []byte(value),
	})
}

func (mc *MessageCarrier) Keys() []string {
	out := make([]string, len(mc.Headers))
	for i, h := range mc.Headers {
		out[i] = string(h.Key)
	}
	return out
}
