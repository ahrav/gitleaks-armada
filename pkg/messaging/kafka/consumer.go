package kafka

import (
	"context"

	"github.com/IBM/sarama"
)

// consumeLoop continuously consumes messages from Kafka topics until context cancellation.
// It handles consumer group rebalancing and reconnection automatically.
func consumeLoop(ctx context.Context, cg sarama.ConsumerGroup, topics []string, handler sarama.ConsumerGroupHandler) {
	for {
		if err := cg.Consume(ctx, topics, handler); err != nil {
			// Errors are expected when rebalancing, only log if needed
		}
		if ctx.Err() != nil {
			return
		}
	}
}
