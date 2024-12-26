package kafka

import (
	"context"
	"log"

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

// Add these helper functions to standardize logging
func logSetup(clientID string, sess sarama.ConsumerGroupSession) {
	log.Printf("[%s] Consumer group session setup - GenerationID: %d, MemberID: %s",
		clientID, sess.GenerationID(), sess.MemberID())
}

func logCleanup(clientID string, sess sarama.ConsumerGroupSession) {
	log.Printf("[%s] Consumer group session cleanup - GenerationID: %d, MemberID: %s",
		clientID, sess.GenerationID(), sess.MemberID())
}

func logPartitionStart(clientID string, partition int32, memberID string) {
	log.Printf("[%s] Starting to consume from partition: %d, member: %s",
		clientID, partition, memberID)
}
