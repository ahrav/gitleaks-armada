package kafka

import (
	"context"

	"github.com/IBM/sarama"

	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

// consumeLoop continuously consumes messages from Kafka topics until context cancellation.
// It handles consumer group rebalancing and reconnection automatically.
func (k *Broker) consumeLoop(
	ctx context.Context,
	cg sarama.ConsumerGroup,
	topics []string,
	handler sarama.ConsumerGroupHandler,
) {
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
func logSetup(logger *logger.Logger, clientID string, sess sarama.ConsumerGroupSession) {
	logger.Info(
		context.Background(),
		"Consumer group session setup",
		"client_id", clientID,
		"generation_id", sess.GenerationID(),
		"member_id", sess.MemberID(),
	)
}

func logCleanup(logger *logger.Logger, clientID string, sess sarama.ConsumerGroupSession) {
	logger.Info(
		context.Background(),
		"Consumer group session cleanup",
		"client_id", clientID,
		"generation_id", sess.GenerationID(),
		"member_id", sess.MemberID(),
	)
}

func logPartitionStart(logger *logger.Logger, clientID string, partition int32, memberID string) {
	logger.Info(
		context.Background(),
		"Starting to consume from partition",
		"client_id", clientID,
		"partition", partition,
		"member_id", memberID,
	)
}
