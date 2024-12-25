package kafka

import (
	"context"
	"fmt"

	"github.com/IBM/sarama"
	"google.golang.org/protobuf/proto"

	"github.com/ahrav/gitleaks-armada/pkg/messaging"
	pb "github.com/ahrav/gitleaks-armada/proto/scanner"
)

// -------------------------------------------------------------------------------------------------
// -- Rules Publishing and Subscribing --
// -------------------------------------------------------------------------------------------------

// PublishRules publishes a set of scanning rules to Kafka.
// These rules define patterns for detecting sensitive information in scanned content.
func (k *Broker) PublishRules(ctx context.Context, ruleSet messaging.GitleaksRuleSet) error {
	data, err := proto.Marshal(ruleSet.ToProto())
	if err != nil {
		return fmt.Errorf("failed to marshal RuleSet: %w", err)
	}

	msg := &sarama.ProducerMessage{
		Topic: k.rulesTopic,
		Value: sarama.ByteEncoder(data),
	}
	_, _, err = k.producer.SendMessage(msg)
	return err
}

// SubscribeRules registers a handler function to process incoming scanning rules.
// The handler is called for each rules message received from the rules topic.
func (k *Broker) SubscribeRules(ctx context.Context, handler func(messaging.GitleaksRuleSet) error) error {
	h := &rulesHandler{
		rulesTopic: k.rulesTopic,
		handler:    handler,
	}
	go consumeLoop(ctx, k.consumerGroup, []string{k.rulesTopic}, h)
	return nil
}

type rulesHandler struct {
	rulesTopic string
	handler    func(messaging.GitleaksRuleSet) error
}

func (h *rulesHandler) Setup(_ sarama.ConsumerGroupSession) error   { return nil }
func (h *rulesHandler) Cleanup(_ sarama.ConsumerGroupSession) error { return nil }

func (h *rulesHandler) ConsumeClaim(sess sarama.ConsumerGroupSession, claim sarama.ConsumerGroupClaim) error {
	for msg := range claim.Messages() {
		var ruleSet pb.RuleSet
		if err := proto.Unmarshal(msg.Value, &ruleSet); err != nil {
			sess.MarkMessage(msg, "")
			continue
		}

		if err := h.handler(messaging.ProtoToGitleaksRuleSet(&ruleSet)); err != nil {
			// Log or handle error, but don't necessarily stop processing
		}
		sess.MarkMessage(msg, "")
	}
	return nil
}
