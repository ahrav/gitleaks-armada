package kafka

import (
	"context"
	"fmt"
	"log"

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
		clientID:   k.clientID,
	}
	log.Printf("[%s] Subscribing to rules topic: %s", k.clientID, k.rulesTopic)
	go consumeLoop(ctx, k.consumerGroup, []string{k.rulesTopic}, h)
	return nil
}

type rulesHandler struct {
	rulesTopic string
	handler    func(messaging.GitleaksRuleSet) error
	clientID   string
}

func (h *rulesHandler) Setup(sess sarama.ConsumerGroupSession) error {
	logSetup(h.clientID, sess)
	return nil
}

func (h *rulesHandler) Cleanup(sess sarama.ConsumerGroupSession) error {
	logCleanup(h.clientID, sess)
	return nil
}

func (h *rulesHandler) ConsumeClaim(sess sarama.ConsumerGroupSession, claim sarama.ConsumerGroupClaim) error {
	logPartitionStart(h.clientID, claim.Partition(), sess.MemberID())

	for msg := range claim.Messages() {
		var ruleSet pb.RuleSet
		if err := proto.Unmarshal(msg.Value, &ruleSet); err != nil {
			log.Printf("[%s] Error unmarshalling rules: %v", h.clientID, err)
			sess.MarkMessage(msg, "")
			continue
		}

		if err := h.handler(messaging.ProtoToGitleaksRuleSet(&ruleSet)); err != nil {
			log.Printf("[%s] Error handling rules: %v", h.clientID, err)
		} else {
			log.Printf("[%s] Successfully processed rules message", h.clientID)
		}
		sess.MarkMessage(msg, "")
	}
	return nil
}
