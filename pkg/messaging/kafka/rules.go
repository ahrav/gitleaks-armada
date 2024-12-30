package kafka

import (
	"context"
	"fmt"

	"github.com/IBM/sarama"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/proto"

	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
	"github.com/ahrav/gitleaks-armada/pkg/messaging"
	"github.com/ahrav/gitleaks-armada/pkg/messaging/kafka/tracing"
	pb "github.com/ahrav/gitleaks-armada/proto/scanner"
)

// -------------------------------------------------------------------------------------------------
// -- Rules Publishing and Subscribing --
// -------------------------------------------------------------------------------------------------

// PublishRule publishes a single scanning rule to Kafka.
// These rules define patterns for detecting sensitive information in scanned content.
func (k *Broker) PublishRule(ctx context.Context, rules messaging.GitleaksRuleMessage) error {
	ctx, span := tracing.StartProducerSpan(ctx, k.rulesTopic, k.tracer)
	defer span.End()

	pbRules := rules.ToProto()
	data, err := proto.Marshal(pbRules)
	if err != nil {
		span.RecordError(err)
		k.metrics.IncPublishError(k.rulesTopic)
		return fmt.Errorf("failed to marshal GitleaksRuleSet: %w", err)
	}

	msg := &sarama.ProducerMessage{
		Topic: k.rulesTopic,
		Key:   sarama.StringEncoder(rules.Hash),
		Value: sarama.ByteEncoder(data),
	}
	tracing.InjectTraceContext(ctx, msg)

	_, _, err = k.producer.SendMessage(msg)
	if err != nil {
		span.RecordError(err)
		k.metrics.IncPublishError(k.rulesTopic)
		return fmt.Errorf("failed to send message: %w", err)
	}

	k.metrics.IncMessagePublished(k.rulesTopic)
	return nil
}

// SubscribeRules registers a handler function to process incoming scanning rules.
// The handler is called for each rules message received from the rules topic.
func (k *Broker) SubscribeRules(ctx context.Context, handler func(context.Context, messaging.GitleaksRuleMessage) error) error {
	h := &rulesHandler{
		rulesTopic: k.rulesTopic,
		handler:    handler,
		clientID:   k.clientID,
		tracer:     k.tracer,
		logger:     k.logger,
		metrics:    k.metrics,
	}

	k.logger.Info(context.Background(), "Subscribing to rules topic", "client_id", k.clientID, "topic", k.rulesTopic)
	go k.consumeLoop(ctx, k.consumerGroup, []string{k.rulesTopic}, h)
	return nil
}

type rulesHandler struct {
	clientID string

	rulesTopic string
	handler    func(context.Context, messaging.GitleaksRuleMessage) error

	tracer  trace.Tracer
	logger  *logger.Logger
	metrics BrokerMetrics
}

func (h *rulesHandler) Setup(sess sarama.ConsumerGroupSession) error {
	logSetup(h.logger, h.clientID, h.rulesTopic, sess)
	return nil
}

func (h *rulesHandler) Cleanup(sess sarama.ConsumerGroupSession) error {
	logCleanup(h.logger, h.clientID, h.rulesTopic, sess)
	return nil
}

func (h *rulesHandler) ConsumeClaim(sess sarama.ConsumerGroupSession, claim sarama.ConsumerGroupClaim) error {
	logPartitionStart(h.logger, h.clientID, h.rulesTopic, claim.Partition(), sess.MemberID())
	for msg := range claim.Messages() {
		h.logger.Info(sess.Context(), "Received message on rules topic",
			"client_id", h.clientID,
			"partition", claim.Partition(),
			"offset", msg.Offset)

		msgCtx := tracing.ExtractTraceContext(sess.Context(), msg)
		msgCtx, span := tracing.StartConsumerSpan(msgCtx, msg, h.tracer)

		var pbRules pb.RuleMessage
		if err := proto.Unmarshal(msg.Value, &pbRules); err != nil {
			span.RecordError(err)
			span.End()
			sess.MarkMessage(msg, "")
			h.metrics.IncConsumeError(h.rulesTopic)
			continue
		}

		rule := messaging.ProtoToGitleaksRuleMessage(&pbRules)
		if err := h.handler(msgCtx, rule); err != nil {
			span.RecordError(err)
			h.metrics.IncConsumeError(h.rulesTopic)
			h.logger.Error(msgCtx, "Failed to handle rules message",
				"client_id", h.clientID,
				"error", err)
		} else {
			h.metrics.IncMessageConsumed(h.rulesTopic)
			h.logger.Info(msgCtx, "Successfully processed rules message",
				"client_id", h.clientID)
		}

		span.End()
		sess.MarkMessage(msg, "")
	}
	return nil
}
