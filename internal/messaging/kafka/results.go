package kafka

import (
	"context"
	"fmt"

	"github.com/IBM/sarama"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/proto"

	"github.com/ahrav/gitleaks-armada/internal/messaging/kafka/tracing"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
	"github.com/ahrav/gitleaks-armada/pkg/messaging/protobuf"
	"github.com/ahrav/gitleaks-armada/pkg/messaging/types"
	pb "github.com/ahrav/gitleaks-armada/proto/scanner"
)

// -------------------------------------------------------------------------------------------------
// -- Result Publishing and Subscribing --
// -------------------------------------------------------------------------------------------------

// PublishResult publishes a scan result to Kafka.
// It converts domain findings and status to protobuf format before publishing.
func (k *Broker) PublishResult(ctx context.Context, result types.ScanResult) error {
	ctx, span := tracing.StartProducerSpan(ctx, k.resultsTopic, k.tracer)
	defer span.End()

	pbResult := protobuf.ScanResultToProto(result)
	data, err := proto.Marshal(pbResult)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to marshal ScanResult: %w", err)
	}

	msg := &sarama.ProducerMessage{
		Topic: k.resultsTopic,
		Key:   sarama.StringEncoder(result.TaskID),
		Value: sarama.ByteEncoder(data),
	}
	tracing.InjectTraceContext(ctx, msg)

	_, _, err = k.producer.SendMessage(msg)
	if err != nil {
		span.RecordError(err)
	}
	return err
}

// SubscribeResults registers a handler function to process incoming scan results.
// The handler is called for each result message received from the results topic.
func (k *Broker) SubscribeResults(ctx context.Context, handler func(context.Context, types.ScanResult) error) error {
	h := &resultsHandler{
		resultsTopic: k.resultsTopic,
		handler:      handler,
		clientID:     k.clientID,
		tracer:       k.tracer,
		logger:       k.logger,
	}
	k.logger.Info(context.Background(), "Subscribing to results topic", "client_id", k.clientID, "topic", k.resultsTopic)
	go k.consumeLoop(ctx, k.consumerGroup, []string{k.resultsTopic}, h)
	return nil
}

type resultsHandler struct {
	clientID string

	resultsTopic string
	handler      func(context.Context, types.ScanResult) error

	logger *logger.Logger
	tracer trace.Tracer
}

func (h *resultsHandler) Setup(sess sarama.ConsumerGroupSession) error {
	logSetup(h.logger, h.clientID, h.resultsTopic, sess)
	return nil
}

func (h *resultsHandler) Cleanup(sess sarama.ConsumerGroupSession) error {
	logCleanup(h.logger, h.clientID, h.resultsTopic, sess)
	return nil
}

func (h *resultsHandler) ConsumeClaim(sess sarama.ConsumerGroupSession, claim sarama.ConsumerGroupClaim) error {
	logPartitionStart(h.logger, h.clientID, h.resultsTopic, claim.Partition(), sess.MemberID())
	for msg := range claim.Messages() {
		msgCtx := tracing.ExtractTraceContext(sess.Context(), msg)
		msgCtx, span := tracing.StartConsumerSpan(msgCtx, msg, h.tracer)

		var pbResult pb.ScanResult
		if err := proto.Unmarshal(msg.Value, &pbResult); err != nil {
			span.RecordError(err)
			span.End()
			sess.MarkMessage(msg, "")
			continue
		}

		result := protobuf.ProtoToScanResult(&pbResult)
		if err := h.handler(msgCtx, result); err != nil {
			span.RecordError(err)
		}

		span.End()
		sess.MarkMessage(msg, "")
	}
	return nil
}
