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
// -- Result Publishing and Subscribing --
// -------------------------------------------------------------------------------------------------

// PublishResult publishes a scan result to Kafka.
// It converts domain findings and status to protobuf format before publishing.
func (k *Broker) PublishResult(ctx context.Context, result messaging.ScanResult) error {
	data, err := proto.Marshal(result.ToProto())
	if err != nil {
		return fmt.Errorf("failed to marshal ScanResult: %w", err)
	}

	msg := &sarama.ProducerMessage{
		Topic: k.resultsTopic,
		Key:   sarama.StringEncoder(result.TaskID),
		Value: sarama.ByteEncoder(data),
	}
	_, _, err = k.producer.SendMessage(msg)
	return err
}

// SubscribeResults registers a handler function to process incoming scan results.
// The handler is called for each result message received from the results topic.
func (k *Broker) SubscribeResults(ctx context.Context, handler func(messaging.ScanResult) error) error {
	h := &resultsHandler{
		resultsTopic: k.resultsTopic,
		handler:      handler,
	}

	go consumeLoop(ctx, k.consumerGroup, []string{k.resultsTopic}, h)
	return nil
}

type resultsHandler struct {
	resultsTopic string
	handler      func(messaging.ScanResult) error
}

func (h *resultsHandler) Setup(_ sarama.ConsumerGroupSession) error   { return nil }
func (h *resultsHandler) Cleanup(_ sarama.ConsumerGroupSession) error { return nil }

func (h *resultsHandler) ConsumeClaim(sess sarama.ConsumerGroupSession, claim sarama.ConsumerGroupClaim) error {
	for msg := range claim.Messages() {
		var pbResult pb.ScanResult
		if err := proto.Unmarshal(msg.Value, &pbResult); err != nil {
			sess.MarkMessage(msg, "")
			continue
		}

		result := messaging.ProtoToScanResult(&pbResult)

		if err := h.handler(result); err != nil {
			// Handler errors are logged but don't stop processing
		}

		sess.MarkMessage(msg, "")
	}
	return nil
}
