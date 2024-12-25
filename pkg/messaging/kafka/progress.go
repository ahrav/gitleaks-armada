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
// -- Progress Publishing and Subscribing --
// -------------------------------------------------------------------------------------------------

// PublishProgress publishes scan progress updates to Kafka.
// Progress updates help track the status of long-running scan operations.
func (k *Broker) PublishProgress(ctx context.Context, progress messaging.ScanProgress) error {
	pbProgress := &pb.ScanProgress{
		TaskId:          progress.TaskID,
		PercentComplete: progress.PercentComplete,
		ItemsProcessed:  progress.ItemsProcessed,
		TotalItems:      progress.TotalItems,
		Metadata:        progress.Metadata,
	}

	data, err := proto.Marshal(pbProgress)
	if err != nil {
		return fmt.Errorf("failed to marshal ScanProgress: %w", err)
	}

	msg := &sarama.ProducerMessage{
		Topic: k.progressTopic,
		Key:   sarama.StringEncoder(progress.TaskID),
		Value: sarama.ByteEncoder(data),
	}
	_, _, err = k.producer.SendMessage(msg)
	return err
}

// SubscribeProgress registers a handler function to process incoming progress updates.
// The handler is called for each progress message received from the progress topic.
func (k *Broker) SubscribeProgress(ctx context.Context, handler func(messaging.ScanProgress) error) error {
	h := &progressHandler{
		progressTopic: k.progressTopic,
		handler:       handler,
	}

	go consumeLoop(ctx, k.consumerGroup, []string{k.progressTopic}, h)
	return nil
}

type progressHandler struct {
	progressTopic string
	handler       func(messaging.ScanProgress) error
}

func (h *progressHandler) Setup(_ sarama.ConsumerGroupSession) error   { return nil }
func (h *progressHandler) Cleanup(_ sarama.ConsumerGroupSession) error { return nil }

func (h *progressHandler) ConsumeClaim(sess sarama.ConsumerGroupSession, claim sarama.ConsumerGroupClaim) error {
	for msg := range claim.Messages() {
		var pbProgress pb.ScanProgress
		if err := proto.Unmarshal(msg.Value, &pbProgress); err != nil {
			sess.MarkMessage(msg, "")
			continue
		}

		progress := messaging.ScanProgress{
			TaskID:          pbProgress.TaskId,
			PercentComplete: pbProgress.PercentComplete,
			ItemsProcessed:  pbProgress.ItemsProcessed,
			TotalItems:      pbProgress.TotalItems,
			Metadata:        pbProgress.Metadata,
		}

		if err := h.handler(progress); err != nil {
			// Handler errors are logged but don't stop processing
		}
		sess.MarkMessage(msg, "")
	}
	return nil
}
