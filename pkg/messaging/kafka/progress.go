package kafka

import (
	"context"
	"fmt"
	"log"

	"github.com/IBM/sarama"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/proto"

	"github.com/ahrav/gitleaks-armada/pkg/messaging"
	"github.com/ahrav/gitleaks-armada/pkg/messaging/kafka/tracing"
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
func (k *Broker) SubscribeProgress(ctx context.Context, handler func(context.Context, messaging.ScanProgress) error) error {
	h := &progressHandler{
		progressTopic: k.progressTopic,
		handler:       handler,
		clientID:      k.clientID,
		tracer:        k.tracer,
	}
	log.Printf("[%s] Subscribing to progress topic: %s", k.clientID, k.progressTopic)
	go consumeLoop(ctx, k.consumerGroup, []string{k.progressTopic}, h)
	return nil
}

type progressHandler struct {
	clientID string

	progressTopic string
	handler       func(context.Context, messaging.ScanProgress) error

	tracer trace.Tracer
}

func (h *progressHandler) Setup(sess sarama.ConsumerGroupSession) error {
	logSetup(h.clientID, sess)
	return nil
}

func (h *progressHandler) Cleanup(sess sarama.ConsumerGroupSession) error {
	logCleanup(h.clientID, sess)
	return nil
}

func (h *progressHandler) ConsumeClaim(sess sarama.ConsumerGroupSession, claim sarama.ConsumerGroupClaim) error {
	logPartitionStart(h.clientID, claim.Partition(), sess.MemberID())
	for msg := range claim.Messages() {
		msgCtx := tracing.ExtractTraceContext(sess.Context(), msg)
		msgCtx, span := tracing.StartConsumerSpan(msgCtx, msg, h.tracer)

		var pbProgress pb.ScanProgress
		if err := proto.Unmarshal(msg.Value, &pbProgress); err != nil {
			span.RecordError(err)
			span.End()
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

		if err := h.handler(msgCtx, progress); err != nil {
			span.RecordError(err)
		}

		span.End()
		sess.MarkMessage(msg, "")
	}
	return nil
}
