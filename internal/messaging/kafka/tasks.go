package kafka

import (
	"context"
	"fmt"

	"github.com/IBM/sarama"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/proto"

	"github.com/ahrav/gitleaks-armada/internal/messaging/kafka/tracing"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
	"github.com/ahrav/gitleaks-armada/pkg/messaging"
	pb "github.com/ahrav/gitleaks-armada/proto/scanner"
)

// -------------------------------------------------------------------------------------------------
// -- Task Publishing and Subscribing --
// -------------------------------------------------------------------------------------------------

// PublishTask publishes a single scan task to Kafka.
// It serializes the task to protobuf format and uses the task ID as the message key
// for consistent partition routing.
func (k *Broker) PublishTask(ctx context.Context, task messaging.Task) error {
	ctx, span := tracing.StartProducerSpan(ctx, k.taskTopic, k.tracer)
	defer span.End()

	pbTask := &pb.ScanTask{
		TaskId:      task.TaskID,
		ResourceUri: task.ResourceURI,
		Metadata:    task.Metadata,
		Credentials: task.Credentials.ToProto(),
	}
	data, err := proto.Marshal(pbTask)
	if err != nil {
		span.RecordError(err)
		k.metrics.IncPublishError(k.taskTopic)
		return fmt.Errorf("failed to marshal ScanTask: %w", err)
	}

	msg := &sarama.ProducerMessage{
		Topic: k.taskTopic,
		Key:   sarama.StringEncoder(task.TaskID),
		Value: sarama.ByteEncoder(data),
	}
	tracing.InjectTraceContext(ctx, msg)

	_, _, err = k.producer.SendMessage(msg)
	if err != nil {
		span.RecordError(err)
		k.metrics.IncPublishError(k.taskTopic)
	}
	k.metrics.IncMessagePublished(k.taskTopic)

	return err
}

// PublishTasks publishes multiple scan tasks to Kafka.
// Tasks are published sequentially, with the first error encountered being returned.
func (k *Broker) PublishTasks(ctx context.Context, tasks []messaging.Task) error {
	for _, t := range tasks {
		if err := k.PublishTask(ctx, t); err != nil {
			return err
		}
	}
	return nil
}

// SubscribeTasks registers a handler function to process incoming scan tasks.
// The handler is called for each task message received from the task topic.
func (k *Broker) SubscribeTasks(ctx context.Context, handler func(context.Context, messaging.Task) error) error {
	h := &taskHandler{
		taskTopic: k.taskTopic,
		handler:   handler,
		clientID:  k.clientID,
		tracer:    k.tracer,
		logger:    k.logger,
		metrics:   k.metrics,
	}

	k.logger.Info(ctx, "Subscribing to tasks topic", "client_id", k.clientID, "topic", k.taskTopic)
	go k.consumeLoop(ctx, k.consumerGroup, []string{k.taskTopic}, h)
	return nil
}

type taskHandler struct {
	clientID string

	taskTopic string
	handler   func(context.Context, messaging.Task) error

	tracer  trace.Tracer
	metrics BrokerMetrics
	logger  *logger.Logger
}

func (h *taskHandler) Setup(sess sarama.ConsumerGroupSession) error {
	logSetup(h.logger, h.clientID, h.taskTopic, sess)
	return nil
}

func (h *taskHandler) Cleanup(sess sarama.ConsumerGroupSession) error {
	logCleanup(h.logger, h.clientID, h.taskTopic, sess)
	return nil
}

func (h *taskHandler) ConsumeClaim(sess sarama.ConsumerGroupSession, claim sarama.ConsumerGroupClaim) error {
	logPartitionStart(h.logger, h.clientID, h.taskTopic, claim.Partition(), sess.MemberID())
	for msg := range claim.Messages() {
		msgCtx := tracing.ExtractTraceContext(sess.Context(), msg)
		msgCtx, span := tracing.StartConsumerSpan(msgCtx, msg, h.tracer)

		var pbTask pb.ScanTask
		if err := proto.Unmarshal(msg.Value, &pbTask); err != nil {
			span.RecordError(err)
			h.metrics.IncConsumeError(h.taskTopic)
			span.End()
			sess.MarkMessage(msg, "")
			continue
		}

		task := messaging.Task{
			TaskID:      pbTask.TaskId,
			ResourceURI: pbTask.ResourceUri,
			Metadata:    pbTask.Metadata,
		}

		if err := h.handler(msgCtx, task); err != nil {
			span.RecordError(err)
			h.metrics.IncConsumeError(h.taskTopic)
		} else {
			h.metrics.IncMessageConsumed(h.taskTopic)
		}

		span.End()
		sess.MarkMessage(msg, "")
	}
	return nil
}
