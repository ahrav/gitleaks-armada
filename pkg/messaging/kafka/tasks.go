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
// -- Task Publishing and Subscribing --
// -------------------------------------------------------------------------------------------------

// PublishTask publishes a single scan task to Kafka.
// It serializes the task to protobuf format and uses the task ID as the message key
// for consistent partition routing.
func (k *Broker) PublishTask(ctx context.Context, task messaging.Task) error {
	pbTask := &pb.ScanTask{
		TaskId:      task.TaskID,
		ResourceUri: task.ResourceURI,
		Metadata:    task.Metadata,
		Credentials: task.Credentials.ToProto(),
	}
	data, err := proto.Marshal(pbTask)
	if err != nil {
		return fmt.Errorf("failed to marshal ScanTask: %w", err)
	}

	msg := &sarama.ProducerMessage{
		Topic: k.taskTopic,
		Key:   sarama.StringEncoder(task.TaskID),
		Value: sarama.ByteEncoder(data),
	}
	_, _, err = k.producer.SendMessage(msg)
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
func (k *Broker) SubscribeTasks(ctx context.Context, handler func(messaging.Task) error) error {
	h := &taskHandler{
		taskTopic: k.taskTopic,
		handler:   handler,
	}

	go consumeLoop(ctx, k.consumerGroup, []string{k.taskTopic}, h)
	return nil
}

type taskHandler struct {
	taskTopic string
	handler   func(messaging.Task) error
}

func (h *taskHandler) Setup(_ sarama.ConsumerGroupSession) error   { return nil }
func (h *taskHandler) Cleanup(_ sarama.ConsumerGroupSession) error { return nil }

func (h *taskHandler) ConsumeClaim(sess sarama.ConsumerGroupSession, claim sarama.ConsumerGroupClaim) error {
	for msg := range claim.Messages() {
		var pbTask pb.ScanTask
		if err := proto.Unmarshal(msg.Value, &pbTask); err != nil {
			sess.MarkMessage(msg, "")
			continue
		}

		task := messaging.Task{
			TaskID:      pbTask.TaskId,
			ResourceURI: pbTask.ResourceUri,
			Metadata:    pbTask.Metadata,
		}

		if err := h.handler(task); err != nil {
			// Handler errors are logged but don't stop processing
		}
		sess.MarkMessage(msg, "")
	}
	return nil
}
