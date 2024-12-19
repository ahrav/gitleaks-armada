package orchestration

import (
	"context"
	"fmt"

	"github.com/IBM/sarama"
	"google.golang.org/protobuf/proto"

	pb "github.com/ahrav/gitleaks-armada/proto/scanner"
)

// KafkaBroker handles publishing scan tasks and consuming scan results via Kafka.
type KafkaBroker struct {
	producer      sarama.SyncProducer
	consumerGroup sarama.ConsumerGroup
	taskTopic     string
	resultsTopic  string
}

// KafkaConfig contains the configuration needed to set up a KafkaBroker.
type KafkaConfig struct {
	Brokers      []string
	TaskTopic    string
	ResultsTopic string
	GroupID      string // Consumer group ID for coordinating message consumption
}

// NewKafkaBroker creates a new broker that can publish tasks and subscribe to results.
func NewKafkaBroker(cfg *KafkaConfig) (*KafkaBroker, error) {
	producer, err := sarama.NewSyncProducer(cfg.Brokers, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create kafka producer: %w", err)
	}

	consumerGroup, err := sarama.NewConsumerGroup(cfg.Brokers, cfg.GroupID, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create consumer group: %w", err)
	}

	return &KafkaBroker{
		producer:      producer,
		consumerGroup: consumerGroup,
		taskTopic:     cfg.TaskTopic,
		resultsTopic:  cfg.ResultsTopic,
	}, nil
}

// PublishTask publishes a single scan task to Kafka.
func (k *KafkaBroker) PublishTask(ctx context.Context, chunk Chunk) error {
	// Convert domain Chunk to protobuf message at the boundary
	pbChunk := &pb.ScanChunk{
		// ChunkId:  chunk.ID,
		// Metadata: chunk.Metadata,
	}

	data, err := proto.Marshal(pbChunk)
	if err != nil {
		return fmt.Errorf("failed to marshal chunk: %w", err)
	}

	msg := &sarama.ProducerMessage{
		Topic: k.taskTopic,
		Value: sarama.ByteEncoder(data),
	}
	_, _, err = k.producer.SendMessage(msg)
	return err
}

// PublishTasks publishes multiple scan tasks to Kafka.
func (k *KafkaBroker) PublishTasks(ctx context.Context, chunks []Chunk) error {
	for _, c := range chunks {
		if err := k.PublishTask(ctx, c); err != nil {
			return err
		}
	}
	return nil
}

// PublishResult publishes a scan result to Kafka
func (k *KafkaBroker) PublishResult(ctx context.Context, result ScanResult) error {
	pbResult := &pb.ScanResult{
		ChunkId: result.ChunkID,
		// ... convert other fields
	}

	data, err := proto.Marshal(pbResult)
	if err != nil {
		return fmt.Errorf("failed to marshal result: %w", err)
	}

	msg := &sarama.ProducerMessage{
		Topic: k.resultsTopic,
		Value: sarama.ByteEncoder(data),
	}
	_, _, err = k.producer.SendMessage(msg)
	return err
}

// SubscribeTasks starts consuming scan tasks from Kafka
func (k *KafkaBroker) SubscribeTasks(ctx context.Context, handler func(Chunk) error) error {
	h := &taskHandler{
		taskTopic: k.taskTopic,
		handler:   handler,
	}

	go func() {
		for {
			if err := k.consumerGroup.Consume(ctx, []string{k.taskTopic}, h); err != nil {
				// Consumer group session ended, will retry unless context is cancelled
			}
			if ctx.Err() != nil {
				return
			}
		}
	}()

	return nil
}

// taskHandler implements sarama.ConsumerGroupHandler to process scan tasks
type taskHandler struct {
	taskTopic string
	handler   func(Chunk) error
}

func (h *taskHandler) Setup(_ sarama.ConsumerGroupSession) error   { return nil }
func (h *taskHandler) Cleanup(_ sarama.ConsumerGroupSession) error { return nil }

func (h *taskHandler) ConsumeClaim(sess sarama.ConsumerGroupSession, claim sarama.ConsumerGroupClaim) error {
	for msg := range claim.Messages() {
		var pbChunk pb.ScanChunk
		if err := proto.Unmarshal(msg.Value, &pbChunk); err != nil {
			sess.MarkMessage(msg, "")
			continue
		}

		// Convert protobuf message to domain type at the boundary
		chunk := Chunk{
			// ID:       pbChunk.ChunkId,
			// Metadata: pbChunk.Metadata,
		}

		if err := h.handler(chunk); err != nil {
			// Handler failed to process the chunk
		}
		sess.MarkMessage(msg, "")
	}
	return nil
}

// SubscribeResults starts consuming scan results from Kafka.
func (k *KafkaBroker) SubscribeResults(ctx context.Context, handler func(ScanResult) error) error {
	h := &resultsHandler{
		resultsTopic: k.resultsTopic,
		handler:      handler,
	}

	go func() {
		for {
			if err := k.consumerGroup.Consume(ctx, []string{k.resultsTopic}, h); err != nil {
				// Consumer group session ended, will retry unless context is cancelled
			}
			if ctx.Err() != nil {
				return
			}
		}
	}()

	return nil
}

// resultsHandler implements sarama.ConsumerGroupHandler to process scan results.
type resultsHandler struct {
	resultsTopic string
	handler      func(ScanResult) error
}

func (h *resultsHandler) Setup(_ sarama.ConsumerGroupSession) error   { return nil }
func (h *resultsHandler) Cleanup(_ sarama.ConsumerGroupSession) error { return nil }

// ConsumeClaim processes messages from a Kafka partition, unmarshaling them into ScanResults
// and passing them to the handler.
func (h *resultsHandler) ConsumeClaim(sess sarama.ConsumerGroupSession, claim sarama.ConsumerGroupClaim) error {
	for msg := range claim.Messages() {
		var pbResult pb.ScanResult
		if err := proto.Unmarshal(msg.Value, &pbResult); err != nil {
			sess.MarkMessage(msg, "")
			continue
		}

		// Convert protobuf message to domain type at the boundary
		result := ScanResult{
			ChunkID: pbResult.ChunkId,
			// ... convert other fields as needed
		}

		if err := h.handler(result); err != nil {
			// Handler failed to process the result
		}
		sess.MarkMessage(msg, "")
	}
	return nil
}
