package kafka

import (
	"context"
	"fmt"

	"github.com/IBM/sarama"
	"google.golang.org/protobuf/proto"

	"github.com/ahrav/gitleaks-armada/pkg/messaging"
	pb "github.com/ahrav/gitleaks-armada/proto/scanner"
)

// KafkaConfig contains configuration for connecting to Kafka brokers and topics.
type KafkaConfig struct {
	Brokers       []string
	TaskTopic     string
	ResultsTopic  string
	ProgressTopic string
	GroupID       string
}

// KafkaBroker implements the Broker interface using Apache Kafka as the message queue.
type KafkaBroker struct {
	producer      sarama.SyncProducer
	consumerGroup sarama.ConsumerGroup
	taskTopic     string
	resultsTopic  string
	progressTopic string
}

// NewKafkaBroker creates a new Kafka broker with the provided configuration.
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
		progressTopic: cfg.ProgressTopic,
	}, nil
}

// PublishTask publishes a single scan task to Kafka.
func (k *KafkaBroker) PublishTask(ctx context.Context, task messaging.Task) error {
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
		Value: sarama.ByteEncoder(data),
	}
	_, _, err = k.producer.SendMessage(msg)
	return err
}

// PublishTasks publishes multiple scan tasks to Kafka.
func (k *KafkaBroker) PublishTasks(ctx context.Context, tasks []messaging.Task) error {
	for _, t := range tasks {
		if err := k.PublishTask(ctx, t); err != nil {
			return err
		}
	}
	return nil
}

// PublishResult publishes a scan result to Kafka.
func (k *KafkaBroker) PublishResult(ctx context.Context, result messaging.ScanResult) error {
	pbFindings := make([]*pb.Finding, len(result.Findings))
	for i, f := range result.Findings {
		pbFindings[i] = &pb.Finding{
			Location:   f.Location,
			LineNumber: f.LineNumber,
			SecretType: f.SecretType,
			Match:      f.Match,
			Confidence: float32(f.Confidence),
		}
	}

	pbStatus := pb.ScanStatus_SCAN_STATUS_UNSPECIFIED
	switch result.Status {
	case messaging.ScanStatusSuccess:
		pbStatus = pb.ScanStatus_SCAN_STATUS_SUCCESS
	case messaging.ScanStatusError:
		pbStatus = pb.ScanStatus_SCAN_STATUS_ERROR
	}

	pbResult := &pb.ScanResult{
		TaskId:   result.TaskID,
		Findings: pbFindings,
		Status:   pbStatus,
		Error:    result.Error,
	}

	data, err := proto.Marshal(pbResult)
	if err != nil {
		return fmt.Errorf("failed to marshal ScanResult: %w", err)
	}

	msg := &sarama.ProducerMessage{
		Topic: k.resultsTopic,
		Value: sarama.ByteEncoder(data),
	}
	_, _, err = k.producer.SendMessage(msg)
	return err
}

// PublishProgress publishes scan progress updates to Kafka.
func (k *KafkaBroker) PublishProgress(ctx context.Context, progress messaging.ScanProgress) error {
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
		Value: sarama.ByteEncoder(data),
	}
	_, _, err = k.producer.SendMessage(msg)
	return err
}

// SubscribeTasks registers a handler function to process incoming scan tasks.
func (k *KafkaBroker) SubscribeTasks(ctx context.Context, handler func(messaging.Task) error) error {
	h := &taskHandler{
		taskTopic: k.taskTopic,
		handler:   handler,
	}

	go consumeLoop(ctx, k.consumerGroup, []string{k.taskTopic}, h)
	return nil
}

// SubscribeResults registers a handler function to process incoming scan results.
func (k *KafkaBroker) SubscribeResults(ctx context.Context, handler func(messaging.ScanResult) error) error {
	h := &resultsHandler{
		resultsTopic: k.resultsTopic,
		handler:      handler,
	}

	go consumeLoop(ctx, k.consumerGroup, []string{k.resultsTopic}, h)
	return nil
}

// SubscribeProgress registers a handler function to process incoming progress updates.
func (k *KafkaBroker) SubscribeProgress(ctx context.Context, handler func(messaging.ScanProgress) error) error {
	h := &progressHandler{
		progressTopic: k.progressTopic,
		handler:       handler,
	}

	go consumeLoop(ctx, k.consumerGroup, []string{k.progressTopic}, h)
	return nil
}

// consumeLoop continuously consumes messages from Kafka topics until context cancellation.
func consumeLoop(ctx context.Context, cg sarama.ConsumerGroup, topics []string, handler sarama.ConsumerGroupHandler) {
	for {
		if err := cg.Consume(ctx, topics, handler); err != nil {
			// Errors are expected when rebalancing, only log if needed
		}
		if ctx.Err() != nil {
			return
		}
	}
}

// Handlers implement the sarama.ConsumerGroupHandler interface for different message types

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

		findings := make([]messaging.Finding, len(pbResult.Findings))
		for i, f := range pbResult.Findings {
			findings[i] = messaging.Finding{
				Location:   f.Location,
				LineNumber: f.LineNumber,
				SecretType: f.SecretType,
				Match:      f.Match,
				Confidence: float64(f.Confidence),
			}
		}

		var status messaging.ScanStatus
		switch pbResult.Status {
		case pb.ScanStatus_SCAN_STATUS_SUCCESS:
			status = messaging.ScanStatusSuccess
		case pb.ScanStatus_SCAN_STATUS_ERROR:
			status = messaging.ScanStatusError
		default:
			status = messaging.ScanStatusUnspecified
		}

		result := messaging.ScanResult{
			TaskID:   pbResult.TaskId,
			Findings: findings,
			Status:   status,
			Error:    pbResult.Error,
		}

		if err := h.handler(result); err != nil {
			// Handler errors are logged but don't stop processing
		}
		sess.MarkMessage(msg, "")
	}
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