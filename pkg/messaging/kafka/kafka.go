// Package kafka provides a Kafka-based implementation of the messaging broker interface.
package kafka

import (
	"context"
	"fmt"
	"time"

	"github.com/IBM/sarama"
	"google.golang.org/protobuf/proto"

	"github.com/ahrav/gitleaks-armada/pkg/messaging"
	pb "github.com/ahrav/gitleaks-armada/proto/scanner"
)

// Config contains settings for connecting to and interacting with Kafka brokers.
// It defines the topics, consumer group, and client identifiers needed for message routing.
type Config struct {
	// Brokers is a list of Kafka broker addresses to connect to.
	Brokers []string

	// TaskTopic is the topic name for publishing scan tasks.
	TaskTopic string
	// ResultsTopic is the topic name for publishing scan results.
	ResultsTopic string
	// ProgressTopic is the topic name for publishing scan progress updates.
	ProgressTopic string
	// RulesTopic is the topic name for publishing scanning rules.
	RulesTopic string

	// GroupID identifies the consumer group for this broker instance.
	GroupID string
	// ClientID uniquely identifies this client to the Kafka cluster.
	ClientID string
}

var _ messaging.Broker = new(Broker)

// Broker implements the messaging.Broker interface using Apache Kafka.
// It handles publishing and subscribing to messages across different topics
// for scan tasks, results, progress updates, and rules.
type Broker struct {
	producer      sarama.SyncProducer
	consumerGroup sarama.ConsumerGroup

	taskTopic     string
	resultsTopic  string
	progressTopic string
	rulesTopic    string

	clientID string
}

// NewBroker creates a new Kafka broker with the provided configuration.
// It sets up both a producer and consumer group with appropriate settings
// for reliable message delivery and consumption.
func NewBroker(cfg *Config) (*Broker, error) {
	// Configure the producer for reliable delivery with acknowledgments
	producerConfig := sarama.NewConfig()
	producerConfig.Producer.RequiredAcks = sarama.WaitForAll
	producerConfig.Producer.Return.Successes = true
	producerConfig.ClientID = cfg.ClientID

	// Use round-robin partitioner to evenly distribute messages
	producerConfig.Producer.Partitioner = sarama.NewRoundRobinPartitioner

	producer, err := sarama.NewSyncProducer(cfg.Brokers, producerConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create kafka producer: %w", err)
	}

	consumerConfig := sarama.NewConfig()
	consumerConfig.ClientID = cfg.ClientID
	consumerConfig.Consumer.Group.Rebalance.Strategy = sarama.NewBalanceStrategyRoundRobin()

	// Start from newest offset to avoid processing historical messages
	consumerConfig.Consumer.Offsets.Initial = sarama.OffsetNewest

	// Configure session management timeouts
	consumerConfig.Consumer.Group.Session.Timeout = 20 * time.Second
	consumerConfig.Consumer.Group.Heartbeat.Interval = 6 * time.Second

	// Enable automatic offset commits
	consumerConfig.Consumer.Offsets.AutoCommit.Enable = true
	consumerConfig.Consumer.Offsets.AutoCommit.Interval = 1 * time.Second

	consumerConfig.Version = sarama.V2_8_0_0

	consumerGroup, err := sarama.NewConsumerGroup(cfg.Brokers, cfg.GroupID, consumerConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create consumer group: %w", err)
	}

	return &Broker{
		producer:      producer,
		consumerGroup: consumerGroup,
		taskTopic:     cfg.TaskTopic,
		resultsTopic:  cfg.ResultsTopic,
		progressTopic: cfg.ProgressTopic,
		clientID:      cfg.ClientID,
	}, nil
}

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

// -------------------------------------------------------------------------------------------------
// -- Result Publishing and Subscribing --
// -------------------------------------------------------------------------------------------------

// PublishResult publishes a scan result to Kafka.
// It converts domain findings and status to protobuf format before publishing.
func (k *Broker) PublishResult(ctx context.Context, result messaging.ScanResult) error {
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
	}
	go consumeLoop(ctx, k.consumerGroup, []string{k.rulesTopic}, h)
	return nil
}

type rulesHandler struct {
	rulesTopic string
	handler    func(messaging.GitleaksRuleSet) error
}

func (h *rulesHandler) Setup(_ sarama.ConsumerGroupSession) error   { return nil }
func (h *rulesHandler) Cleanup(_ sarama.ConsumerGroupSession) error { return nil }

func (h *rulesHandler) ConsumeClaim(sess sarama.ConsumerGroupSession, claim sarama.ConsumerGroupClaim) error {
	for msg := range claim.Messages() {
		var ruleSet pb.RuleSet
		if err := proto.Unmarshal(msg.Value, &ruleSet); err != nil {
			sess.MarkMessage(msg, "")
			continue
		}

		if err := h.handler(messaging.ProtoToGitleaksRuleSet(&ruleSet)); err != nil {
			// Log or handle error, but don't necessarily stop processing
		}
		sess.MarkMessage(msg, "")
	}
	return nil
}

// consumeLoop continuously consumes messages from Kafka topics until context cancellation.
// It handles consumer group rebalancing and reconnection automatically.
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
