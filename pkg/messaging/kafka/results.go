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
