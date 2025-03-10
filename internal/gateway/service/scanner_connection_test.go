package gateway_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc"

	gateway "github.com/ahrav/gitleaks-armada/internal/gateway/service"
	grpcbus "github.com/ahrav/gitleaks-armada/internal/infra/eventbus/grpc"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
	"github.com/ahrav/gitleaks-armada/pkg/common/timeutil"
	pb "github.com/ahrav/gitleaks-armada/proto"
)

// MockGatewayScannerStream implements the "GatewayScannerStream" interface.
type MockGatewayScannerStream struct {
	SendFunc func(msg *grpcbus.GatewayToScannerMessage) error
	RecvFunc func() (*grpcbus.ScannerToGatewayMessage, error)

	grpc.ServerStream
}

func (m *MockGatewayScannerStream) Send(msg *grpcbus.GatewayToScannerMessage) error {
	if m.SendFunc != nil {
		return m.SendFunc(msg)
	}
	return nil
}

func (m *MockGatewayScannerStream) Recv() (*grpcbus.ScannerToGatewayMessage, error) {
	if m.RecvFunc != nil {
		return m.RecvFunc()
	}
	return nil, nil
}

func TestNewScannerConnection(t *testing.T) {
	mockStream := new(MockGatewayScannerStream)
	mockTime := timeutil.Mock{CurrentTime: time.Date(2025, time.January, 2, 15, 4, 5, 0, time.UTC)}
	log := logger.Noop()
	tracer := noop.NewTracerProvider().Tracer("test")

	conn := gateway.NewScannerConnection(
		"scanner-1", mockStream, []string{"cap1", "cap2"}, "v2.1", &mockTime, log, tracer,
	)

	assert.Equal(t, "scanner-1", conn.ScannerID)
	assert.Equal(t, mockStream, conn.Stream)
	assert.Equal(t, mockTime.CurrentTime, conn.Connected)
	assert.Equal(t, mockTime.CurrentTime, conn.LastActivity)
	assert.Equal(t, []string{"cap1", "cap2"}, conn.Capabilities)
	assert.Equal(t, "v2.1", conn.Version)
}

func TestScannerConnection_SendMessage(t *testing.T) {
	sentMessages := []*grpcbus.GatewayToScannerMessage{}
	mockStream := &MockGatewayScannerStream{
		SendFunc: func(msg *grpcbus.GatewayToScannerMessage) error {
			sentMessages = append(sentMessages, msg)
			return nil
		},
	}
	tracer := noop.NewTracerProvider().Tracer("test")
	conn := gateway.NewScannerConnection(
		"scanner-1", mockStream, nil, "", timeutil.Default(), logger.Noop(), tracer,
	)

	testMsg := &pb.GatewayToScannerMessage{MessageId: "msg-123"}
	err := conn.SendMessage(context.Background(), testMsg)
	assert.NoError(t, err)
	assert.Len(t, sentMessages, 1)
	assert.Equal(t, "msg-123", sentMessages[0].MessageId, "Should have sent the correct message")
}

func TestScannerConnection_SendMessage_Error(t *testing.T) {
	// If stream.Send fails, we ensure the error is returned up the chain.
	mockStream := &MockGatewayScannerStream{
		SendFunc: func(msg *grpcbus.GatewayToScannerMessage) error { return errors.New("network error") },
	}
	tracer := noop.NewTracerProvider().Tracer("test")
	conn := gateway.NewScannerConnection(
		"scanner-1", mockStream, nil, "", timeutil.Default(), logger.Noop(), tracer,
	)

	testMsg := &pb.GatewayToScannerMessage{MessageId: "msg-FAIL"}
	err := conn.SendMessage(context.Background(), testMsg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "network error")
}

func TestScannerConnection_ReceiveMessage(t *testing.T) {
	mockStream := &MockGatewayScannerStream{
		RecvFunc: func() (*grpcbus.ScannerToGatewayMessage, error) {
			return &grpcbus.ScannerToGatewayMessage{MessageId: "scanner-msg-1"}, nil
		},
	}
	tracer := noop.NewTracerProvider().Tracer("test")
	conn := gateway.NewScannerConnection(
		"scanner-1", mockStream, nil, "", timeutil.Default(), logger.Noop(), tracer,
	)

	msg, err := conn.ReceiveMessage(context.Background())
	assert.NoError(t, err)
	assert.NotNil(t, msg)
	assert.Equal(t, "scanner-msg-1", msg.MessageId)
}

func TestScannerConnection_ReceiveMessage_Error(t *testing.T) {
	mockStream := &MockGatewayScannerStream{
		RecvFunc: func() (*grpcbus.ScannerToGatewayMessage, error) { return nil, errors.New("recv failed") },
	}
	tracer := noop.NewTracerProvider().Tracer("test")
	conn := gateway.NewScannerConnection(
		"scanner-1", mockStream, nil, "", timeutil.Default(), logger.Noop(), tracer,
	)

	msg, err := conn.ReceiveMessage(context.Background())
	assert.Error(t, err)
	assert.Nil(t, msg)
	assert.Contains(t, err.Error(), "recv failed")
}

func TestScannerConnection_UpdateActivity(t *testing.T) {
	tracer := noop.NewTracerProvider().Tracer("test")
	conn := gateway.NewScannerConnection(
		"scanner-1", new(MockGatewayScannerStream), nil, "", timeutil.Default(), logger.Noop(), tracer,
	)
	oldTime := conn.LastActivity

	newTime := time.Now().Add(5 * time.Minute)
	conn.UpdateActivity(newTime)
	assert.True(t, conn.LastActivity.After(oldTime), "LastActivity should have been updated")
	assert.Equal(t, newTime, conn.LastActivity, "Should match the new time")
}

func TestScannerConnection_HasCapability(t *testing.T) {
	caps := []string{"cap1", "cap2", "advanced-mode"}
	tracer := noop.NewTracerProvider().Tracer("test")
	conn := gateway.NewScannerConnection(
		"scanner-X", new(MockGatewayScannerStream), caps, "v1", timeutil.Default(), logger.Noop(), tracer,
	)

	assert.True(t, conn.HasCapability("cap1"))
	assert.True(t, conn.HasCapability("advanced-mode"))
	assert.False(t, conn.HasCapability("super-secret"))
}

func TestScannerConnection_CreateAcknowledgment(t *testing.T) {
	tracer := noop.NewTracerProvider().Tracer("test")
	conn := gateway.NewScannerConnection(
		"scanner-ACK", new(MockGatewayScannerStream), nil, "v1", timeutil.Default(), logger.Noop(), tracer,
	)

	ack := conn.CreateAcknowledgment("orig-msg-123", false, "some error message")

	assert.Equal(t, "orig-msg-123", ack.OriginalMessageId)
	assert.False(t, ack.Success)
	assert.Equal(t, "some error message", ack.ErrorMessage)
	assert.Equal(t, "scanner-ACK", ack.ScannerId)
}
