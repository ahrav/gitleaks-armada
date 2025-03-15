package handlers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

// Mock implementations for testing.
type mockScannerService struct{ mock.Mock }

func (m *mockScannerService) CreateScanner(ctx context.Context, cmd scanning.CreateScannerCommand) (*scanning.Scanner, error) {
	args := m.Called(ctx, cmd)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*scanning.Scanner), args.Error(1)
}

func (m *mockScannerService) CreateScannerGroup(ctx context.Context, cmd scanning.CreateScannerGroupCommand) (*scanning.ScannerGroup, error) {
	args := m.Called(ctx, cmd)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*scanning.ScannerGroup), args.Error(1)
}

// setupScannerHandlerTestSuite creates a ScannerHandler with mock dependencies for testing.
func setupScannerHandlerTestSuite() (*ScannerHandler, *mockScannerService) {
	mockService := new(mockScannerService)
	log := logger.Noop()
	tracer := noop.NewTracerProvider().Tracer("test-tracer")

	handler := NewScannerHandler("test-controller", mockService, log, tracer)

	return handler, mockService
}

// TestScannerHandlerSupportedEvents verifies that the ScannerHandler reports all expected event types.
// This prevents event type handling regressions when new events are added but not properly registered.
func TestScannerHandlerSupportedEvents(t *testing.T) {
	handler, _ := setupScannerHandlerTestSuite()

	expectedEventTypes := []events.EventType{
		scanning.EventTypeScannerRegistered,
		scanning.EventTypeScannerHeartbeat,
		scanning.EventTypeScannerStatusChanged,
		scanning.EventTypeScannerDeregistered,
	}

	supportedEvents := handler.SupportedEvents()
	assert.Len(t, supportedEvents, len(expectedEventTypes),
		"Handler should support exactly %d event types", len(expectedEventTypes))

	for _, expected := range expectedEventTypes {
		assert.Contains(t, supportedEvents, expected,
			"Handler should support the %s event type", expected)
	}
}
