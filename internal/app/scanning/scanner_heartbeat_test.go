package scanning

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
	"github.com/ahrav/gitleaks-armada/pkg/common/timeutil"
)

// TestScannerHeartbeatAgent_Start verifies the heartbeat agent
// sends heartbeats at the expected intervals and can be gracefully
// stopped when the context is cancelled.
func TestScannerHeartbeatAgent_Start(t *testing.T) {
	testInterval := 10 * time.Millisecond

	mockTime := timeutil.NewMock(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC))
	eventPublisher := new(mockEventPublisher)
	scannerID := "test-scanner"

	heartbeatAgent := NewScannerHeartbeatAgent(
		scannerID,
		eventPublisher,
		logger.Noop(),
		noop.NewTracerProvider().Tracer("test"),
	)
	heartbeatAgent.interval = testInterval
	heartbeatAgent.timeProvider = mockTime

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Create a channel to signal when the manager has stopped.
	done := make(chan struct{})
	go func() {
		err := heartbeatAgent.Start(ctx)
		assert.Equal(t, context.DeadlineExceeded, err)
		close(done)
	}()

	// Wait for the manager to stop.
	select {
	case <-done:
		// Success - manager stopped when context was cancelled.
	case <-time.After(200 * time.Millisecond):
		t.Fatal("Timed out waiting for heartbeat agent to stop")
	}

	eventPublisher.mu.RLock()
	defer eventPublisher.mu.RUnlock()
	assert.NotEmpty(t, eventPublisher.publishedEvents, "Expected at least one heartbeat to be published")

	if assert.GreaterOrEqual(t, len(eventPublisher.publishedEvents), 1) {
		evt, ok := eventPublisher.publishedEvents[0].(scanning.ScannerHeartbeatEvent)
		require.True(t, ok, "Expected first event to be a ScannerHeartbeatEvent")
		assert.Equal(t, scannerID, evt.ScannerName(), "Expected scanner ID to match")
		assert.Equal(t, scanning.ScannerStatusOnline, evt.Status(), "Expected scanner status to be online")
		assert.NotEmpty(t, evt.Metrics(), "Expected metrics to be populated")
	}
}

// TestScannerHeartbeatAgent_UpdateMetrics verifies custom metrics
// are included in heartbeat events when they are set.
func TestScannerHeartbeatAgent_UpdateMetrics(t *testing.T) {
	scannerID := "test-scanner"
	mockTime := timeutil.NewMock(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC))
	eventPublisher := new(mockEventPublisher)

	heartbeatAgent := NewScannerHeartbeatAgent(
		scannerID,
		eventPublisher,
		logger.Noop(),
		noop.NewTracerProvider().Tracer("test"),
	)
	heartbeatAgent.timeProvider = mockTime

	metricKey := "test_metric"
	metricValue := 42.0
	heartbeatAgent.UpdateMetrics(metricKey, metricValue)

	err := heartbeatAgent.sendHeartbeat(context.Background())
	assert.NoError(t, err, "Expected no error when sending heartbeat")

	// Verify the heartbeat event contains our custom metric.
	eventPublisher.mu.RLock()
	defer eventPublisher.mu.RUnlock()

	if assert.Len(t, eventPublisher.publishedEvents, 1, "Expected exactly one event to be published") {
		evt, ok := eventPublisher.publishedEvents[0].(scanning.ScannerHeartbeatEvent)
		require.True(t, ok, "Expected event to be a ScannerHeartbeatEvent")

		metrics := evt.Metrics()
		assert.Contains(t, metrics, metricKey, "Expected metrics to contain custom key")
		assert.Equal(t, metricValue, metrics[metricKey], "Expected custom metric value to match")
	}
}

// TestScannerHeartbeatAgent_SendHeartbeatError tests error handling
// when publishing a heartbeat event fails.
func TestScannerHeartbeatAgent_SendHeartbeatError(t *testing.T) {
	scannerID := "test-scanner"
	mockTime := timeutil.NewMock(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC))

	expectedErr := assert.AnError
	eventPublisher := new(mockEventPublisher)
	eventPublisher.publishFunc = func(ctx context.Context, evt events.DomainEvent, opts ...events.PublishOption) error {
		return expectedErr
	}

	heartbeatAgent := NewScannerHeartbeatAgent(
		scannerID,
		eventPublisher,
		logger.Noop(),
		noop.NewTracerProvider().Tracer("test"),
	)
	heartbeatAgent.timeProvider = mockTime

	// Attempt to send a heartbeat, which should fail.
	err := heartbeatAgent.sendHeartbeat(context.Background())
	assert.ErrorIs(t, err, expectedErr, "Expected error from publisher to be returned")
}

// TestScannerHeartbeatAgent_SendHeartbeatContent verifies the content
// of the heartbeat event that is published.
func TestScannerHeartbeatAgent_SendHeartbeatContent(t *testing.T) {
	scannerID := "test-scanner"
	mockTime := timeutil.NewMock(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC))
	eventPublisher := new(mockEventPublisher)

	heartbeatAgent := NewScannerHeartbeatAgent(
		scannerID,
		eventPublisher,
		logger.Noop(),
		noop.NewTracerProvider().Tracer("test"),
	)
	heartbeatAgent.timeProvider = mockTime

	heartbeatAgent.UpdateMetrics("custom_metric_1", 100.0)
	heartbeatAgent.UpdateMetrics("custom_metric_2", 200.0)

	err := heartbeatAgent.sendHeartbeat(context.Background())
	assert.NoError(t, err, "Expected no error when sending heartbeat")

	eventPublisher.mu.RLock()
	defer eventPublisher.mu.RUnlock()

	if assert.Len(t, eventPublisher.publishedEvents, 1, "Expected exactly one event to be published") {
		evt, ok := eventPublisher.publishedEvents[0].(scanning.ScannerHeartbeatEvent)
		require.True(t, ok, "Expected event to be a ScannerHeartbeatEvent")

		// Verify scanner ID and status.
		assert.Equal(t, scannerID, evt.ScannerName(), "Expected scanner ID to match")
		assert.Equal(t, scanning.ScannerStatusOnline, evt.Status(), "Expected scanner status to be online")

		// Verify metrics.
		metrics := evt.Metrics()
		assert.Contains(t, metrics, "memory_usage", "Expected metrics to contain memory_usage")
		assert.Contains(t, metrics, "cpu_usage", "Expected metrics to contain cpu_usage")
		assert.Contains(t, metrics, "active_tasks", "Expected metrics to contain active_tasks")
		assert.Contains(t, metrics, "queue_depth", "Expected metrics to contain queue_depth")
		assert.Contains(t, metrics, "uptime_seconds", "Expected metrics to contain uptime_seconds")

		assert.Equal(t, 100.0, metrics["custom_metric_1"], "Expected custom_metric_1 value to match")
		assert.Equal(t, 200.0, metrics["custom_metric_2"], "Expected custom_metric_2 value to match")

		if assert.Len(t, eventPublisher.publishOptions, 1, "Expected exactly one set of publish options") {
			options := eventPublisher.publishOptions[0]
			assert.NotEmpty(t, options, "Expected publish options to be set")
		}
	}
}
