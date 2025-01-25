package scanning

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

type mockTaskStaller struct {
	markStaleFunc func(context.Context, scanning.TaskStaleEvent) error
}

func (m *mockTaskStaller) MarkTaskStale(ctx context.Context, evt scanning.TaskStaleEvent) error {
	if m.markStaleFunc != nil {
		return m.markStaleFunc(ctx, evt)
	}
	return nil
}

func TestHeartbeatMonitor_HandleHeartbeat(t *testing.T) {
	taskID := uuid.New()
	mockTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	mockProvider := &mockTimeProvider{now: mockTime}

	monitor := NewHeartbeatMonitor(
		&mockTaskStaller{},
		noop.NewTracerProvider().Tracer("test"),
		logger.Noop(),
	)
	monitor.timeProvider = mockProvider

	evt := scanning.TaskHeartbeatEvent{
		TaskID: taskID,
	}

	monitor.HandleHeartbeat(context.Background(), evt)

	if lastBeat, exists := monitor.lastHeartbeatByTask[taskID]; !exists {
		t.Error("Expected heartbeat to be recorded but it wasn't")
	} else {
		assert.Equal(t, mockTime, lastBeat)
	}
}

func TestHeartbeatMonitor_CheckForStaleTasks(t *testing.T) {
	taskID := uuid.New()
	baseTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	mockTime := &mockTimeProvider{now: baseTime}

	var capturedEvent scanning.TaskStaleEvent
	staller := &mockTaskStaller{
		markStaleFunc: func(ctx context.Context, evt scanning.TaskStaleEvent) error {
			capturedEvent = evt
			return nil
		},
	}

	monitor := NewHeartbeatMonitor(
		staller,
		noop.NewTracerProvider().Tracer("test"),
		logger.Noop(),
	)
	monitor.timeProvider = mockTime

	// Add a task with an old heartbeat.
	monitor.lastHeartbeatByTask[taskID] = baseTime.Add(-20 * time.Second)

	// Advance mock time by 20 seconds.
	mockTime.now = baseTime.Add(20 * time.Second)

	// Check for stale tasks with a 15-second threshold.
	monitor.checkForStaleTasks(context.Background(), 15*time.Second)

	// Verify the task was marked as stale.
	if capturedEvent.TaskID != taskID {
		t.Errorf("Expected task %v to be marked stale, but it wasn't", taskID)
	}

	// Verify the task was removed from tracking.
	if _, exists := monitor.lastHeartbeatByTask[taskID]; exists {
		t.Error("Expected stale task to be removed from tracking but it wasn't")
	}
}

// TODO: Fix this to not use real tickers.
// func TestHeartbeatMonitor_Start(t *testing.T) {
// 	taskID := uuid.New()
// 	baseTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
// 	advancedTime := baseTime.Add(20 * time.Second)
// 	mockProvider := &mockTimeProvider{now: baseTime}

// 	var capturedEvent scanning.TaskStaleEvent
// 	staller := &mockTaskStaller{
// 		markStaleFunc: func(ctx context.Context, evt scanning.TaskStaleEvent) error {
// 			capturedEvent = evt
// 			return nil
// 		},
// 	}

// 	monitor := NewHeartbeatMonitor(
// 		staller,
// 		noop.NewTracerProvider().Tracer("test"),
// 		logger.Noop(),
// 	)
// 	monitor.timeProvider = mockProvider

// 	ctx, cancel := context.WithCancel(context.Background())
// 	defer cancel()

// 	monitor.Start(ctx)

// 	// Add a task that will become stale
// 	monitor.lastHeartbeatByTask[taskID] = baseTime.Add(-20 * time.Second)

// 	// Advance mock time by 20 seconds
// 	mockProvider.now = advancedTime

// 	// Wait for staleness check to run
// 	time.Sleep(stalenessLoopInterval + time.Second)

// 	assert.Equal(t, taskID, capturedEvent.TaskID)
// 	assert.Equal(t, scanning.StallReasonNoProgress, capturedEvent.Reason)
// 	assert.Equal(t, advancedTime, capturedEvent.OccurredAt)
// }

func TestHeartbeatMonitor_ConcurrentAccess(t *testing.T) {
	baseTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	mockProvider := &mockTimeProvider{now: baseTime}

	monitor := NewHeartbeatMonitor(
		&mockTaskStaller{},
		noop.NewTracerProvider().Tracer("test"),
		logger.Noop(),
	)
	monitor.timeProvider = mockProvider

	taskID := uuid.New()
	done := make(chan bool)

	go func() {
		for i := 0; i < 100; i++ {
			monitor.HandleHeartbeat(context.Background(), scanning.TaskHeartbeatEvent{TaskID: taskID})
			mockProvider.SetNow(time.Millisecond)
		}
		done <- true
	}()

	go func() {
		for i := 0; i < 100; i++ {
			monitor.checkForStaleTasks(context.Background(), defaultThreshold)
			mockProvider.SetNow(time.Millisecond)
		}
		done <- true
	}()

	<-done
	<-done
}
