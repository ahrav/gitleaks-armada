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

type mockStalenessHandler struct {
	markStaleFunc func(context.Context, scanning.TaskStaleEvent) error
	getTaskFunc   func(context.Context, uuid.UUID) (*scanning.Task, error)
}

func (m *mockStalenessHandler) MarkTaskStale(ctx context.Context, evt scanning.TaskStaleEvent) error {
	if m.markStaleFunc != nil {
		return m.markStaleFunc(ctx, evt)
	}
	return nil
}

func (m *mockStalenessHandler) GetTask(ctx context.Context, taskID uuid.UUID) (*scanning.Task, error) {
	if m.getTaskFunc != nil {
		return m.getTaskFunc(ctx, taskID)
	}
	return nil, nil
}

func TestHeartbeatMonitor_HandleHeartbeat(t *testing.T) {
	taskID := uuid.New()
	mockTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	mockProvider := &mockTimeProvider{now: mockTime}

	monitor := NewHeartbeatMonitor(
		new(mockStalenessHandler),
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
	tests := []struct {
		name         string
		taskID       uuid.UUID
		taskStatus   scanning.TaskStatus
		expectStale  bool
		heartbeatAge time.Duration
		staleTimeout time.Duration
	}{
		{
			name:         "in_progress_task_becomes_stale",
			taskID:       uuid.New(),
			taskStatus:   scanning.TaskStatusInProgress,
			expectStale:  true,
			heartbeatAge: 20 * time.Second,
			staleTimeout: 15 * time.Second,
		},
		{
			name:         "completed_task_not_marked_stale",
			taskID:       uuid.New(),
			taskStatus:   scanning.TaskStatusCompleted,
			expectStale:  false,
			heartbeatAge: 20 * time.Second,
			staleTimeout: 15 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			baseTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
			mockTime := &mockTimeProvider{now: baseTime}

			var capturedEvent scanning.TaskStaleEvent
			var markStaleCalled bool

			staleTaskHandler := &mockStalenessHandler{
				markStaleFunc: func(ctx context.Context, evt scanning.TaskStaleEvent) error {
					capturedEvent = evt
					markStaleCalled = true
					return nil
				},
				getTaskFunc: func(ctx context.Context, taskID uuid.UUID) (*scanning.Task, error) {
					task := scanning.NewScanTask(taskID, taskID, "test://resource")
					if tt.taskStatus == scanning.TaskStatusCompleted {
						task.Complete()
					}
					return task, nil
				},
			}

			monitor := NewHeartbeatMonitor(
				staleTaskHandler,
				noop.NewTracerProvider().Tracer("test"),
				logger.Noop(),
			)
			monitor.timeProvider = mockTime

			monitor.lastHeartbeatByTask[tt.taskID] = baseTime.Add(-tt.heartbeatAge)
			mockTime.now = baseTime.Add(tt.heartbeatAge)

			monitor.checkForStaleTasks(context.Background(), tt.staleTimeout)

			if tt.expectStale {
				if !markStaleCalled {
					t.Error("Expected task to be marked stale, but it wasn't")
				}
				if capturedEvent.TaskID != tt.taskID {
					t.Errorf("Expected task %v to be marked stale, but got %v", tt.taskID, capturedEvent.TaskID)
				}
				// Verify the task was removed from tracking.
				if _, exists := monitor.lastHeartbeatByTask[tt.taskID]; exists {
					t.Error("Expected stale task to be removed from tracking but it wasn't")
				}
			} else {
				if markStaleCalled {
					t.Error("Task was marked stale when it shouldn't have been")
				}
				// Even for non-stale tasks, we should clean up completed ones.
				if _, exists := monitor.lastHeartbeatByTask[tt.taskID]; exists {
					t.Error("Expected completed task to be removed from tracking but it wasn't")
				}
			}
		})
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
		new(mockStalenessHandler),
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
