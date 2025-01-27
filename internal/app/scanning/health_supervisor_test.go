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

// mockHeartbeatService implements HeartbeatService for testing
type mockHeartbeatService struct {
	updateHeartbeatsFunc func(context.Context, map[uuid.UUID]time.Time) (int64, error)
	findStaleTasksFunc   func(context.Context, time.Time) ([]*scanning.Task, error)
}

func (m *mockHeartbeatService) UpdateHeartbeats(ctx context.Context, beats map[uuid.UUID]time.Time) (int64, error) {
	if m.updateHeartbeatsFunc != nil {
		return m.updateHeartbeatsFunc(ctx, beats)
	}
	return int64(len(beats)), nil
}

func (m *mockHeartbeatService) FindStaleTasks(ctx context.Context, cutoff time.Time) ([]*scanning.Task, error) {
	if m.findStaleTasksFunc != nil {
		return m.findStaleTasksFunc(ctx, cutoff)
	}
	return nil, nil
}

// mockTaskStateHandler implements TaskStateHandler for testing
type mockTaskStateHandler struct {
	handleTaskStaleFunc func(context.Context, scanning.TaskStaleEvent) error
}

func (m *mockTaskStateHandler) HandleTaskStale(ctx context.Context, evt scanning.TaskStaleEvent) error {
	if m.handleTaskStaleFunc != nil {
		return m.handleTaskStaleFunc(ctx, evt)
	}
	return nil
}

func TestHeartbeatMonitor_HandleHeartbeat(t *testing.T) {
	taskID := uuid.New()
	mockTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	mockProvider := &mockTimeProvider{now: mockTime}

	capturedBeats := make(map[uuid.UUID]time.Time)
	heartbeatSvc := &mockHeartbeatService{
		updateHeartbeatsFunc: func(ctx context.Context, beats map[uuid.UUID]time.Time) (int64, error) {
			for k, v := range beats {
				capturedBeats[k] = v
			}
			return int64(len(beats)), nil
		},
	}

	heartbeatMonitor := NewTaskHealthSupervisor(
		heartbeatSvc,
		&mockTaskStateHandler{},
		noop.NewTracerProvider().Tracer("test"),
		logger.Noop(),
	)
	heartbeatMonitor.timeProvider = mockProvider

	// Set a shorter flush interval to allow the test to complete faster.
	heartbeatMonitor.flushInterval = 50 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	heartbeatMonitor.Start(ctx)

	evt := scanning.NewTaskHeartbeatEvent(taskID)
	heartbeatMonitor.HandleHeartbeat(context.Background(), evt)

	time.Sleep(100 * time.Millisecond)

	if assert.NotNil(t, capturedBeats, "Expected captured beats to not be nil") {
		assert.Len(t, capturedBeats, 1, "Expected exactly one heartbeat")
		assert.Equal(t, mockTime, capturedBeats[taskID], "Expected heartbeat time to match mock time")
	}

	heartbeatMonitor.Stop()
}

func TestHeartbeatMonitor_CheckForStaleTasks(t *testing.T) {
	tests := []struct {
		name            string
		taskID          uuid.UUID
		jobID           uuid.UUID
		expectStale     bool
		setupStaleTasks func() []*scanning.Task
	}{
		{
			name:        "stale_task_marked",
			taskID:      uuid.New(),
			jobID:       uuid.New(),
			expectStale: true,
			setupStaleTasks: func() []*scanning.Task {
				task := scanning.NewScanTask(uuid.New(), uuid.New(), "test://resource")
				return []*scanning.Task{task}
			},
		},
		{
			name:        "no_stale_tasks",
			expectStale: false,
			setupStaleTasks: func() []*scanning.Task {
				return nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			baseTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
			mockTime := &mockTimeProvider{now: baseTime}

			var staleEventReceived bool
			heartbeatSvc := &mockHeartbeatService{
				findStaleTasksFunc: func(ctx context.Context, cutoff time.Time) ([]*scanning.Task, error) {
					return tt.setupStaleTasks(), nil
				},
			}

			stateHandler := &mockTaskStateHandler{
				handleTaskStaleFunc: func(ctx context.Context, evt scanning.TaskStaleEvent) error {
					staleEventReceived = true
					return nil
				},
			}

			heartbeatMonitor := NewTaskHealthSupervisor(
				heartbeatSvc,
				stateHandler,
				noop.NewTracerProvider().Tracer("test"),
				logger.Noop(),
			)
			heartbeatMonitor.timeProvider = mockTime
			heartbeatMonitor.checkForStaleTasks(context.Background())

			if tt.expectStale {
				assert.True(t, staleEventReceived, "Expected HandleTaskStale to be called")
			} else {
				assert.False(t, staleEventReceived, "Expected HandleTaskStale not to be called")
			}
		})
	}
}

func TestHeartbeatMonitor_Start(t *testing.T) {
	taskID := uuid.New()
	baseTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	advancedTime := baseTime.Add(20 * time.Second)
	mockProvider := &mockTimeProvider{now: baseTime}

	var staleEventReceived bool
	heartbeatSvc := &mockHeartbeatService{
		findStaleTasksFunc: func(ctx context.Context, cutoff time.Time) ([]*scanning.Task, error) {
			// As soon as the cutoff passes, we treat anything older than that as stale
			return []*scanning.Task{
				scanning.NewScanTask(uuid.New(), taskID, "test://resource"),
			}, nil
		},
	}

	stateHandler := &mockTaskStateHandler{
		handleTaskStaleFunc: func(ctx context.Context, evt scanning.TaskStaleEvent) error {
			staleEventReceived = true
			return nil
		},
	}

	heartbeatMonitor := NewTaskHealthSupervisor(
		heartbeatSvc,
		stateHandler,
		noop.NewTracerProvider().Tracer("test"),
		logger.Noop(),
	)
	heartbeatMonitor.flushInterval = 30 * time.Millisecond
	heartbeatMonitor.stalenessCheckIntv = 50 * time.Millisecond
	heartbeatMonitor.timeProvider = mockProvider

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	heartbeatMonitor.Start(ctx)

	// Allow one flush/stale-check cycle at the original time.
	time.Sleep(100 * time.Millisecond)

	// Advance time so the next stale check sees tasks as stale.
	mockProvider.now = advancedTime

	// Wait enough time for the next stale check to run.
	time.Sleep(100 * time.Millisecond)

	assert.True(t, staleEventReceived, "Expected HandleTaskStale to be called for stale tasks")

	heartbeatMonitor.Stop()
}

func TestHeartbeatMonitor_ConcurrentAccess(t *testing.T) {
	baseTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	mockProvider := &mockTimeProvider{now: baseTime}

	heartbeatMonitor := NewTaskHealthSupervisor(
		&mockHeartbeatService{},
		&mockTaskStateHandler{},
		noop.NewTracerProvider().Tracer("test"),
		logger.Noop(),
	)
	heartbeatMonitor.timeProvider = mockProvider

	taskID := uuid.New()
	done := make(chan bool)

	go func() {
		for i := 0; i < 100; i++ {
			heartbeatMonitor.HandleHeartbeat(context.Background(), scanning.TaskHeartbeatEvent{TaskID: taskID})
			mockProvider.SetNow(time.Millisecond)
		}
		done <- true
	}()

	go func() {
		for range 100 {
			heartbeatMonitor.checkForStaleTasks(context.Background())
			mockProvider.SetNow(time.Millisecond)
		}
		done <- true
	}()

	<-done
	<-done
}
