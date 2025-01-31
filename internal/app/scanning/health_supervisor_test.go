package scanning

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

// mockHeartbeatService implements scanning.TaskHealthService for testing.
type mockHeartbeatService struct {
	updateHeartbeatsFunc func(context.Context, map[uuid.UUID]time.Time) (int64, error)
	findStaleTasksFunc   func(context.Context, string, time.Time) ([]scanning.StaleTaskInfo, error)
}

func (m *mockHeartbeatService) UpdateHeartbeats(ctx context.Context, beats map[uuid.UUID]time.Time) (int64, error) {
	if m.updateHeartbeatsFunc != nil {
		return m.updateHeartbeatsFunc(ctx, beats)
	}
	return int64(len(beats)), nil
}

func (m *mockHeartbeatService) FindStaleTasks(ctx context.Context, controllerID string, cutoff time.Time) ([]scanning.StaleTaskInfo, error) {
	if m.findStaleTasksFunc != nil {
		return m.findStaleTasksFunc(ctx, controllerID, cutoff)
	}
	return nil, nil
}

// mockStateHandler implements scanning.TaskStateHandler for testing.
type mockStateHandler struct {
	handleTaskStaleFunc func(context.Context, scanning.TaskStaleEvent) error
}

func (m *mockStateHandler) HandleTaskStale(ctx context.Context, evt scanning.TaskStaleEvent) error {
	if m.handleTaskStaleFunc != nil {
		return m.handleTaskStaleFunc(ctx, evt)
	}
	return nil
}

// mockEventPublisher implements events.DomainEventPublisher for testing.
type mockEventPublisher struct {
	publishedEvents []events.DomainEvent
	publishOptions  [][]events.PublishOption
}

func (m *mockEventPublisher) PublishDomainEvent(ctx context.Context, evt events.DomainEvent, opts ...events.PublishOption) error {
	m.publishedEvents = append(m.publishedEvents, evt)
	m.publishOptions = append(m.publishOptions, opts)
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

	stateHandler := new(mockStateHandler)
	eventPublisher := new(mockEventPublisher)
	heartbeatMonitor := NewTaskHealthSupervisor(
		"test-controller",
		heartbeatSvc,
		stateHandler,
		eventPublisher,
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
		setupStaleTasks func() []scanning.StaleTaskInfo
	}{
		{
			name:        "stale_task_marked",
			taskID:      uuid.New(),
			jobID:       uuid.New(),
			expectStale: true,
			setupStaleTasks: func() []scanning.StaleTaskInfo {
				taskID := uuid.New()
				jobID := uuid.New()
				return []scanning.StaleTaskInfo{
					scanning.NewStaleTaskInfo(taskID, jobID, "test-controller"),
				}
			},
		},
		{
			name:        "no_stale_tasks",
			expectStale: false,
			setupStaleTasks: func() []scanning.StaleTaskInfo {
				return nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			baseTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
			mockTime := &mockTimeProvider{now: baseTime}

			eventPublisher := new(mockEventPublisher)
			stateHandler := new(mockStateHandler)
			heartbeatSvc := &mockHeartbeatService{
				findStaleTasksFunc: func(ctx context.Context, controllerID string, cutoff time.Time) ([]scanning.StaleTaskInfo, error) {
					return tt.setupStaleTasks(), nil
				},
			}

			heartbeatMonitor := NewTaskHealthSupervisor(
				"test-controller",
				heartbeatSvc,
				stateHandler,
				eventPublisher,
				noop.NewTracerProvider().Tracer("test"),
				logger.Noop(),
			)
			heartbeatMonitor.timeProvider = mockTime
			heartbeatMonitor.checkForStaleTasks(context.Background())

			if tt.expectStale {
				require.Len(t, eventPublisher.publishedEvents, 1, "Expected one event to be published")
				evt, ok := eventPublisher.publishedEvents[0].(scanning.TaskStaleEvent)
				require.True(t, ok, "Expected event to be TaskStaleEvent")
				assert.Equal(t, scanning.StallReasonNoProgress, evt.Reason)

				// Verify publish options.
				require.Len(t, eventPublisher.publishOptions, 1, "Expected one set of publish options")
				assert.NotEmpty(t, eventPublisher.publishOptions[0], "Expected publish options to be set")
			} else {
				assert.Empty(t, eventPublisher.publishedEvents, "Expected no events to be published")
			}
		})
	}
}

func TestHeartbeatMonitor_Start(t *testing.T) {
	taskID := uuid.New()
	jobID := uuid.New()
	baseTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	advancedTime := baseTime.Add(20 * time.Second)
	mockProvider := &mockTimeProvider{now: baseTime}

	eventPublisher := new(mockEventPublisher)
	stateHandler := new(mockStateHandler)
	heartbeatSvc := &mockHeartbeatService{
		findStaleTasksFunc: func(ctx context.Context, controllerID string, cutoff time.Time) ([]scanning.StaleTaskInfo, error) {
			return []scanning.StaleTaskInfo{
				scanning.NewStaleTaskInfo(taskID, jobID, controllerID),
			}, nil
		},
	}

	heartbeatMonitor := NewTaskHealthSupervisor(
		"test-controller",
		heartbeatSvc,
		stateHandler,
		eventPublisher,
		noop.NewTracerProvider().Tracer("test"),
		logger.Noop(),
	)
	heartbeatMonitor.timeProvider = mockProvider
	heartbeatMonitor.flushInterval = 30 * time.Millisecond
	heartbeatMonitor.stalenessCheckIntv = 50 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	heartbeatMonitor.Start(ctx)

	// Allow one flush/stale-check cycle at the original time.
	time.Sleep(100 * time.Millisecond)

	// Advance time so the next stale check sees tasks as stale.
	mockProvider.now = advancedTime

	// Wait enough time for the next stale check to run.
	time.Sleep(100 * time.Millisecond)

	assert.NotEmpty(t, eventPublisher.publishedEvents, "Expected events to be published for stale tasks")
	assert.NotEmpty(t, eventPublisher.publishOptions, "Expected publish options to be set")

	heartbeatMonitor.Stop()
}

func TestHeartbeatMonitor_ConcurrentAccess(t *testing.T) {
	baseTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	mockProvider := &mockTimeProvider{now: baseTime}

	heartbeatMonitor := NewTaskHealthSupervisor(
		"test-controller",
		new(mockHeartbeatService),
		new(mockStateHandler),
		new(mockEventPublisher),
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
