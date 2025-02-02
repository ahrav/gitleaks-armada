package scanning

import (
	"context"
	"sync"
	"sync/atomic"
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
	mu              sync.RWMutex
	publishedEvents []events.DomainEvent
	publishOptions  [][]events.PublishOption
	publishFunc     func(context.Context, events.DomainEvent, ...events.PublishOption) error
}

func (m *mockEventPublisher) PublishDomainEvent(ctx context.Context, evt events.DomainEvent, opts ...events.PublishOption) error {
	m.mu.Lock()
	m.publishedEvents = append(m.publishedEvents, evt)
	m.publishOptions = append(m.publishOptions, opts)
	m.mu.Unlock()

	if m.publishFunc != nil {
		return m.publishFunc(ctx, evt, opts...)
	}
	return nil
}

func TestHeartbeatMonitor_HandleHeartbeat(t *testing.T) {
	taskID := uuid.New()
	mockTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	mockProvider := &mockTimeProvider{now: mockTime}

	// Channel to signal when heartbeats are processed.
	heartbeatProcessed := make(chan struct{}, 1)

	var mu sync.RWMutex
	capturedBeats := make(map[uuid.UUID]time.Time)
	heartbeatSvc := &mockHeartbeatService{
		updateHeartbeatsFunc: func(ctx context.Context, beats map[uuid.UUID]time.Time) (int64, error) {
			mu.Lock()
			defer mu.Unlock()
			for k, v := range beats {
				capturedBeats[k] = v
			}
			heartbeatProcessed <- struct{}{} // Signal heartbeat was processed
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
	heartbeatMonitor.flushInterval = time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start the monitor to enable periodic flushing.
	heartbeatMonitor.Start(ctx)
	defer heartbeatMonitor.Stop()

	evt := scanning.NewTaskHeartbeatEvent(taskID)
	heartbeatMonitor.HandleHeartbeat(context.Background(), evt)

	// Wait for heartbeat to be processed.
	select {
	case <-heartbeatProcessed:
		// Success - heartbeat was processed.
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Timed out waiting for heartbeat to be processed")
	}

	mu.RLock()
	defer mu.RUnlock()
	if assert.NotNil(t, capturedBeats, "Expected captured beats to not be nil") {
		assert.Len(t, capturedBeats, 1, "Expected exactly one heartbeat")
		assert.Equal(t, mockTime, capturedBeats[taskID], "Expected heartbeat time to match mock time")
	}
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
	mockProvider := &mockTimeProvider{now: baseTime}

	// Buffered channel to signal event processing.
	eventProcessed := make(chan struct{}, 1)

	eventPublisher := &mockEventPublisher{}
	eventPublisher.publishFunc = func(ctx context.Context, evt events.DomainEvent, opts ...events.PublishOption) error {
		eventPublisher.mu.Lock()
		eventPublisher.publishedEvents = append(eventPublisher.publishedEvents, evt)
		eventPublisher.publishOptions = append(eventPublisher.publishOptions, opts)
		eventPublisher.mu.Unlock()

		// Signal event processing.
		select {
		case eventProcessed <- struct{}{}:
		default:
			// Channel is full, which means we've already signaled.
		}
		return nil
	}

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

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	t.Cleanup(func() {
		heartbeatMonitor.Stop()
	})

	heartbeatMonitor.Start(ctx)

	// Advance time past the staleness threshold.
	mockProvider.SetNow(21 * time.Second) // Past the 20-second staleness threshold

	// Directly trigger the staleness check.
	heartbeatMonitor.checkForStaleTasks(ctx)

	// Wait for the event to be processed.
	select {
	case <-eventProcessed:
		// Success - event was processed.
		t.Log("Event was processed successfully")
	case <-ctx.Done():
		t.Fatal("Test timed out waiting for event to be processed")
	}

	eventPublisher.mu.RLock()
	defer eventPublisher.mu.RUnlock()

	assert.NotEmpty(t, eventPublisher.publishedEvents, "Expected events to be published for stale tasks")
	if len(eventPublisher.publishedEvents) > 0 {
		evt, ok := eventPublisher.publishedEvents[0].(scanning.TaskStaleEvent)
		require.True(t, ok, "Expected event to be TaskStaleEvent")
		assert.Equal(t, scanning.StallReasonNoProgress, evt.Reason)
	}
	assert.NotEmpty(t, eventPublisher.publishOptions, "Expected publish options to be set")
}

func TestHeartbeatMonitor_ConcurrentAccess(t *testing.T) {
	baseTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	mockProvider := &mockTimeProvider{now: baseTime}

	var heartbeatsReceived int32
	var staleChecksPerformed int32

	heartbeatSvc := &mockHeartbeatService{
		updateHeartbeatsFunc: func(ctx context.Context, beats map[uuid.UUID]time.Time) (int64, error) {
			atomic.AddInt32(&heartbeatsReceived, int32(len(beats)))
			return int64(len(beats)), nil
		},
		findStaleTasksFunc: func(ctx context.Context, controllerID string, cutoff time.Time) ([]scanning.StaleTaskInfo, error) {
			atomic.AddInt32(&staleChecksPerformed, 1)
			return nil, nil
		},
	}

	heartbeatMonitor := NewTaskHealthSupervisor(
		"test-controller",
		heartbeatSvc,
		new(mockStateHandler),
		new(mockEventPublisher),
		noop.NewTracerProvider().Tracer("test"),
		logger.Noop(),
	)
	heartbeatMonitor.timeProvider = mockProvider
	heartbeatMonitor.flushInterval = time.Millisecond // Set very short flush interval

	const operations = 100

	// Start the monitor to enable periodic flushing.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	heartbeatMonitor.Start(ctx)

	// Launch concurrent operations.
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for i := 0; i < operations; i++ {
			taskID := uuid.New() // Generate unique taskID for each heartbeat
			heartbeatMonitor.HandleHeartbeat(context.Background(), scanning.TaskHeartbeatEvent{TaskID: taskID})
			time.Sleep(time.Microsecond) // Small sleep to allow for flush
		}
	}()

	go func() {
		defer wg.Done()
		for i := 0; i < operations; i++ {
			heartbeatMonitor.checkForStaleTasks(context.Background())
			time.Sleep(time.Microsecond) // Small sleep to prevent tight loop
		}
	}()

	// Wait for all operations to complete.
	wg.Wait()

	// Give time for final flushes to complete.
	time.Sleep(10 * time.Millisecond)

	// Force a final flush.
	heartbeatMonitor.flushHeartbeats(context.Background())
	heartbeatMonitor.Stop()

	totalHeartbeats := atomic.LoadInt32(&heartbeatsReceived)
	totalStaleChecks := atomic.LoadInt32(&staleChecksPerformed)

	if totalHeartbeats != int32(operations) {
		t.Errorf("Expected %d heartbeats to be processed, but got %d", operations, totalHeartbeats)
	}
	if totalStaleChecks != int32(operations) {
		t.Errorf("Expected %d stale checks to be performed, but got %d", operations, totalStaleChecks)
	}
}
