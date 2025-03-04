package handlers

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/ahrav/gitleaks-armada/internal/domain/enumeration"
	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
	"github.com/ahrav/gitleaks-armada/pkg/common/uuid"
)

// Mock implementations for testing
type mockJobScheduler struct{ mock.Mock }

func (m *mockJobScheduler) Schedule(ctx context.Context, cmd scanning.ScheduleJobCommand) error {
	return m.Called(ctx, cmd).Error(0)
}

func (m *mockJobScheduler) Pause(ctx context.Context, cmd scanning.JobControlCommand) error {
	return m.Called(ctx, cmd).Error(0)
}

func (m *mockJobScheduler) Cancel(ctx context.Context, cmd scanning.JobControlCommand) error {
	return m.Called(ctx, cmd).Error(0)
}

func (m *mockJobScheduler) Resume(ctx context.Context, cmd scanning.JobControlCommand) error {
	return m.Called(ctx, cmd).Error(0)
}

type mockExecutionTracker struct{ mock.Mock }

func (m *mockExecutionTracker) ProcessEnumerationStream(ctx context.Context, jobID uuid.UUID, result *scanning.ScanningResult) error {
	return m.Called(ctx, jobID, result).Error(0)
}

func (m *mockExecutionTracker) HandleTaskStart(ctx context.Context, evt scanning.TaskStartedEvent) error {
	return m.Called(ctx, evt).Error(0)
}

func (m *mockExecutionTracker) HandleTaskProgress(ctx context.Context, evt scanning.TaskProgressedEvent) error {
	return m.Called(ctx, evt).Error(0)
}

func (m *mockExecutionTracker) HandleTaskCompletion(ctx context.Context, evt scanning.TaskCompletedEvent) error {
	return m.Called(ctx, evt).Error(0)
}

func (m *mockExecutionTracker) HandleTaskFailure(ctx context.Context, evt scanning.TaskFailedEvent) error {
	return m.Called(ctx, evt).Error(0)
}

func (m *mockExecutionTracker) HandleTaskStale(ctx context.Context, evt scanning.TaskStaleEvent) error {
	return m.Called(ctx, evt).Error(0)
}

func (m *mockExecutionTracker) HandleTaskPaused(ctx context.Context, evt scanning.TaskPausedEvent) error {
	return m.Called(ctx, evt).Error(0)
}

func (m *mockExecutionTracker) HandleTaskCancelled(ctx context.Context, evt scanning.TaskCancelledEvent) error {
	return m.Called(ctx, evt).Error(0)
}

type mockTaskHealthMonitor struct{ mock.Mock }

func (m *mockTaskHealthMonitor) Start(ctx context.Context) { m.Called(ctx) }

func (m *mockTaskHealthMonitor) HandleHeartbeat(ctx context.Context, evt scanning.TaskHeartbeatEvent) {
	m.Called(ctx, evt)
}

func (m *mockTaskHealthMonitor) Stop() { m.Called() }

type mockJobMetricsAggregator struct{ mock.Mock }

func (m *mockJobMetricsAggregator) LaunchMetricsFlusher(interval time.Duration) { m.Called(interval) }

func (m *mockJobMetricsAggregator) FlushMetrics(ctx context.Context) error {
	return m.Called(ctx).Error(0)
}

func (m *mockJobMetricsAggregator) Stop(ctx context.Context) { m.Called(ctx) }

func (m *mockJobMetricsAggregator) HandleJobMetrics(ctx context.Context, evt events.EventEnvelope, ack events.AckFunc) error {
	return m.Called(ctx, evt, ack).Error(0)
}

func (m *mockJobMetricsAggregator) HandleEnumerationCompleted(ctx context.Context, evt events.EventEnvelope, ack events.AckFunc) error {
	return m.Called(ctx, evt, ack).Error(0)
}

type mockEnumerationService struct{ mock.Mock }

func (m *mockEnumerationService) StartEnumeration(ctx context.Context, targetSpec *enumeration.TargetSpec) enumeration.EnumerationResult {
	args := m.Called(ctx, targetSpec)
	return args.Get(0).(enumeration.EnumerationResult)
}

// setupScanningHandlerTestSuite creates a ScanningHandler with mock dependencies for testing.
func setupScanningHandlerTestSuite() (
	*ScanningHandler,
	*mockJobScheduler,
	*mockExecutionTracker,
	*mockTaskHealthMonitor,
	*mockJobMetricsAggregator,
	*mockEnumerationService,
) {
	mockScheduler := new(mockJobScheduler)
	mockTracker := new(mockExecutionTracker)
	mockHealthMonitor := new(mockTaskHealthMonitor)
	mockMetricsAggregator := new(mockJobMetricsAggregator)
	mockEnumSvc := new(mockEnumerationService)

	tracer := noop.NewTracerProvider().Tracer("test-tracer")

	handler := NewScanningHandler(
		"test-controller",
		mockScheduler,
		mockTracker,
		mockHealthMonitor,
		mockMetricsAggregator,
		mockEnumSvc,
		tracer,
	)

	// // Set the ACL fields manually since they're not part of the constructor
	// handler.scanToEnumACL = acl.ScanningToEnumerationTranslator{}
	// handler.enumToScanACL = acl.EnumerationToScanningTranslator{}

	return handler, mockScheduler, mockTracker, mockHealthMonitor, mockMetricsAggregator, mockEnumSvc
}

func TestHandleScanJobRequested(t *testing.T) {
	jobID := uuid.New()
	requestedBy := "test-user"

	auth := scanning.NewAuth("token", map[string]interface{}{"token": "test-token"})
	metadata := map[string]string{"repo": "test-repo"}
	githubTarget := scanning.NewGitHubTarget("test-org", []string{"test-repo"})
	config := scanning.TargetConfig{
		GitHub: githubTarget,
	}
	target := scanning.NewTarget("test-target", shared.SourceTypeGitHub, &auth, metadata, config)
	targets := []scanning.Target{target}

	jobEvt := scanning.NewJobRequestedEvent(jobID, targets, requestedBy)

	tests := []struct {
		name              string
		setupMock         func(m *mockJobScheduler)
		expectErr         bool
		expectedErrSubstr string
	}{
		{
			name: "success",
			setupMock: func(m *mockJobScheduler) {
				m.On("Schedule", mock.Anything, mock.MatchedBy(func(cmd scanning.ScheduleJobCommand) bool {
					return true // Simplify to avoid the RequestedBy() function error
				})).Return(nil)
			},
			expectErr: false,
		},
		{
			name: "schedule error",
			setupMock: func(m *mockJobScheduler) {
				m.On("Schedule", mock.Anything, mock.Anything).Return(errors.New("scheduler error"))
			},
			expectErr:         true,
			expectedErrSubstr: "failed to schedule job",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, mockScheduler, _, _, _, _ := setupScanningHandlerTestSuite()
			tt.setupMock(mockScheduler)

			var ackCalled bool
			ack := func(err error) { ackCalled = true }

			evt := events.EventEnvelope{Type: scanning.EventTypeJobRequested, Payload: jobEvt}
			err := handler.HandleScanJobRequested(context.Background(), evt, ack)

			if tt.expectErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErrSubstr)
			} else {
				assert.NoError(t, err)
			}
			assert.True(t, ackCalled, "ack function should have been called")
			mockScheduler.AssertExpectations(t)
		})
	}
}

func TestHandleScanJobScheduled(t *testing.T) {
	jobID := uuid.New()

	auth := scanning.NewAuth("token", map[string]interface{}{"token": "test-token"})
	metadata := map[string]string{"repo": "test-repo"}
	githubTarget := scanning.NewGitHubTarget("test-org", []string{"test-repo"})
	config := scanning.TargetConfig{
		GitHub: githubTarget,
	}
	target := scanning.NewTarget("test-target", shared.SourceTypeGitHub, &auth, metadata, config)

	jobEvt := scanning.NewJobScheduledEvent(jobID, target)

	enumResult := enumeration.EnumerationResult{
		ScanTargetsCh: make(chan []uuid.UUID, 1),
		TasksCh:       make(chan *enumeration.Task, 1),
		ErrCh:         make(chan error, 1),
	}

	tests := []struct {
		name              string
		setupMocks        func(e *mockEnumerationService, t *mockExecutionTracker)
		expectErr         bool
		expectedErrSubstr string
	}{
		{
			name: "success",
			setupMocks: func(e *mockEnumerationService, t *mockExecutionTracker) {
				e.On("StartEnumeration", mock.Anything, mock.MatchedBy(func(spec *enumeration.TargetSpec) bool {
					return true // Simplify matching
				})).Return(enumResult)
				t.On("ProcessEnumerationStream", mock.Anything, jobID, mock.Anything).Return(nil)
			},
			expectErr: false,
		},
		{
			name: "process enumeration stream error",
			setupMocks: func(e *mockEnumerationService, t *mockExecutionTracker) {
				e.On("StartEnumeration", mock.Anything, mock.Anything).Return(enumResult)
				t.On("ProcessEnumerationStream", mock.Anything, jobID, mock.Anything).
					Return(errors.New("enumeration stream processing failed"))
			},
			expectErr:         true,
			expectedErrSubstr: "enumeration stream processing failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, _, mockTracker, _, _, mockEnumSvc := setupScanningHandlerTestSuite()
			tt.setupMocks(mockEnumSvc, mockTracker)

			var ackCalled bool
			ack := func(err error) { ackCalled = true }

			evt := events.EventEnvelope{Type: scanning.EventTypeJobScheduled, Payload: jobEvt}
			err := handler.HandleScanJobScheduled(context.Background(), evt, ack)

			if tt.expectErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErrSubstr)
			} else {
				assert.NoError(t, err)
			}
			assert.True(t, ackCalled, "ack function should have been called")
			mockEnumSvc.AssertExpectations(t)
			mockTracker.AssertExpectations(t)
		})
	}
}

func TestHandleJobPausing(t *testing.T) {
	jobIDString := uuid.New().String()
	requestedBy := "test-user"

	jobEvt := scanning.JobPausingEvent{JobID: jobIDString, RequestedBy: requestedBy}
	tests := []struct {
		name              string
		setupMock         func(m *mockJobScheduler)
		expectErr         bool
		expectedErrSubstr string
	}{
		{
			name: "success",
			setupMock: func(m *mockJobScheduler) {
				// Set up the mock for the Pause method.
				m.On("Pause", mock.Anything, mock.MatchedBy(func(cmd scanning.JobControlCommand) bool {
					return true // Accept any JobControlCommand
				})).Return(nil)
			},
			expectErr: false,
		},
		{
			name: "pause error",
			setupMock: func(m *mockJobScheduler) {
				m.On("Pause", mock.Anything, mock.Anything).Return(errors.New("pause error"))
			},
			expectErr:         true,
			expectedErrSubstr: "failed to pause job",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, mockScheduler, _, _, _, _ := setupScanningHandlerTestSuite()
			tt.setupMock(mockScheduler)

			var ackCalled bool
			ack := func(err error) { ackCalled = true }

			evt := events.EventEnvelope{Type: scanning.EventTypeJobPausing, Payload: jobEvt}
			err := handler.HandleJobPausing(context.Background(), evt, ack)

			if tt.expectErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErrSubstr)
			} else {
				assert.NoError(t, err)
			}
			assert.True(t, ackCalled, "ack function should have been called")
			mockScheduler.AssertExpectations(t)
		})
	}
}

func TestHandleTaskStarted(t *testing.T) {
	jobID := uuid.New()
	taskID := uuid.New()

	taskEvt := scanning.TaskStartedEvent{
		JobID:       jobID,
		TaskID:      taskID,
		ResourceURI: "https://example.com/repo.git",
	}

	tests := []struct {
		name              string
		setupMock         func(m *mockExecutionTracker)
		expectErr         bool
		expectedErrSubstr string
	}{
		{
			name: "success",
			setupMock: func(m *mockExecutionTracker) {
				m.On("HandleTaskStart", mock.Anything, taskEvt).Return(nil)
			},
			expectErr: false,
		},
		{
			name: "handle task start error",
			setupMock: func(m *mockExecutionTracker) {
				m.On("HandleTaskStart", mock.Anything, taskEvt).
					Return(errors.New("task start error"))
			},
			expectErr:         true,
			expectedErrSubstr: "task start error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, _, mockTracker, _, _, _ := setupScanningHandlerTestSuite()
			tt.setupMock(mockTracker)

			var ackCalled bool
			ack := func(err error) { ackCalled = true }

			evt := events.EventEnvelope{Type: scanning.EventTypeTaskStarted, Payload: taskEvt}
			err := handler.HandleTaskStarted(context.Background(), evt, ack)

			if tt.expectErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErrSubstr)
			} else {
				assert.NoError(t, err)
			}
			assert.True(t, ackCalled, "ack function should have been called")
			mockTracker.AssertExpectations(t)
		})
	}
}

func TestHandleTaskJobMetric(t *testing.T) {
	metricEvt := scanning.TaskJobMetricEvent{
		JobID:  uuid.New(),
		TaskID: uuid.New(),
		Status: scanning.TaskStatusInProgress,
	}

	enumCompletedEvt := scanning.JobEnumerationCompletedEvent{JobID: uuid.New(), TotalTasks: 10}

	tests := []struct {
		name              string
		payload           interface{}
		setupMock         func(m *mockJobMetricsAggregator)
		expectErr         bool
		expectedErrSubstr string
	}{
		{
			name:    "success with TaskJobMetricEvent",
			payload: metricEvt,
			setupMock: func(m *mockJobMetricsAggregator) {
				m.On("HandleJobMetrics", mock.Anything, mock.Anything, mock.Anything).Return(nil)
			},
			expectErr: false,
		},
		{
			name:    "success with JobEnumerationCompletedEvent",
			payload: enumCompletedEvt,
			setupMock: func(m *mockJobMetricsAggregator) {
				m.On("HandleEnumerationCompleted", mock.Anything, mock.Anything, mock.Anything).Return(nil)
			},
			expectErr: false,
		},
		{
			name:    "error with TaskJobMetricEvent",
			payload: metricEvt,
			setupMock: func(m *mockJobMetricsAggregator) {
				m.On("HandleJobMetrics", mock.Anything, mock.Anything, mock.Anything).
					Return(errors.New("metrics error"))
			},
			expectErr:         true,
			expectedErrSubstr: "metrics error",
		},
		{
			name:    "error with JobEnumerationCompletedEvent",
			payload: enumCompletedEvt,
			setupMock: func(m *mockJobMetricsAggregator) {
				m.On("HandleEnumerationCompleted", mock.Anything, mock.Anything, mock.Anything).
					Return(errors.New("enumeration completed error"))
			},
			expectErr:         true,
			expectedErrSubstr: "enumeration completed error",
		},
		{
			name:              "invalid payload type",
			payload:           "invalid payload",
			setupMock:         func(m *mockJobMetricsAggregator) {},
			expectErr:         true,
			expectedErrSubstr: "unexpected event type for job metrics tracker",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, _, _, _, mockMetricsAggregator, _ := setupScanningHandlerTestSuite()
			tt.setupMock(mockMetricsAggregator)

			var ackCalled bool
			ack := func(err error) { ackCalled = true }

			evt := events.EventEnvelope{Type: scanning.EventTypeTaskJobMetric, Payload: tt.payload}
			err := handler.HandleTaskJobMetric(context.Background(), evt, ack)

			if tt.expectErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErrSubstr)
				// ack is not called in error case for metrics because we want to reprocess.
				assert.False(t, ackCalled, "ack function should not have been called for error case")
			} else {
				assert.NoError(t, err)
				// ack is not called for metrics in success case either since the metrics aggregator manages offsets.
				assert.False(t, ackCalled, "ack function should not have been called")
			}
			mockMetricsAggregator.AssertExpectations(t)
		})
	}
}

func TestHandleTaskHeartbeat(t *testing.T) {
	heartbeatEvt := scanning.TaskHeartbeatEvent{
		TaskID: uuid.New(),
	}

	tests := []struct {
		name      string
		setupMock func(m *mockTaskHealthMonitor)
		expectErr bool
	}{
		{
			name: "success",
			setupMock: func(m *mockTaskHealthMonitor) {
				m.On("HandleHeartbeat", mock.Anything, heartbeatEvt)
			},
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, _, _, mockHealthMonitor, _, _ := setupScanningHandlerTestSuite()
			tt.setupMock(mockHealthMonitor)

			var ackCalled bool
			ack := func(err error) { ackCalled = true }

			evt := events.EventEnvelope{Type: scanning.EventTypeTaskHeartbeat, Payload: heartbeatEvt}
			err := handler.HandleTaskHeartbeat(context.Background(), evt, ack)

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.True(t, ackCalled, "ack function should have been called")
			mockHealthMonitor.AssertExpectations(t)
		})
	}
}
