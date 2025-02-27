package orchestration

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/ahrav/gitleaks-armada/pkg/common/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/ahrav/gitleaks-armada/internal/domain/enumeration"
	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/domain/rules"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
)

type mockJobScheduler struct{ mock.Mock }

func (m *mockJobScheduler) Schedule(ctx context.Context, jobID uuid.UUID, targets []scanning.Target) error {
	args := m.Called(ctx, jobID, targets)
	return args.Error(0)
}

func (m *mockJobScheduler) Pause(ctx context.Context, jobID uuid.UUID, requestedBy string) error {
	args := m.Called(ctx, jobID, requestedBy)
	return args.Error(0)
}

func (m *mockJobScheduler) Cancel(ctx context.Context, jobID uuid.UUID, requestedBy string) error {
	args := m.Called(ctx, jobID, requestedBy)
	return args.Error(0)
}

// Mock implementations.
type mockExecutionTracker struct{ mock.Mock }

func (m *mockExecutionTracker) ProcessEnumerationStream(ctx context.Context, jobID uuid.UUID, result *scanning.ScanningResult) error {
	args := m.Called(ctx, jobID, result)
	return args.Error(0)
}

func (m *mockExecutionTracker) HandleTaskStart(ctx context.Context, evt scanning.TaskStartedEvent) error {
	args := m.Called(ctx, evt)
	return args.Error(0)
}

func (m *mockExecutionTracker) HandleTaskProgress(ctx context.Context, evt scanning.TaskProgressedEvent) error {
	args := m.Called(ctx, evt)
	return args.Error(0)
}

func (m *mockExecutionTracker) HandleTaskCompletion(ctx context.Context, evt scanning.TaskCompletedEvent) error {
	args := m.Called(ctx, evt)
	return args.Error(0)
}

func (m *mockExecutionTracker) HandleTaskFailure(ctx context.Context, evt scanning.TaskFailedEvent) error {
	args := m.Called(ctx, evt)
	return args.Error(0)
}

func (m *mockExecutionTracker) HandleTaskStale(ctx context.Context, evt scanning.TaskStaleEvent) error {
	args := m.Called(ctx, evt)
	return args.Error(0)
}

func (m *mockExecutionTracker) HandleTaskPaused(ctx context.Context, evt scanning.TaskPausedEvent) error {
	args := m.Called(ctx, evt)
	return args.Error(0)
}

func (m *mockExecutionTracker) HandleTaskCancelled(ctx context.Context, evt scanning.TaskCancelledEvent) error {
	args := m.Called(ctx, evt)
	return args.Error(0)
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
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *mockJobMetricsAggregator) Stop(ctx context.Context) { m.Called(ctx) }

func (m *mockJobMetricsAggregator) HandleJobMetrics(ctx context.Context, evt events.EventEnvelope, ack events.AckFunc) error {
	args := m.Called(ctx, evt, ack)
	return args.Error(0)
}

func (m *mockJobMetricsAggregator) HandleEnumerationCompleted(ctx context.Context, evt events.EventEnvelope, ack events.AckFunc) error {
	args := m.Called(ctx, evt, ack)
	return args.Error(0)
}

type mockEnumerationService struct{ mock.Mock }

func (m *mockEnumerationService) StartEnumeration(ctx context.Context, targetSpec *enumeration.TargetSpec) enumeration.EnumerationResult {
	args := m.Called(ctx, targetSpec)
	return args.Get(0).(enumeration.EnumerationResult)
}

type mockRulesService struct{ mock.Mock }

func (m *mockRulesService) SaveRule(ctx context.Context, r rules.GitleaksRule) error {
	args := m.Called(ctx, r)
	return args.Error(0)
}

func setupEventsFacilitatorTestSuite() (
	*EventsFacilitator,
	*mockJobScheduler,
	*mockExecutionTracker,
	*mockTaskHealthMonitor,
	*mockJobMetricsAggregator,
	*mockEnumerationService,
	*mockRulesService,
) {
	mockJobScheduler := new(mockJobScheduler)
	mockTracker := new(mockExecutionTracker)
	mockHealthMonitor := new(mockTaskHealthMonitor)
	mockMetricsAggregator := new(mockJobMetricsAggregator)
	mockEnumService := new(mockEnumerationService)
	mockRulesService := new(mockRulesService)

	facilitator := NewEventsFacilitator(
		"test-controller",
		mockJobScheduler,
		mockTracker,
		mockHealthMonitor, mockMetricsAggregator,
		mockEnumService,
		mockRulesService,
		noop.NewTracerProvider().Tracer("test"),
	)

	return facilitator, mockJobScheduler, mockTracker, mockHealthMonitor, mockMetricsAggregator,
		mockEnumService, mockRulesService
}

func TestHandleScanJobRequested(t *testing.T) {
	tests := []struct {
		name          string
		setupMock     func(m *mockJobScheduler)
		targets       []scanning.Target
		expectedCalls int
		expectErr     bool
	}{
		{
			name: "success - two targets",
			setupMock: func(m *mockJobScheduler) {
				m.On("Schedule", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
			},
			targets: []scanning.Target{
				scanning.NewTarget("test-target", shared.SourceTypeGitHub, &scanning.Auth{}, map[string]string{}, scanning.TargetConfig{}),
				scanning.NewTarget("test-target-2", shared.SourceTypeURL, &scanning.Auth{}, map[string]string{}, scanning.TargetConfig{}),
			},
			expectedCalls: 1,
			expectErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			facilitator, mockJobScheduler, _, _, _, _, _ := setupEventsFacilitatorTestSuite()
			tt.setupMock(mockJobScheduler)

			var ackCalled bool
			ack := func(err error) { ackCalled = true }

			err := facilitator.HandleScanJobRequested(
				context.Background(),
				events.EventEnvelope{
					Payload: scanning.JobRequestedEvent{
						RequestedBy: "test-user",
						Targets:     tt.targets,
					},
				},
				ack,
			)

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.True(t, ackCalled, "ack function should have been called")
			mockJobScheduler.AssertNumberOfCalls(t, "Schedule", tt.expectedCalls)
		})
	}
}

// TODO: Add tests for HandleScanJobCreated.

func TestHandleJobPausing(t *testing.T) {
	validJobID := uuid.New()

	tests := []struct {
		name      string
		setupMock func(m *mockJobScheduler)
		payload   any
		expectErr bool
	}{
		{
			name: "success",
			setupMock: func(m *mockJobScheduler) {
				m.On("Pause", mock.Anything, validJobID, "test-user").Return(nil).Once()
			},
			payload: scanning.JobPausingEvent{
				JobID:       validJobID.String(),
				RequestedBy: "test-user",
			},
			expectErr: false,
		},
		{
			name: "invalid payload type",
			setupMock: func(m *mockJobScheduler) {
				// No expectations, should fail before calling scheduler.
			},
			payload:   "invalid payload",
			expectErr: true,
		},
		{
			name: "invalid job ID",
			setupMock: func(m *mockJobScheduler) {
				// No expectations, should fail before calling scheduler.
			},
			payload: scanning.JobPausingEvent{
				JobID:       "not-a-uuid",
				RequestedBy: "test-user",
			},
			expectErr: true,
		},
		{
			name: "job scheduler error",
			setupMock: func(m *mockJobScheduler) {
				m.On("Pause", mock.Anything, validJobID, "test-user").
					Return(errors.New("scheduler error")).Once()
			},
			payload: scanning.JobPausingEvent{
				JobID:       validJobID.String(),
				RequestedBy: "test-user",
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			facilitator, mockJobScheduler, _, _, _, _, _ := setupEventsFacilitatorTestSuite()
			tt.setupMock(mockJobScheduler)

			var ackCalled bool
			ack := func(err error) { ackCalled = true }

			err := facilitator.HandleJobPausing(
				context.Background(),
				events.EventEnvelope{Payload: tt.payload},
				ack,
			)

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.True(t, ackCalled, "ack function should have been called")
			mockJobScheduler.AssertExpectations(t)
		})
	}
}

func TestHandleJobCancelling(t *testing.T) {
	validJobID := uuid.New()

	tests := []struct {
		name      string
		setupMock func(m *mockJobScheduler)
		payload   any
		expectErr bool
	}{
		{
			name: "success",
			setupMock: func(m *mockJobScheduler) {
				m.On("Cancel", mock.Anything, validJobID, "test-user").Return(nil).Once()
			},
			payload: scanning.JobCancellingEvent{
				JobID:       validJobID.String(),
				RequestedBy: "test-user",
			},
			expectErr: false,
		},
		{
			name: "invalid payload type",
			setupMock: func(m *mockJobScheduler) {
				// No expectations, should fail before calling scheduler.
			},
			payload:   "invalid payload",
			expectErr: true,
		},
		{
			name: "invalid job ID",
			setupMock: func(m *mockJobScheduler) {
				// No expectations, should fail before calling scheduler.
			},
			payload: scanning.JobCancellingEvent{
				JobID:       "not-a-uuid",
				RequestedBy: "test-user",
			},
			expectErr: true,
		},
		{
			name: "job scheduler error",
			setupMock: func(m *mockJobScheduler) {
				m.On("Cancel", mock.Anything, validJobID, "test-user").
					Return(errors.New("scheduler error")).Once()
			},
			payload: scanning.JobCancellingEvent{
				JobID:       validJobID.String(),
				RequestedBy: "test-user",
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			facilitator, mockJobScheduler, _, _, _, _, _ := setupEventsFacilitatorTestSuite()
			tt.setupMock(mockJobScheduler)

			var ackCalled bool
			ack := func(err error) { ackCalled = true }

			err := facilitator.HandleJobCancelling(
				context.Background(),
				events.EventEnvelope{Payload: tt.payload},
				ack,
			)

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.True(t, ackCalled, "ack function should have been called")
			mockJobScheduler.AssertExpectations(t)
		})
	}
}

func TestHandleTaskPaused(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(*mockExecutionTracker)
		event   events.EventEnvelope
		wantErr bool
	}{
		{
			name: "successful task pause",
			setup: func(m *mockExecutionTracker) {
				m.On("HandleTaskPaused", mock.Anything, mock.MatchedBy(func(evt scanning.TaskPausedEvent) bool {
					return evt.RequestedBy == "test-user"
				})).Return(nil)
			},
			event: events.EventEnvelope{
				Payload: scanning.TaskPausedEvent{
					JobID:       uuid.New(),
					TaskID:      uuid.New(),
					Progress:    scanning.Progress{},
					RequestedBy: "test-user",
				},
				Metadata: events.EventMetadata{
					Partition: 0,
					Offset:    1,
				},
			},
			wantErr: false,
		},
		{
			name: "invalid event payload",
			setup: func(m *mockExecutionTracker) {
				// No expectations since handler should fail before calling tracker
			},
			event: events.EventEnvelope{
				Payload: "invalid payload",
			},
			wantErr: true,
		},
		{
			name: "execution tracker error",
			setup: func(m *mockExecutionTracker) {
				m.On("HandleTaskPaused", mock.Anything, mock.Anything).
					Return(errors.New("tracker error"))
			},
			event: events.EventEnvelope{
				Payload: scanning.TaskPausedEvent{
					JobID:       uuid.New(),
					TaskID:      uuid.New(),
					Progress:    scanning.Progress{},
					RequestedBy: "test-user",
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			facilitator, _, tracker, _, _, _, _ := setupEventsFacilitatorTestSuite()
			tt.setup(tracker)

			err := facilitator.HandleTaskPaused(context.Background(), tt.event, func(error) {})
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			tracker.AssertExpectations(t)
		})
	}
}

func TestHandleTaskStarted(t *testing.T) {
	startedEvt := scanning.TaskStartedEvent{
		TaskID:      uuid.New(),
		JobID:       uuid.New(),
		ResourceURI: "test://resource",
	}

	tests := []struct {
		name      string
		setupMock func(m *mockExecutionTracker)
		expectErr bool
	}{
		{
			name: "success",
			setupMock: func(m *mockExecutionTracker) {
				m.On("HandleTaskStart", mock.Anything, startedEvt).Return(nil)
			},
			expectErr: false,
		},
		{
			name: "error",
			setupMock: func(m *mockExecutionTracker) {
				m.On("HandleTaskStart", mock.Anything, startedEvt).Return(errors.New("handler error"))
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			facilitator, _, mockTracker, _, _, _, _ := setupEventsFacilitatorTestSuite()
			tt.setupMock(mockTracker)

			var ackCalled bool
			ack := func(err error) { ackCalled = true }

			err := facilitator.HandleTaskStarted(
				context.Background(),
				events.EventEnvelope{Payload: startedEvt},
				ack,
			)

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.True(t, ackCalled, "ack function should have been called")
			mockTracker.AssertExpectations(t)
		})
	}
}

func TestHandleTaskProgressed(t *testing.T) {
	progressEvt := scanning.TaskProgressedEvent{
		Progress: scanning.NewProgress(
			uuid.New(),
			uuid.New(),
			100,
			time.Now(),
			5,
			10,
			"",
			json.RawMessage(`{"test": "test"}`),
			nil,
		),
	}

	tests := []struct {
		name      string
		setupMock func(m *mockExecutionTracker)
		expectErr bool
	}{
		{
			name: "success",
			setupMock: func(m *mockExecutionTracker) {
				m.On("HandleTaskProgress", mock.Anything, progressEvt).Return(nil)
			},
			expectErr: false,
		},
		{
			name: "error",
			setupMock: func(m *mockExecutionTracker) {
				m.On("HandleTaskProgress", mock.Anything, progressEvt).Return(errors.New("handler error"))
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			facilitator, _, mockTracker, _, _, _, _ := setupEventsFacilitatorTestSuite()
			tt.setupMock(mockTracker)

			var ackCalled bool
			ack := func(err error) { ackCalled = true }

			err := facilitator.HandleTaskProgressed(
				context.Background(),
				events.EventEnvelope{Payload: progressEvt},
				ack,
			)

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.True(t, ackCalled, "ack function should have been called")
			mockTracker.AssertExpectations(t)
		})
	}
}

func TestHandleTaskCompleted(t *testing.T) {
	completedEvt := scanning.TaskCompletedEvent{TaskID: uuid.New(), JobID: uuid.New()}

	tests := []struct {
		name      string
		setupMock func(m *mockExecutionTracker)
		expectErr bool
	}{
		{
			name: "success",
			setupMock: func(m *mockExecutionTracker) {
				m.On("HandleTaskCompletion", mock.Anything, completedEvt).Return(nil)
			},
			expectErr: false,
		},
		{
			name: "error",
			setupMock: func(m *mockExecutionTracker) {
				m.On("HandleTaskCompletion", mock.Anything, completedEvt).Return(errors.New("handler error"))
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			facilitator, _, mockTracker, _, _, _, _ := setupEventsFacilitatorTestSuite()
			tt.setupMock(mockTracker)

			var ackCalled bool
			ack := func(err error) { ackCalled = true }

			err := facilitator.HandleTaskCompleted(
				context.Background(),
				events.EventEnvelope{Payload: completedEvt},
				ack,
			)

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.True(t, ackCalled, "ack function should have been called")
			mockTracker.AssertExpectations(t)
		})
	}
}

func TestHandleTaskFailed(t *testing.T) {
	failedEvt := scanning.TaskFailedEvent{
		TaskID: uuid.New(),
		JobID:  uuid.New(),
		Reason: "test failure",
	}

	tests := []struct {
		name      string
		setupMock func(m *mockExecutionTracker)
		expectErr bool
	}{
		{
			name: "success",
			setupMock: func(m *mockExecutionTracker) {
				m.On("HandleTaskFailure", mock.Anything, failedEvt).Return(nil)
			},
			expectErr: false,
		},
		{
			name: "error",
			setupMock: func(m *mockExecutionTracker) {
				m.On("HandleTaskFailure", mock.Anything, failedEvt).Return(errors.New("handler error"))
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			facilitator, _, mockTracker, _, _, _, _ := setupEventsFacilitatorTestSuite()
			tt.setupMock(mockTracker)

			var ackCalled bool
			ack := func(err error) { ackCalled = true }

			err := facilitator.HandleTaskFailed(
				context.Background(),
				events.EventEnvelope{Payload: failedEvt},
				ack,
			)

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.True(t, ackCalled, "ack function should have been called")
			mockTracker.AssertExpectations(t)
		})
	}
}

func TestHandleTaskHeartbeat(t *testing.T) {
	tests := []struct {
		name string
	}{
		{
			name: "heartbeat success",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			facilitator, _, _, mockHealthMonitor, _, _, _ := setupEventsFacilitatorTestSuite()

			taskID := uuid.New()
			heartbeatEvt := scanning.TaskHeartbeatEvent{TaskID: taskID}

			var ackCalled bool
			ack := func(err error) { ackCalled = true }

			mockHealthMonitor.On("HandleHeartbeat", mock.Anything, heartbeatEvt).Return()

			err := facilitator.HandleTaskHeartbeat(
				context.Background(),
				events.EventEnvelope{Payload: heartbeatEvt},
				ack,
			)

			assert.NoError(t, err)
			assert.True(t, ackCalled, "ack function should have been called")
			mockHealthMonitor.AssertExpectations(t)
		})
	}
}

func TestHandleTaskJobMetric(t *testing.T) {
	metricEvt := scanning.TaskJobMetricEvent{
		JobID:  uuid.New(),
		TaskID: uuid.New(),
		Status: scanning.TaskStatusInProgress,
	}

	evt := events.EventEnvelope{Payload: metricEvt}

	tests := []struct {
		name      string
		setupMock func(m *mockJobMetricsAggregator)
		expectErr bool
	}{
		{
			name: "success",
			setupMock: func(m *mockJobMetricsAggregator) {
				m.On("HandleJobMetrics",
					mock.Anything,
					mock.MatchedBy(func(e events.EventEnvelope) bool {
						metric, ok := e.Payload.(scanning.TaskJobMetricEvent)
						return ok &&
							metric.JobID == metricEvt.JobID &&
							metric.TaskID == metricEvt.TaskID &&
							metric.Status == metricEvt.Status
					}),
					mock.AnythingOfType("events.AckFunc"),
				).Return(nil)
			},
			expectErr: false,
		},
		{
			name: "error",
			setupMock: func(m *mockJobMetricsAggregator) {
				m.On("HandleJobMetrics", mock.Anything, mock.Anything, mock.Anything).Return(errors.New("handler error"))
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			facilitator, _, _, _, mockMetricsTracker, _, _ := setupEventsFacilitatorTestSuite()
			tt.setupMock(mockMetricsTracker)

			ack := func(err error) {} // Ack is handled by the execution tracker.

			err := facilitator.HandleTaskJobMetric(context.Background(), evt, ack)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			mockMetricsTracker.AssertExpectations(t)
		})
	}
}

func TestHandleRule(t *testing.T) {
	ruleEvt := rules.RuleUpdatedEvent{
		Rule: rules.GitleaksRuleMessage{
			GitleaksRule: rules.GitleaksRule{
				RuleID: "test-rule",
			},
		},
	}

	tests := []struct {
		name      string
		setupMock func(m *mockRulesService)
		expectErr bool
	}{
		{
			name: "success",
			setupMock: func(m *mockRulesService) {
				m.On("SaveRule", mock.Anything, ruleEvt.Rule.GitleaksRule).Return(nil)
			},
			expectErr: false,
		},
		{
			name: "error",
			setupMock: func(m *mockRulesService) {
				m.On("SaveRule", mock.Anything, ruleEvt.Rule.GitleaksRule).Return(errors.New("handler error"))
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			facilitator, _, _, _, _, _, mockRulesService := setupEventsFacilitatorTestSuite()
			tt.setupMock(mockRulesService)

			var ackCalled bool
			ack := func(err error) { ackCalled = true }

			err := facilitator.HandleRule(
				context.Background(),
				events.EventEnvelope{Payload: ruleEvt},
				ack,
			)

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.True(t, ackCalled, "ack function should have been called")
			mockRulesService.AssertExpectations(t)
		})
	}
}
