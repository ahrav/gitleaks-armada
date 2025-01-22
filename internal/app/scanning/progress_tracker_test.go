package scanning

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

// mockScanJobCoordinator helps test the progress tracker's interactions
// with the job coordination layer
type mockScanJobCoordinator struct{ mock.Mock }

func (m *mockScanJobCoordinator) CreateJob(ctx context.Context) (*scanning.Job, error) {
	args := m.Called(ctx)
	if job := args.Get(0); job != nil {
		return job.(*scanning.Job), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockScanJobCoordinator) LinkTargets(ctx context.Context, jobID uuid.UUID, targets []uuid.UUID) error {
	return m.Called(ctx, jobID, targets).Error(0)
}

func (m *mockScanJobCoordinator) StartTask(ctx context.Context, jobID, taskID uuid.UUID) (*scanning.Task, error) {
	args := m.Called(ctx, jobID, taskID)
	if task := args.Get(0); task != nil {
		return task.(*scanning.Task), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockScanJobCoordinator) UpdateTaskProgress(
	ctx context.Context,
	progress scanning.Progress,
) (*scanning.Task, error) {
	args := m.Called(ctx, progress)
	if task := args.Get(0); task != nil {
		return task.(*scanning.Task), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockScanJobCoordinator) CompleteTask(
	ctx context.Context,
	jobID,
	taskID uuid.UUID,
) (*scanning.Task, error) {
	args := m.Called(ctx, jobID, taskID)
	if task := args.Get(0); task != nil {
		return task.(*scanning.Task), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockScanJobCoordinator) FailTask(
	ctx context.Context,
	jobID,
	taskID uuid.UUID,
) (*scanning.Task, error) {
	args := m.Called(ctx, jobID, taskID)
	if task := args.Get(0); task != nil {
		return task.(*scanning.Task), args.Error(1)
	}
	return nil, args.Error(1)
}

type trackerTestSuite struct {
	jobCoordinator *mockScanJobCoordinator
	logger         *logger.Logger
	tracer         trace.Tracer
	tracker        ExecutionTracker
}

func newTrackerTestSuite(t *testing.T) *trackerTestSuite {
	t.Helper()

	jobCoordinator := new(mockScanJobCoordinator)
	logger := logger.New(io.Discard, logger.LevelDebug, "test", nil)
	tracer := noop.NewTracerProvider().Tracer("test")

	return &trackerTestSuite{
		jobCoordinator: jobCoordinator,
		logger:         logger,
		tracer:         tracer,
		tracker:        NewExecutionTracker(jobCoordinator, logger, tracer),
	}
}

func TestStartTracking(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(*mockScanJobCoordinator)
		event   scanning.TaskStartedEvent
		wantErr bool
	}{
		{
			name: "successful task start",
			setup: func(m *mockScanJobCoordinator) {
				m.On("StartTask", mock.Anything, mock.Anything, mock.Anything).
					Return(new(scanning.Task), nil)
			},
			event:   scanning.TaskStartedEvent{JobID: uuid.New(), TaskID: uuid.New()},
			wantErr: false,
		},
		{
			name: "coordinator failure",
			setup: func(m *mockScanJobCoordinator) {
				m.On("StartTask", mock.Anything, mock.Anything, mock.Anything).
					Return(nil, errors.New("coordinator failure"))
			},
			event:   scanning.TaskStartedEvent{JobID: uuid.New(), TaskID: uuid.New()},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			suite := newTrackerTestSuite(t)
			tt.setup(suite.jobCoordinator)

			err := suite.tracker.StartTracking(context.Background(), tt.event)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			suite.jobCoordinator.AssertExpectations(t)
		})
	}
}

func TestUpdateProgress(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(*mockScanJobCoordinator)
		event   scanning.TaskProgressedEvent
		wantErr bool
	}{
		{
			name: "successful progress update",
			setup: func(m *mockScanJobCoordinator) {
				m.On("UpdateTaskProgress", mock.Anything, mock.Anything).
					Return(new(scanning.Task), nil)
			},
			event: scanning.TaskProgressedEvent{
				Progress: scanning.NewProgress(uuid.New(), 1, time.Now(), 1, 0, "", nil, nil),
			},
			wantErr: false,
		},
		{
			name: "failed progress update",
			setup: func(m *mockScanJobCoordinator) {
				m.On("UpdateTaskProgress", mock.Anything, mock.Anything).
					Return(nil, errors.New("coordinator failure"))
			},
			event: scanning.TaskProgressedEvent{
				Progress: scanning.NewProgress(uuid.New(), 1, time.Now(), 1, 0, "", nil, nil),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			suite := newTrackerTestSuite(t)
			tt.setup(suite.jobCoordinator)

			err := suite.tracker.UpdateProgress(context.Background(), tt.event)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			suite.jobCoordinator.AssertExpectations(t)
		})
	}
}

func TestFullScanningLifecycle(t *testing.T) {
	suite := newTrackerTestSuite(t)
	jobID := uuid.New()
	taskID := uuid.New()

	// Setup expectations for the full lifecycle.
	suite.jobCoordinator.On("StartTask", mock.Anything, jobID, taskID).
		Return(&scanning.Task{}, nil)
	suite.jobCoordinator.On("UpdateTaskProgress", mock.Anything, mock.Anything).
		Return(&scanning.Task{}, nil).Times(3)
	suite.jobCoordinator.On("CompleteTask", mock.Anything, jobID, taskID).
		Return(&scanning.Task{}, nil)

	ctx := context.Background()

	err := suite.tracker.StartTracking(ctx, scanning.TaskStartedEvent{
		JobID:  jobID,
		TaskID: taskID,
	})
	require.NoError(t, err)

	// Simulate progress.
	for i := 0; i < 3; i++ {
		progress := scanning.NewProgress(taskID, int64(i), time.Now(), int64(i), 0, "", nil, nil)
		err = suite.tracker.UpdateProgress(ctx, scanning.TaskProgressedEvent{
			Progress: progress,
		})
		require.NoError(t, err)
	}

	// Complete the task.
	err = suite.tracker.StopTracking(ctx, scanning.TaskCompletedEvent{
		JobID:  jobID,
		TaskID: taskID,
	})
	require.NoError(t, err)

	suite.jobCoordinator.AssertExpectations(t)
}
