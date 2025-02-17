package scanning

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
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

func (m *mockScanJobCoordinator) CreateTask(ctx context.Context, task *scanning.Task) error {
	return m.Called(ctx, task).Error(0)
}

func (m *mockScanJobCoordinator) StartTask(ctx context.Context, jobID, taskID uuid.UUID, resourceURI string) error {
	return m.Called(ctx, jobID, taskID, resourceURI).Error(0)
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

func (m *mockScanJobCoordinator) GetTaskSourceType(ctx context.Context, taskID uuid.UUID) (shared.SourceType, error) {
	args := m.Called(ctx, taskID)
	return args.Get(0).(shared.SourceType), args.Error(1)
}

func (m *mockScanJobCoordinator) MarkTaskStale(
	ctx context.Context,
	jobID,
	taskID uuid.UUID,
	reason scanning.StallReason,
) (*scanning.Task, error) {
	args := m.Called(ctx, jobID, taskID, reason)
	if task := args.Get(0); task != nil {
		return task.(*scanning.Task), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockScanJobCoordinator) GetTask(ctx context.Context, taskID uuid.UUID) (*scanning.Task, error) {
	args := m.Called(ctx, taskID)
	if task := args.Get(0); task != nil {
		return task.(*scanning.Task), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockScanJobCoordinator) FindStaleTasks(ctx context.Context, controllerID string, cutoff time.Time) ([]scanning.StaleTaskInfo, error) {
	args := m.Called(ctx, controllerID, cutoff)
	return args.Get(0).([]scanning.StaleTaskInfo), args.Error(1)
}

func (m *mockScanJobCoordinator) UpdateHeartbeats(ctx context.Context, heartbeats map[uuid.UUID]time.Time) (int64, error) {
	args := m.Called(ctx, heartbeats)
	return args.Get(0).(int64), args.Error(1)
}

type mockDomainEventPublisher struct{ mock.Mock }

func (m *mockDomainEventPublisher) PublishDomainEvent(ctx context.Context, event events.DomainEvent, opts ...events.PublishOption) error {
	return m.Called(ctx, event, opts).Error(0)
}

type trackerTestSuite struct {
	jobCoordinator  *mockScanJobCoordinator
	domainPublisher *mockDomainEventPublisher
	logger          *logger.Logger
	tracer          trace.Tracer
	tracker         *executionTracker
}

func newTrackerTestSuite(t *testing.T) *trackerTestSuite {
	t.Helper()

	jobCoordinator := new(mockScanJobCoordinator)
	domainPublisher := new(mockDomainEventPublisher)
	logger := logger.New(io.Discard, logger.LevelDebug, "test", nil)
	tracer := noop.NewTracerProvider().Tracer("test")

	return &trackerTestSuite{
		jobCoordinator:  jobCoordinator,
		domainPublisher: domainPublisher,
		logger:          logger,
		tracer:          tracer,
		tracker:         NewExecutionTracker("test-controller", jobCoordinator, domainPublisher, logger, tracer),
	}
}

func TestExecutionTracker_StartTracking(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(*mockScanJobCoordinator)
		event   scanning.TaskStartedEvent
		wantErr bool
	}{
		{
			name: "successful task start",
			setup: func(m *mockScanJobCoordinator) {
				m.On("StartTask", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(nil)
			},
			event: scanning.TaskStartedEvent{
				JobID:       uuid.New(),
				TaskID:      uuid.New(),
				ResourceURI: "https://example.com",
			},
			wantErr: false,
		},
		{
			name: "coordinator failure",
			setup: func(m *mockScanJobCoordinator) {
				m.On("StartTask", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(errors.New("coordinator failure"))
			},
			event: scanning.TaskStartedEvent{
				JobID:       uuid.New(),
				TaskID:      uuid.New(),
				ResourceURI: "https://example.com",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			suite := newTrackerTestSuite(t)
			tt.setup(suite.jobCoordinator)

			err := suite.tracker.HandleTaskStart(context.Background(), tt.event)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			suite.jobCoordinator.AssertExpectations(t)
		})
	}
}

func TestExecutionTracker_UpdateProgress(t *testing.T) {
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
				Progress: scanning.NewProgress(uuid.New(), uuid.New(), 1, time.Now(), 1, 0, "", nil, nil),
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
				Progress: scanning.NewProgress(uuid.New(), uuid.New(), 1, time.Now(), 1, 0, "", nil, nil),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			suite := newTrackerTestSuite(t)
			tt.setup(suite.jobCoordinator)

			err := suite.tracker.HandleTaskProgress(context.Background(), tt.event)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			suite.jobCoordinator.AssertExpectations(t)
		})
	}
}

func TestExecutionTracker_FullScanningLifecycle(t *testing.T) {
	suite := newTrackerTestSuite(t)
	jobID := uuid.New()
	taskID := uuid.New()
	resourceURI := "https://example.com"

	// Setup expectations for the full lifecycle.
	suite.jobCoordinator.On("StartTask", mock.Anything, jobID, taskID, resourceURI).
		Return(nil)
	suite.jobCoordinator.On("UpdateTaskProgress", mock.Anything, mock.Anything).
		Return(new(scanning.Task), nil).Times(3)
	suite.jobCoordinator.On("CompleteTask", mock.Anything, jobID, taskID).
		Return(new(scanning.Task), nil)

	ctx := context.Background()

	err := suite.tracker.HandleTaskStart(ctx, scanning.TaskStartedEvent{
		JobID:       jobID,
		TaskID:      taskID,
		ResourceURI: resourceURI,
	})
	require.NoError(t, err)

	// Simulate progress.
	for i := 0; i < 3; i++ {
		progress := scanning.NewProgress(taskID, jobID, int64(i), time.Now(), int64(i), 0, "", nil, nil)
		err = suite.tracker.HandleTaskProgress(ctx, scanning.TaskProgressedEvent{
			Progress: progress,
		})
		require.NoError(t, err)
	}

	// Complete the task.
	err = suite.tracker.HandleTaskCompletion(ctx, scanning.TaskCompletedEvent{
		JobID:  jobID,
		TaskID: taskID,
	})
	require.NoError(t, err)

	suite.jobCoordinator.AssertExpectations(t)
}

func TestExecutionTracker_StopTracking(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(*mockScanJobCoordinator)
		event   scanning.TaskCompletedEvent
		wantErr bool
	}{
		{
			name: "successful task completion",
			setup: func(m *mockScanJobCoordinator) {
				m.On("CompleteTask", mock.Anything, mock.Anything, mock.Anything).
					Return(new(scanning.Task), nil)
			},
			event: scanning.TaskCompletedEvent{
				JobID:  uuid.New(),
				TaskID: uuid.New(),
			},
			wantErr: false,
		},
		{
			name: "failed task completion",
			setup: func(m *mockScanJobCoordinator) {
				m.On("CompleteTask", mock.Anything, mock.Anything, mock.Anything).
					Return(new(scanning.Task), errors.New("completion failed"))
			},
			event: scanning.TaskCompletedEvent{
				JobID:  uuid.New(),
				TaskID: uuid.New(),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			suite := newTrackerTestSuite(t)
			tt.setup(suite.jobCoordinator)

			err := suite.tracker.HandleTaskCompletion(context.Background(), tt.event)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "failed to complete task")
			} else {
				require.NoError(t, err)
			}
			suite.jobCoordinator.AssertExpectations(t)
		})
	}
}

func TestExecutionTracker_MarkTaskFailure(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(*mockScanJobCoordinator)
		event   scanning.TaskFailedEvent
		wantErr bool
	}{
		{
			name: "successful task failure marking",
			setup: func(m *mockScanJobCoordinator) {
				m.On("FailTask", mock.Anything, mock.Anything, mock.Anything).
					Return(new(scanning.Task), nil)
			},
			event: scanning.TaskFailedEvent{
				JobID:  uuid.New(),
				TaskID: uuid.New(),
			},
			wantErr: false,
		},
		{
			name: "error marking task as failed",
			setup: func(m *mockScanJobCoordinator) {
				m.On("FailTask", mock.Anything, mock.Anything, mock.Anything).
					Return(new(scanning.Task), errors.New("failure marking failed"))
			},
			event: scanning.TaskFailedEvent{
				JobID:  uuid.New(),
				TaskID: uuid.New(),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			suite := newTrackerTestSuite(t)
			tt.setup(suite.jobCoordinator)

			err := suite.tracker.HandleTaskFailure(context.Background(), tt.event)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "failed to fail task")
			} else {
				require.NoError(t, err)
			}
			suite.jobCoordinator.AssertExpectations(t)
		})
	}
}

func TestExecutionTracker_MarkTaskStale(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(*mockScanJobCoordinator, *mockDomainEventPublisher)
		event   scanning.TaskStaleEvent
		wantErr bool
	}{
		{
			name: "successful stale task marking",
			setup: func(m *mockScanJobCoordinator, p *mockDomainEventPublisher) {
				m.On("MarkTaskStale", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(new(scanning.Task), nil)
				m.On("GetTaskSourceType", mock.Anything, mock.Anything).
					Return(shared.SourceTypeGitHub, nil)
				p.On("PublishDomainEvent",
					mock.Anything,
					mock.MatchedBy(func(event events.DomainEvent) bool {
						_, ok := event.(*scanning.TaskResumeEvent)
						return ok
					}),
					mock.Anything,
				).Return(nil)
			},
			event: scanning.TaskStaleEvent{
				JobID:  uuid.New(),
				TaskID: uuid.New(),
				Reason: scanning.StallReason("task timeout"),
			},
			wantErr: false,
		},
		{
			name: "error marking task as stale",
			setup: func(m *mockScanJobCoordinator, p *mockDomainEventPublisher) {
				m.On("MarkTaskStale", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(new(scanning.Task), errors.New("stale marking failed"))
			},
			event: scanning.TaskStaleEvent{
				JobID:  uuid.New(),
				TaskID: uuid.New(),
				Reason: scanning.StallReason("task timeout"),
			},
			wantErr: true,
		},
		{
			name: "error publishing resume event",
			setup: func(m *mockScanJobCoordinator, p *mockDomainEventPublisher) {
				m.On("MarkTaskStale", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(new(scanning.Task), nil)
				m.On("GetTaskSourceType", mock.Anything, mock.Anything).
					Return(shared.SourceTypeGitHub, nil)
				p.On("PublishDomainEvent",
					mock.Anything,
					mock.MatchedBy(func(event events.DomainEvent) bool {
						_, ok := event.(*scanning.TaskResumeEvent)
						return ok
					}),
					mock.Anything,
				).Return(errors.New("publish failed"))
			},
			event: scanning.TaskStaleEvent{
				JobID:  uuid.New(),
				TaskID: uuid.New(),
				Reason: scanning.StallReason("task timeout"),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			suite := newTrackerTestSuite(t)
			tt.setup(suite.jobCoordinator, suite.domainPublisher)

			err := suite.tracker.HandleTaskStale(context.Background(), tt.event)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			suite.jobCoordinator.AssertExpectations(t)
			suite.domainPublisher.AssertExpectations(t)
		})
	}
}

func TestExecutionTracker_HandleEnumeratedScanTask(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(*mockScanJobCoordinator, *mockDomainEventPublisher)
		jobID   uuid.UUID
		task    *scanning.Task
		auth    scanning.Auth
		meta    map[string]string
		wantErr bool
	}{
		{
			name: "successful task creation and event publish",
			setup: func(m *mockScanJobCoordinator, p *mockDomainEventPublisher) {
				m.On("CreateTask", mock.Anything, mock.Anything).
					Return(nil)
				p.On("PublishDomainEvent", mock.Anything, mock.Anything, mock.Anything).
					Return(nil)
			},
			jobID:   uuid.New(),
			task:    scanning.NewScanTask(uuid.New(), shared.SourceTypeGitHub, uuid.New(), "https://example.com"),
			auth:    scanning.Auth{},
			meta:    map[string]string{"key": "value"},
			wantErr: false,
		},
		{
			name: "task creation failure",
			setup: func(m *mockScanJobCoordinator, p *mockDomainEventPublisher) {
				m.On("CreateTask", mock.Anything, mock.Anything).
					Return(errors.New("creation failed"))
			},
			jobID:   uuid.New(),
			task:    scanning.NewScanTask(uuid.New(), shared.SourceTypeGitHub, uuid.New(), "https://example.com"),
			auth:    scanning.Auth{},
			meta:    map[string]string{"key": "value"},
			wantErr: true,
		},
		{
			name: "event publish failure",
			setup: func(m *mockScanJobCoordinator, p *mockDomainEventPublisher) {
				m.On("CreateTask", mock.Anything, mock.Anything).
					Return(nil)
				p.On("PublishDomainEvent", mock.Anything, mock.Anything, mock.Anything).
					Return(errors.New("publish failed"))
			},
			jobID:   uuid.New(),
			task:    scanning.NewScanTask(uuid.New(), shared.SourceTypeGitHub, uuid.New(), "https://example.com"),
			auth:    scanning.Auth{},
			meta:    map[string]string{"key": "value"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			suite := newTrackerTestSuite(t)
			tt.setup(suite.jobCoordinator, suite.domainPublisher)

			err := suite.tracker.HandleEnumeratedScanTask(
				context.Background(),
				tt.jobID,
				tt.task,
				tt.auth,
				tt.meta,
			)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			suite.jobCoordinator.AssertExpectations(t)
			suite.domainPublisher.AssertExpectations(t)
		})
	}
}
