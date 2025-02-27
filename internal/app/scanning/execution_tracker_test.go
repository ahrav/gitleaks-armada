package scanning

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/ahrav/gitleaks-armada/pkg/common/uuid"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	domain "github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

type trackerTestSuite struct {
	jobTaskSvc      *mockJobTaskSvc
	domainPublisher *mockDomainEventPublisher
	logger          *logger.Logger
	tracer          trace.Tracer
	tracker         *executionTracker
}

func newTrackerTestSuite(t *testing.T) *trackerTestSuite {
	t.Helper()

	jobTaskSvc := new(mockJobTaskSvc)
	domainPublisher := new(mockDomainEventPublisher)
	logger := logger.New(io.Discard, logger.LevelDebug, "test", nil)
	tracer := noop.NewTracerProvider().Tracer("test")

	return &trackerTestSuite{
		jobTaskSvc:      jobTaskSvc,
		domainPublisher: domainPublisher,
		logger:          logger,
		tracer:          tracer,
		tracker:         NewExecutionTracker("test-controller", jobTaskSvc, domainPublisher, logger, tracer),
	}
}

func TestExecutionTracker_AssociateEnumeratedTargetsToJob(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(*mockJobTaskSvc)
		jobID     uuid.UUID
		targetIDs []uuid.UUID
		wantErr   bool
	}{
		{
			name: "successful target linking and task increment",
			setup: func(m *mockJobTaskSvc) {
				m.On("AssociateEnumeratedTargets", mock.Anything, mock.Anything, mock.Anything).
					Return(nil)
			},
			jobID: uuid.New(),
			targetIDs: []uuid.UUID{
				uuid.New(),
				uuid.New(),
			},
			wantErr: false,
		},
		{
			name: "linking failure",
			setup: func(m *mockJobTaskSvc) {
				m.On("AssociateEnumeratedTargets", mock.Anything, mock.Anything, mock.Anything).
					Return(errors.New("failed to link targets"))
			},
			jobID: uuid.New(),
			targetIDs: []uuid.UUID{
				uuid.New(),
				uuid.New(),
			},
			wantErr: true,
		},
		{
			name: "empty target list",
			setup: func(m *mockJobTaskSvc) {
				m.On("AssociateEnumeratedTargets", mock.Anything, mock.Anything, mock.MatchedBy(func(targets []uuid.UUID) bool {
					return len(targets) == 0
				})).Return(nil)
			},
			jobID:     uuid.New(),
			targetIDs: []uuid.UUID{},
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			suite := newTrackerTestSuite(t)
			tt.setup(suite.jobTaskSvc)

			err := suite.tracker.associateEnumeratedTargetsToJob(context.Background(), tt.jobID, tt.targetIDs)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			suite.jobTaskSvc.AssertExpectations(t)
		})
	}
}

func TestExecutionTracker_HandleEnumeratedScanTask(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(*mockJobTaskSvc, *mockDomainEventPublisher)
		jobID   uuid.UUID
		task    *scanning.Task
		auth    scanning.Auth
		meta    map[string]string
		wantErr bool
	}{
		{
			name: "successful task creation and event publish",
			setup: func(m *mockJobTaskSvc, p *mockDomainEventPublisher) {
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
			setup: func(m *mockJobTaskSvc, p *mockDomainEventPublisher) {
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
			setup: func(m *mockJobTaskSvc, p *mockDomainEventPublisher) {
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
			tt.setup(suite.jobTaskSvc, suite.domainPublisher)

			err := suite.tracker.handleEnumeratedScanTask(
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

			suite.jobTaskSvc.AssertExpectations(t)
			suite.domainPublisher.AssertExpectations(t)
		})
	}
}

func TestExecutionTracker_StartTracking(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(*mockJobTaskSvc)
		event   scanning.TaskStartedEvent
		wantErr bool
	}{
		{
			name: "successful task start",
			setup: func(m *mockJobTaskSvc) {
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
			setup: func(m *mockJobTaskSvc) {
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
			tt.setup(suite.jobTaskSvc)

			err := suite.tracker.HandleTaskStart(context.Background(), tt.event)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			suite.jobTaskSvc.AssertExpectations(t)
		})
	}
}

func TestExecutionTracker_UpdateProgress(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(*mockJobTaskSvc)
		event   scanning.TaskProgressedEvent
		wantErr bool
	}{
		{
			name: "successful progress update",
			setup: func(m *mockJobTaskSvc) {
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
			setup: func(m *mockJobTaskSvc) {
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
			tt.setup(suite.jobTaskSvc)

			err := suite.tracker.HandleTaskProgress(context.Background(), tt.event)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			suite.jobTaskSvc.AssertExpectations(t)
		})
	}
}

func TestHandleTaskPaused(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(*mockJobTaskSvc)
		event   scanning.TaskPausedEvent
		wantErr bool
	}{
		{
			name: "successful task pause",
			setup: func(m *mockJobTaskSvc) {
				m.On("PauseTask", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(new(scanning.Task), nil)
			},
			event: scanning.TaskPausedEvent{
				JobID:       uuid.New(),
				TaskID:      uuid.New(),
				Progress:    domain.Progress{},
				RequestedBy: "test-user",
			},
			wantErr: false,
		},
		{
			name: "pause task failure",
			setup: func(m *mockJobTaskSvc) {
				m.On("PauseTask", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(nil, errors.New("pause failed"))
			},
			event: scanning.TaskPausedEvent{
				JobID:       uuid.New(),
				TaskID:      uuid.New(),
				Progress:    domain.Progress{},
				RequestedBy: "test-user",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			suite := newTrackerTestSuite(t)
			tt.setup(suite.jobTaskSvc)

			err := suite.tracker.HandleTaskPaused(context.Background(), tt.event)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			suite.jobTaskSvc.AssertExpectations(t)
		})
	}
}

func TestExecutionTracker_FullScanningLifecycle(t *testing.T) {
	suite := newTrackerTestSuite(t)
	jobID := uuid.New()
	taskID := uuid.New()
	resourceURI := "https://example.com"

	// Setup expectations for the full lifecycle.
	suite.jobTaskSvc.On("StartTask", mock.Anything, taskID, resourceURI).
		Return(nil)
	suite.jobTaskSvc.On("UpdateTaskProgress", mock.Anything, mock.Anything).
		Return(new(scanning.Task), nil).Times(3)
	suite.jobTaskSvc.On("CompleteTask", mock.Anything, taskID).
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

	suite.jobTaskSvc.AssertExpectations(t)
}

func TestExecutionTracker_StopTracking(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(*mockJobTaskSvc)
		event   scanning.TaskCompletedEvent
		wantErr bool
	}{
		{
			name: "successful task completion",
			setup: func(m *mockJobTaskSvc) {
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
			setup: func(m *mockJobTaskSvc) {
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
			tt.setup(suite.jobTaskSvc)

			err := suite.tracker.HandleTaskCompletion(context.Background(), tt.event)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			suite.jobTaskSvc.AssertExpectations(t)
		})
	}
}

func TestExecutionTracker_MarkTaskFailure(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(*mockJobTaskSvc)
		event   scanning.TaskFailedEvent
		wantErr bool
	}{
		{
			name: "successful task failure marking",
			setup: func(m *mockJobTaskSvc) {
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
			setup: func(m *mockJobTaskSvc) {
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
			tt.setup(suite.jobTaskSvc)

			err := suite.tracker.HandleTaskFailure(context.Background(), tt.event)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			suite.jobTaskSvc.AssertExpectations(t)
		})
	}
}

func TestExecutionTracker_HandleTaskCancelled(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(*mockJobTaskSvc)
		event   scanning.TaskCancelledEvent
		wantErr bool
	}{
		{
			name: "successful task cancellation",
			setup: func(m *mockJobTaskSvc) {
				m.On("CancelTask", mock.Anything, mock.Anything, mock.Anything).
					Return(new(scanning.Task), nil)
			},
			event: scanning.TaskCancelledEvent{
				JobID:       uuid.New(),
				TaskID:      uuid.New(),
				RequestedBy: "test-user",
			},
			wantErr: false,
		},
		{
			name: "error cancelling task",
			setup: func(m *mockJobTaskSvc) {
				m.On("CancelTask", mock.Anything, mock.Anything, mock.Anything).
					Return(nil, errors.New("cancellation failed"))
			},
			event: scanning.TaskCancelledEvent{
				JobID:       uuid.New(),
				TaskID:      uuid.New(),
				RequestedBy: "test-user",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			suite := newTrackerTestSuite(t)
			tt.setup(suite.jobTaskSvc)

			err := suite.tracker.HandleTaskCancelled(context.Background(), tt.event)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			suite.jobTaskSvc.AssertExpectations(t)
		})
	}
}

func TestExecutionTracker_MarkTaskStale(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(*mockJobTaskSvc, *mockDomainEventPublisher)
		event   scanning.TaskStaleEvent
		wantErr bool
	}{
		{
			name: "successful stale task marking",
			setup: func(m *mockJobTaskSvc, p *mockDomainEventPublisher) {
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
			setup: func(m *mockJobTaskSvc, p *mockDomainEventPublisher) {
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
			setup: func(m *mockJobTaskSvc, p *mockDomainEventPublisher) {
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
			tt.setup(suite.jobTaskSvc, suite.domainPublisher)

			err := suite.tracker.HandleTaskStale(context.Background(), tt.event)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			suite.jobTaskSvc.AssertExpectations(t)
			suite.domainPublisher.AssertExpectations(t)
		})
	}
}
