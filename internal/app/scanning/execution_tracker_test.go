package scanning

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	domain "github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
	"github.com/ahrav/gitleaks-armada/pkg/common/uuid"
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
				m.On("AssociateEnumeratedTargets", mock.Anything, mock.MatchedBy(func(cmd domain.AssociateEnumeratedTargetsCommand) bool {
					return len(cmd.TargetIDs) > 0
				})).Return(nil)
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
				m.On("AssociateEnumeratedTargets", mock.Anything, mock.Anything).
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
				m.On("AssociateEnumeratedTargets", mock.Anything, mock.MatchedBy(func(cmd domain.AssociateEnumeratedTargetsCommand) bool {
					return len(cmd.TargetIDs) == 0
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

func TestExecutionTracker_ProcessEnumerationStream(t *testing.T) {
	tests := []struct {
		name           string
		setup          func(*mockJobTaskSvc, *mockDomainEventPublisher)
		jobID          uuid.UUID
		scanningResult func() *scanning.ScanningResult
		simulateData   func(chan []uuid.UUID, chan scanning.TranslationResult, chan error)
		wantErr        bool
	}{
		{
			name: "successful enumeration processing with targets and tasks",
			setup: func(m *mockJobTaskSvc, p *mockDomainEventPublisher) {
				// Signal enumeration starting.
				m.On("UpdateJobStatus", mock.Anything, mock.Anything, domain.JobStatusEnumerating).Return(nil)
				// Process scan targets.
				m.On("AssociateEnumeratedTargets", mock.Anything, mock.MatchedBy(func(cmd domain.AssociateEnumeratedTargetsCommand) bool {
					return len(cmd.TargetIDs) > 0
				})).Return(nil)
				// Process tasks - expect TaskCreatedEvent for each task.
				m.On("CreateTask", mock.Anything, mock.Anything).Return(nil)
				p.On("PublishDomainEvent",
					mock.Anything,
					mock.AnythingOfType("*scanning.TaskCreatedEvent"),
					mock.Anything).Return(nil).Times(2) // Expect this to be called twice for our two tasks
				// Signal enumeration completion - expect JobEnumerationCompletedEvent.
				m.On("CompleteEnumeration", mock.Anything, mock.Anything).Return(&domain.JobMetrics{}, nil)
				p.On("PublishDomainEvent",
					mock.Anything,
					mock.AnythingOfType("scanning.JobEnumerationCompletedEvent"),
					mock.Anything).Return(nil).Once()
			},
			jobID: uuid.New(),
			scanningResult: func() *scanning.ScanningResult {
				return &scanning.ScanningResult{Auth: scanning.Auth{}, Metadata: map[string]string{"key": "value"}}
			},
			simulateData: func(targetCh chan []uuid.UUID, taskCh chan scanning.TranslationResult, errCh chan error) {
				targetCh <- []uuid.UUID{uuid.New(), uuid.New()}
				taskCh <- scanning.TranslationResult{
					Task: scanning.NewScanTask(uuid.New(), shared.SourceTypeGitHub, uuid.New(), "https://example.com/repo1"),
				}
				taskCh <- scanning.TranslationResult{
					Task: scanning.NewScanTask(uuid.New(), shared.SourceTypeGitHub, uuid.New(), "https://example.com/repo2"),
				}

				// Close channels to signal completion.
				close(targetCh)
				close(taskCh)
				close(errCh)
			},
			wantErr: false,
		},
		{
			name: "error from enumeration error channel",
			setup: func(m *mockJobTaskSvc, p *mockDomainEventPublisher) {
				// Signal enumeration starting.
				m.On("UpdateJobStatus", mock.Anything, mock.Anything, domain.JobStatusEnumerating).Return(nil)
				// We expect no further calls since we'll error early.
			},
			jobID: uuid.New(),
			scanningResult: func() *scanning.ScanningResult {
				return &scanning.ScanningResult{Auth: scanning.Auth{}, Metadata: map[string]string{"key": "value"}}
			},
			simulateData: func(targetCh chan []uuid.UUID, taskCh chan scanning.TranslationResult, errCh chan error) {
				errCh <- errors.New("enumeration failed")

				// Close channels to prevent test from hanging.
				close(targetCh)
				close(taskCh)
				close(errCh)
			},
			wantErr: true,
		},
		{
			name: "error when linking scan targets",
			setup: func(m *mockJobTaskSvc, p *mockDomainEventPublisher) {
				// Signal enumeration starting.
				m.On("UpdateJobStatus", mock.Anything, mock.Anything, domain.JobStatusEnumerating).Return(nil)

				// Return error when trying to link scan targets.
				m.On("AssociateEnumeratedTargets", mock.Anything, mock.Anything).
					Return(errors.New("link failed"))
			},
			jobID: uuid.New(),
			scanningResult: func() *scanning.ScanningResult {
				return &scanning.ScanningResult{Auth: scanning.Auth{}, Metadata: map[string]string{"key": "value"}}
			},
			simulateData: func(targetCh chan []uuid.UUID, taskCh chan scanning.TranslationResult, errCh chan error) {
				// Send data that will trigger the error.
				targetCh <- []uuid.UUID{uuid.New()}

				// Close channels to prevent test from hanging
				close(targetCh)
				close(taskCh)
				close(errCh)
			},
			wantErr: true,
		},
		{
			name: "error when creating task",
			setup: func(m *mockJobTaskSvc, p *mockDomainEventPublisher) {
				// Signal enumeration starting.
				m.On("UpdateJobStatus", mock.Anything, mock.Anything, domain.JobStatusEnumerating).Return(nil)
				// Process scan targets successful.
				m.On("AssociateEnumeratedTargets", mock.Anything, mock.MatchedBy(func(cmd domain.AssociateEnumeratedTargetsCommand) bool {
					return true
				})).Return(nil)
				// Return error when creating task.
				m.On("CreateTask", mock.Anything, mock.Anything).
					Return(errors.New("task creation failed"))
			},
			jobID: uuid.New(),
			scanningResult: func() *scanning.ScanningResult {
				return &scanning.ScanningResult{Auth: scanning.Auth{}, Metadata: map[string]string{"key": "value"}}
			},
			simulateData: func(targetCh chan []uuid.UUID, taskCh chan scanning.TranslationResult, errCh chan error) {
				// Send data that passes linking but fails on task creation.
				targetCh <- []uuid.UUID{uuid.New()}
				taskCh <- scanning.TranslationResult{
					Task: scanning.NewScanTask(uuid.New(), shared.SourceTypeGitHub, uuid.New(), "https://example.com/repo"),
				}

				// Close channels to prevent test from hanging.
				close(targetCh)
				close(taskCh)
				close(errCh)
			},
			wantErr: true,
		},
		{
			name: "error when publishing task event",
			setup: func(m *mockJobTaskSvc, p *mockDomainEventPublisher) {
				// Signal enumeration starting.
				m.On("UpdateJobStatus", mock.Anything, mock.Anything, domain.JobStatusEnumerating).Return(nil)
				// Process scan targets successful.
				m.On("AssociateEnumeratedTargets", mock.Anything, mock.MatchedBy(func(cmd domain.AssociateEnumeratedTargetsCommand) bool {
					return true
				})).Return(nil)
				// Task creation successful but event publish fails.
				m.On("CreateTask", mock.Anything, mock.Anything).Return(nil)
				p.On("PublishDomainEvent",
					mock.Anything,
					mock.AnythingOfType("*scanning.TaskCreatedEvent"),
					mock.Anything).Return(errors.New("event publish failed")).Once()
			},
			jobID: uuid.New(),
			scanningResult: func() *scanning.ScanningResult {
				return &scanning.ScanningResult{Auth: scanning.Auth{}, Metadata: map[string]string{"key": "value"}}
			},
			simulateData: func(targetCh chan []uuid.UUID, taskCh chan scanning.TranslationResult, errCh chan error) {
				// Send data that passes task creation but fails on event publishing.
				targetCh <- []uuid.UUID{uuid.New()}
				taskCh <- scanning.TranslationResult{
					Task: scanning.NewScanTask(uuid.New(), shared.SourceTypeGitHub, uuid.New(), "https://example.com/repo"),
				}

				// Close channels to prevent test from hanging.
				close(targetCh)
				close(taskCh)
				close(errCh)
			},
			wantErr: true,
		},
		{
			name: "error at enumeration completion",
			setup: func(m *mockJobTaskSvc, p *mockDomainEventPublisher) {
				// Signal enumeration starting.
				m.On("UpdateJobStatus", mock.Anything, mock.Anything, domain.JobStatusEnumerating).Return(nil)
				// Complete enumeration fails.
				m.On("CompleteEnumeration", mock.Anything, mock.Anything).
					Return(nil, errors.New("completion failed"))
			},
			jobID: uuid.New(),
			scanningResult: func() *scanning.ScanningResult {
				return &scanning.ScanningResult{Auth: scanning.Auth{}, Metadata: map[string]string{"key": "value"}}
			},
			simulateData: func(targetCh chan []uuid.UUID, taskCh chan scanning.TranslationResult, errCh chan error) {
				// No data, just close channels to trigger completion.
				close(targetCh)
				close(taskCh)
				close(errCh)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			suite := newTrackerTestSuite(t)
			tt.setup(suite.jobTaskSvc, suite.domainPublisher)

			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()

			scanTargetsCh := make(chan []uuid.UUID)
			tasksCh := make(chan scanning.TranslationResult)
			errCh := make(chan error)

			scanResult := tt.scanningResult()
			scanResult.ScanTargetsCh = scanTargetsCh
			scanResult.TasksCh = tasksCh
			scanResult.ErrCh = errCh

			// Launch a goroutine to send test data through channels.
			go tt.simulateData(scanTargetsCh, tasksCh, errCh)

			err := suite.tracker.ProcessEnumerationStream(ctx, tt.jobID, scanResult)
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

func TestExecutionTracker_HandleEnumeratedScanTask(t *testing.T) {
	tests := []struct {
		name           string
		setup          func(*mockJobTaskSvc, *mockDomainEventPublisher)
		jobID          uuid.UUID
		task           *scanning.Task
		scanningResult *scanning.ScanningResult
		wantErr        bool
	}{
		{
			name: "successful task creation and event publish",
			setup: func(m *mockJobTaskSvc, p *mockDomainEventPublisher) {
				m.On("CreateTask", mock.Anything, mock.Anything).
					Return(nil)
				p.On("PublishDomainEvent", mock.Anything, mock.Anything, mock.Anything).
					Return(nil)
			},
			jobID: uuid.New(),
			task:  scanning.NewScanTask(uuid.New(), shared.SourceTypeGitHub, uuid.New(), "https://example.com"),
			scanningResult: &scanning.ScanningResult{
				Auth:     scanning.Auth{},
				Metadata: map[string]string{"key": "value"},
			},
			wantErr: false,
		},
		{
			name: "task creation failure",
			setup: func(m *mockJobTaskSvc, p *mockDomainEventPublisher) {
				m.On("CreateTask", mock.Anything, mock.Anything).
					Return(errors.New("creation failed"))
			},
			jobID: uuid.New(),
			task:  scanning.NewScanTask(uuid.New(), shared.SourceTypeGitHub, uuid.New(), "https://example.com"),
			scanningResult: &scanning.ScanningResult{
				Auth:     scanning.Auth{},
				Metadata: map[string]string{"key": "value"},
			},
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
			jobID: uuid.New(),
			task:  scanning.NewScanTask(uuid.New(), shared.SourceTypeGitHub, uuid.New(), "https://example.com"),
			scanningResult: &scanning.ScanningResult{
				Auth:     scanning.Auth{},
				Metadata: map[string]string{"key": "value"},
			},
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
				tt.scanningResult,
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
				m.On("PauseTask", mock.Anything, mock.MatchedBy(func(cmd domain.PauseTaskCommand) bool {
					return cmd.RequestedBy == "test-user"
				})).Return(new(scanning.Task), nil)
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
				m.On("PauseTask", mock.Anything, mock.Anything).
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
		setup   func(*mockJobTaskSvc, *mockDomainEventPublisher, uuid.UUID, uuid.UUID)
		event   scanning.TaskStaleEvent
		wantErr bool
	}{
		{
			name: "successful stale task marking",
			setup: func(m *mockJobTaskSvc, p *mockDomainEventPublisher, taskID, jobID uuid.UUID) {
				// First, mark the task as stale - prepare a return value for MarkTaskStale.
				task := domain.ReconstructTask(
					taskID,
					jobID,
					"https://example.com/repo",
					domain.TaskStatusStale,
					5,           // lastSequenceNum
					time.Now(),  // lastHeartbeatAt
					time.Now(),  // startTime
					time.Time{}, // endTime
					100,         // itemsProcessed
					nil,         // progressDetails
					domain.NewCheckpoint(taskID, []byte(`{"position":"HEAD"}`), nil), // checkpoint
					func() *domain.StallReason { // stallReason
						r := domain.StallReasonNoProgress
						return &r
					}(),
					time.Now(),  // stalledAt
					time.Time{}, // pausedAt
					0,           // recoveryAttempts
				)

				m.On("MarkTaskStale", mock.Anything, taskID, mock.Anything).
					Return(task, nil)

				// Second, get job configuration info - prepare return value for GetJobConfigInfo.
				m.On("GetJobConfigInfo", mock.Anything, jobID).
					Return(domain.NewJobConfigInfo(
						jobID,
						shared.SourceTypeGitHub.String(),
						json.RawMessage(`{"auth":{"type":"token","token":"test-token"}}`),
					), nil)

				// Finally, expect a call to publish the resume event.
				p.On("PublishDomainEvent",
					mock.Anything,
					mock.MatchedBy(func(event events.DomainEvent) bool {
						resumeEvent, ok := event.(*domain.TaskResumeEvent)
						return ok &&
							resumeEvent.SourceType == shared.SourceTypeGitHub &&
							resumeEvent.SequenceNum == 5
					}),
					mock.Anything,
				).Return(nil)
			},
			event: func() scanning.TaskStaleEvent {
				taskID := uuid.New()
				jobID := uuid.New()
				return scanning.TaskStaleEvent{
					JobID:        jobID,
					TaskID:       taskID,
					Reason:       scanning.StallReasonNoProgress,
					StalledSince: time.Now(),
				}
			}(),
			wantErr: false,
		},
		{
			name: "error marking task as stale",
			setup: func(m *mockJobTaskSvc, p *mockDomainEventPublisher, taskID, jobID uuid.UUID) {
				m.On("MarkTaskStale", mock.Anything, taskID, mock.Anything).
					Return(nil, errors.New("stale marking failed"))

				// Need to add this since the concurrent call will still happen
				m.On("GetJobConfigInfo", mock.Anything, jobID).
					Return(domain.NewJobConfigInfo(
						jobID,
						shared.SourceTypeGitHub.String(),
						json.RawMessage(`{"auth":{"type":"token","token":"test-token"}}`),
					), nil)
			},
			event: func() scanning.TaskStaleEvent {
				taskID := uuid.New()
				jobID := uuid.New()
				return scanning.TaskStaleEvent{
					JobID:        jobID,
					TaskID:       taskID,
					Reason:       scanning.StallReasonNoProgress,
					StalledSince: time.Now(),
				}
			}(),
			wantErr: true,
		},
		{
			name: "error getting job config info",
			setup: func(m *mockJobTaskSvc, p *mockDomainEventPublisher, taskID, jobID uuid.UUID) {
				task := domain.ReconstructTask(
					taskID,
					jobID,
					"https://example.com/repo",
					domain.TaskStatusStale,
					5,           // lastSequenceNum
					time.Now(),  // lastHeartbeatAt
					time.Now(),  // startTime
					time.Time{}, // endTime
					100,         // itemsProcessed
					nil,         // progressDetails
					nil,         // checkpoint
					func() *domain.StallReason { // stallReason
						r := domain.StallReasonNoProgress
						return &r
					}(),
					time.Now(),  // stalledAt
					time.Time{}, // pausedAt
					0,           // recoveryAttempts
				)

				m.On("MarkTaskStale", mock.Anything, taskID, mock.Anything).
					Return(task, nil)

				m.On("GetJobConfigInfo", mock.Anything, jobID).
					Return(nil, errors.New("config info retrieval failed"))
			},
			event: func() scanning.TaskStaleEvent {
				taskID := uuid.New()
				jobID := uuid.New()
				return scanning.TaskStaleEvent{
					JobID:        jobID,
					TaskID:       taskID,
					Reason:       scanning.StallReasonNoProgress,
					StalledSince: time.Now(),
				}
			}(),
			wantErr: true,
		},
		{
			name: "error publishing resume event",
			setup: func(m *mockJobTaskSvc, p *mockDomainEventPublisher, taskID, jobID uuid.UUID) {
				task := domain.ReconstructTask(
					taskID,
					jobID,
					"https://example.com/repo",
					domain.TaskStatusStale,
					5,           // lastSequenceNum
					time.Now(),  // lastHeartbeatAt
					time.Now(),  // startTime
					time.Time{}, // endTime
					100,         // itemsProcessed
					nil,         // progressDetails
					nil,         // checkpoint
					func() *domain.StallReason { // stallReason
						r := domain.StallReasonNoProgress
						return &r
					}(),
					time.Now(),  // stalledAt
					time.Time{}, // pausedAt
					0,           // recoveryAttempts
				)

				m.On("MarkTaskStale", mock.Anything, taskID, mock.Anything).
					Return(task, nil)

				m.On("GetJobConfigInfo", mock.Anything, jobID).
					Return(domain.NewJobConfigInfo(
						jobID,
						shared.SourceTypeGitHub.String(),
						json.RawMessage(`{"auth":{"type":"token","token":"test-token"}}`),
					), nil)

				p.On("PublishDomainEvent",
					mock.Anything,
					mock.Anything,
					mock.Anything,
				).Return(errors.New("publish failed"))
			},
			event: func() scanning.TaskStaleEvent {
				taskID := uuid.New()
				jobID := uuid.New()
				return scanning.TaskStaleEvent{
					JobID:        jobID,
					TaskID:       taskID,
					Reason:       scanning.StallReasonNoProgress,
					StalledSince: time.Now(),
				}
			}(),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			suite := newTrackerTestSuite(t)
			tt.setup(suite.jobTaskSvc, suite.domainPublisher, tt.event.TaskID, tt.event.JobID)

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
