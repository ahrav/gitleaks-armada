package scanning

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	domain "github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
	"github.com/ahrav/gitleaks-armada/pkg/common/uuid"
)

// mockJobRepository helps test coordinator interactions with job persistence.
type mockJobRepository struct{ mock.Mock }

func (m *mockJobRepository) CreateJob(ctx context.Context, job *scanning.Job) error {
	return m.Called(ctx, job).Error(0)
}

func (m *mockJobRepository) UpdateJob(ctx context.Context, job *scanning.Job) error {
	return m.Called(ctx, job).Error(0)
}

func (m *mockJobRepository) AssociateTargets(ctx context.Context, jobID uuid.UUID, targetIDs []uuid.UUID) error {
	return m.Called(ctx, jobID, targetIDs).Error(0)
}

func (m *mockJobRepository) IncrementTotalTasks(ctx context.Context, jobID uuid.UUID, amount int) error {
	return m.Called(ctx, jobID, amount).Error(0)
}

func (m *mockJobRepository) GetJob(ctx context.Context, jobID uuid.UUID) (*scanning.Job, error) {
	args := m.Called(ctx, jobID)
	if job := args.Get(0); job != nil {
		return job.(*scanning.Job), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockJobRepository) GetJobConfigInfo(ctx context.Context, jobID uuid.UUID) (*scanning.JobConfigInfo, error) {
	args := m.Called(ctx, jobID)
	if configInfo := args.Get(0); configInfo != nil {
		return configInfo.(*scanning.JobConfigInfo), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockJobRepository) BulkUpdateJobMetrics(ctx context.Context, updates map[uuid.UUID]*domain.JobMetrics) (int64, error) {
	return 0, nil
}

func (m *mockJobRepository) GetJobMetrics(ctx context.Context, jobID uuid.UUID) (*scanning.JobMetrics, error) {
	args := m.Called(ctx, jobID)
	if metrics := args.Get(0); metrics != nil {
		return metrics.(*scanning.JobMetrics), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockJobRepository) StoreCheckpoint(ctx context.Context, jobID uuid.UUID, partitionID int32, offset int64) error {
	return m.Called(ctx, jobID, partitionID, offset).Error(0)
}

func (m *mockJobRepository) GetCheckpoints(ctx context.Context, jobID uuid.UUID) (map[int32]int64, error) {
	args := m.Called(ctx, jobID)
	if checkpoints := args.Get(0); checkpoints != nil {
		return checkpoints.(map[int32]int64), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockJobRepository) UpdateMetricsAndCheckpoint(ctx context.Context, jobID uuid.UUID, metrics *domain.JobMetrics, partitionID int32, offset int64) error {
	return m.Called(ctx, jobID, metrics, partitionID, offset).Error(0)
}

// mockTaskRepository helps test coordinator interactions with task persistence.
type mockTaskRepository struct {
	mock.Mock
}

func (m *mockTaskRepository) CreateTask(ctx context.Context, task *scanning.Task, controllerID string) error {
	return m.Called(ctx, task).Error(0)
}

func (m *mockTaskRepository) GetTask(ctx context.Context, taskID uuid.UUID) (*scanning.Task, error) {
	args := m.Called(ctx, taskID)
	if task := args.Get(0); task != nil {
		return task.(*scanning.Task), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockTaskRepository) GetTaskSourceType(ctx context.Context, taskID uuid.UUID) (shared.SourceType, error) {
	args := m.Called(ctx, taskID)
	return args.Get(0).(shared.SourceType), args.Error(1)
}

func (m *mockTaskRepository) UpdateTask(ctx context.Context, task *scanning.Task) error {
	return m.Called(ctx, task).Error(0)
}

func (m *mockTaskRepository) ListTasksByJobAndStatus(ctx context.Context, jobID uuid.UUID, status scanning.TaskStatus) ([]*scanning.Task, error) {
	args := m.Called(ctx, jobID, status)
	return args.Get(0).([]*scanning.Task), args.Error(1)
}

func (m *mockTaskRepository) FindStaleTasks(ctx context.Context, controllerID string, cutoff time.Time) ([]scanning.StaleTaskInfo, error) {
	args := m.Called(ctx, controllerID, cutoff)
	return args.Get(0).([]scanning.StaleTaskInfo), args.Error(1)
}

func (m *mockTaskRepository) BatchUpdateHeartbeats(ctx context.Context, heartbeats map[uuid.UUID]time.Time) (int64, error) {
	args := m.Called(ctx, heartbeats)
	return args.Get(0).(int64), args.Error(1)
}

func (m *mockTaskRepository) GetTasksToResume(ctx context.Context, jobID uuid.UUID) ([]scanning.ResumeTaskInfo, error) {
	args := m.Called(ctx, jobID)
	return args.Get(0).([]scanning.ResumeTaskInfo), args.Error(1)
}

func newJobTaskService(t *testing.T) *jobTaskService {
	t.Helper()
	jobRepo := new(mockJobRepository)
	taskRepo := new(mockTaskRepository)
	tracer := noop.NewTracerProvider().Tracer("test")
	return NewJobTaskService("test", jobRepo, taskRepo, logger.Noop(), tracer)
}

func TestCreateJob(t *testing.T) {
	tests := []struct {
		name    string
		cmd     domain.CreateJobCommand
		setup   func(*mockJobRepository)
		wantErr bool
	}{
		{
			name: "successful job creation",
			cmd: domain.CreateJobCommand{
				JobID:      uuid.New(),
				SourceType: "github",
				Config:     json.RawMessage(`{"token": "test-token"}`),
			},
			setup: func(repo *mockJobRepository) {
				repo.On("CreateJob", mock.Anything, mock.MatchedBy(func(job *scanning.Job) bool {
					return job.Status() == scanning.JobStatusQueued &&
						job.SourceType() == "github" &&
						string(job.Config()) == `{"token": "test-token"}`
				})).Return(nil)
			},
			wantErr: false,
		},
		{
			name: "repository error",
			cmd: domain.CreateJobCommand{
				JobID:      uuid.New(),
				SourceType: "github",
				Config:     json.RawMessage(`{}`),
			},
			setup: func(repo *mockJobRepository) {
				repo.On("CreateJob", mock.Anything, mock.Anything).
					Return(assert.AnError)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			suite := newJobTaskService(t)
			tt.setup(suite.jobRepo.(*mockJobRepository))

			err := suite.CreateJob(context.Background(), tt.cmd)
			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			suite.jobRepo.(*mockJobRepository).AssertExpectations(t)
		})
	}
}

func TestAssociateEnumeratedTargets(t *testing.T) {
	jobID := uuid.MustParse("429735d7-ec1b-4d96-8749-938ca0a744be")
	targetIDs := []uuid.UUID{
		uuid.MustParse("b1f7eff4-2921-4e6c-9d88-da2de5707a2b"),
		uuid.MustParse("c2f8eff4-3922-4e6c-9d88-da2de5707a2c"),
	}
	cmd := domain.NewAssociateEnumeratedTargetsCommand(jobID, targetIDs)

	tests := []struct {
		name    string
		setup   func(*mockJobRepository)
		wantErr bool
	}{
		{
			name: "successful target association and task count increment",
			setup: func(repo *mockJobRepository) {
				// Expect target association.
				repo.On("AssociateTargets", mock.Anything, jobID, targetIDs).
					Return(nil)

				// Expect task count increment.
				repo.On("IncrementTotalTasks", mock.Anything, jobID, len(targetIDs)).
					Return(nil)
			},
			wantErr: false,
		},
		{
			name: "target association fails",
			setup: func(repo *mockJobRepository) {
				repo.On("AssociateTargets", mock.Anything, jobID, targetIDs).
					Return(assert.AnError)
			},
			wantErr: true,
		},
		{
			name: "task count increment fails",
			setup: func(repo *mockJobRepository) {
				repo.On("AssociateTargets", mock.Anything, jobID, targetIDs).
					Return(nil)

				repo.On("IncrementTotalTasks", mock.Anything, jobID, len(targetIDs)).
					Return(assert.AnError)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			suite := newJobTaskService(t)
			tt.setup(suite.jobRepo.(*mockJobRepository))

			err := suite.AssociateEnumeratedTargets(context.Background(), cmd)
			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			suite.jobRepo.(*mockJobRepository).AssertExpectations(t)
		})
	}
}

func TestGetJobConfigInfo(t *testing.T) {
	jobID := uuid.MustParse("429735d7-ec1b-4d96-8749-938ca0a744be")

	tests := []struct {
		name    string
		setup   func(*mockJobRepository)
		wantErr bool
	}{
		{
			name: "successfully get job config info",
			setup: func(repo *mockJobRepository) {
				configInfo := domain.NewJobConfigInfo(
					jobID,
					shared.SourceTypeGitHub.String(),
					json.RawMessage(`{"test_key":"test_value"}`),
				)
				repo.On("GetJobConfigInfo", mock.Anything, jobID).
					Return(configInfo, nil)
			},
			wantErr: false,
		},
		{
			name: "repository error",
			setup: func(repo *mockJobRepository) {
				repo.On("GetJobConfigInfo", mock.Anything, jobID).
					Return(nil, assert.AnError)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			suite := newJobTaskService(t)
			tt.setup(suite.jobRepo.(*mockJobRepository))

			configInfo, err := suite.GetJobConfigInfo(context.Background(), jobID)
			if tt.wantErr {
				require.Error(t, err)
				require.Nil(t, configInfo)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, configInfo)
			assert.Equal(t, jobID, configInfo.JobID())
			assert.Equal(t, shared.SourceTypeGitHub, configInfo.SourceType())
			assert.NotEmpty(t, configInfo.Config())
			suite.jobRepo.(*mockJobRepository).AssertExpectations(t)
		})
	}
}

func TestUpdateJobStatus(t *testing.T) {
	tests := []struct {
		name          string
		setup         func(*mockJobRepository)
		initialStatus domain.JobStatus
		targetStatus  domain.JobStatus
		wantErr       bool
	}{
		{
			name: "valid transition from queued to enumerating",
			setup: func(repo *mockJobRepository) {
				job := domain.NewJobWithStatus(uuid.New(), domain.JobStatusQueued)
				repo.On("GetJob", mock.Anything, mock.Anything).Return(job, nil)
				repo.On("UpdateJob", mock.Anything, mock.MatchedBy(func(j *domain.Job) bool {
					return j.Status() == domain.JobStatusEnumerating
				})).Return(nil)
			},
			initialStatus: domain.JobStatusQueued,
			targetStatus:  domain.JobStatusEnumerating,
			wantErr:       false,
		},
		{
			name: "valid transition from enumerating to running",
			setup: func(repo *mockJobRepository) {
				job := domain.NewJobWithStatus(uuid.New(), domain.JobStatusEnumerating)
				repo.On("GetJob", mock.Anything, mock.Anything).Return(job, nil)
				repo.On("UpdateJob", mock.Anything, mock.MatchedBy(func(j *domain.Job) bool {
					return j.Status() == domain.JobStatusRunning
				})).Return(nil)
			},
			initialStatus: domain.JobStatusEnumerating,
			targetStatus:  domain.JobStatusRunning,
			wantErr:       false,
		},
		{
			name: "valid transition from enumerating to failed",
			setup: func(repo *mockJobRepository) {
				job := domain.NewJobWithStatus(uuid.New(), domain.JobStatusEnumerating)
				repo.On("GetJob", mock.Anything, mock.Anything).Return(job, nil)
				repo.On("UpdateJob", mock.Anything, mock.MatchedBy(func(j *domain.Job) bool {
					return j.Status() == domain.JobStatusFailed
				})).Return(nil)
			},
			initialStatus: domain.JobStatusEnumerating,
			targetStatus:  domain.JobStatusFailed,
			wantErr:       false,
		},
		{
			name: "valid transition from running to completed",
			setup: func(repo *mockJobRepository) {
				job := domain.NewJobWithStatus(uuid.New(), domain.JobStatusRunning)
				repo.On("GetJob", mock.Anything, mock.Anything).Return(job, nil)
				repo.On("UpdateJob", mock.Anything, mock.MatchedBy(func(j *domain.Job) bool {
					return j.Status() == domain.JobStatusCompleted
				})).Return(nil)
			},
			initialStatus: domain.JobStatusRunning,
			targetStatus:  domain.JobStatusCompleted,
			wantErr:       false,
		},
		{
			name: "valid transition from running to failed",
			setup: func(repo *mockJobRepository) {
				job := domain.NewJobWithStatus(uuid.New(), domain.JobStatusRunning)
				repo.On("GetJob", mock.Anything, mock.Anything).Return(job, nil)
				repo.On("UpdateJob", mock.Anything, mock.MatchedBy(func(j *domain.Job) bool {
					return j.Status() == domain.JobStatusFailed
				})).Return(nil)
			},
			initialStatus: domain.JobStatusRunning,
			targetStatus:  domain.JobStatusFailed,
			wantErr:       false,
		},
		{
			name: "invalid transition from completed to running",
			setup: func(repo *mockJobRepository) {
				job := domain.NewJobWithStatus(uuid.New(), domain.JobStatusCompleted)
				repo.On("GetJob", mock.Anything, mock.Anything).Return(job, nil)
			},
			initialStatus: domain.JobStatusCompleted,
			targetStatus:  domain.JobStatusRunning,
			wantErr:       true,
		},
		{
			name: "invalid transition from failed to completed",
			setup: func(repo *mockJobRepository) {
				job := domain.NewJobWithStatus(uuid.New(), domain.JobStatusFailed)
				repo.On("GetJob", mock.Anything, mock.Anything).Return(job, nil)
			},
			initialStatus: domain.JobStatusFailed,
			targetStatus:  domain.JobStatusCompleted,
			wantErr:       true,
		},
		{
			name: "invalid transition from queued to running",
			setup: func(repo *mockJobRepository) {
				job := domain.NewJobWithStatus(uuid.New(), domain.JobStatusQueued)
				repo.On("GetJob", mock.Anything, mock.Anything).Return(job, nil)
			},
			initialStatus: domain.JobStatusQueued,
			targetStatus:  domain.JobStatusRunning,
			wantErr:       true,
		},
		{
			name: "repository update failure",
			setup: func(repo *mockJobRepository) {
				job := domain.NewJobWithStatus(uuid.New(), domain.JobStatusEnumerating)
				repo.On("GetJob", mock.Anything, mock.Anything).Return(job, nil)
				repo.On("UpdateJob", mock.Anything, mock.MatchedBy(func(j *domain.Job) bool {
					return j.Status() == domain.JobStatusRunning
				})).Return(assert.AnError)
			},
			initialStatus: domain.JobStatusEnumerating,
			targetStatus:  domain.JobStatusRunning,
			wantErr:       true,
		},
		{
			name: "job load failure",
			setup: func(repo *mockJobRepository) {
				repo.On("GetJob", mock.Anything, mock.Anything).Return(nil, assert.AnError)
			},
			initialStatus: domain.JobStatusEnumerating,
			targetStatus:  domain.JobStatusRunning,
			wantErr:       true,
		},

		{
			name: "valid transition from running to pausing",
			setup: func(repo *mockJobRepository) {
				job := domain.NewJobWithStatus(uuid.New(), domain.JobStatusRunning)
				repo.On("GetJob", mock.Anything, mock.Anything).Return(job, nil)
				repo.On("UpdateJob", mock.Anything, mock.MatchedBy(func(j *domain.Job) bool {
					return j.Status() == domain.JobStatusPausing
				})).Return(nil)
			},
			initialStatus: domain.JobStatusRunning,
			targetStatus:  domain.JobStatusPausing,
			wantErr:       false,
		},
		{
			name: "valid transition from pausing to paused",
			setup: func(repo *mockJobRepository) {
				job := domain.NewJobWithStatus(uuid.New(), domain.JobStatusPausing)
				repo.On("GetJob", mock.Anything, mock.Anything).Return(job, nil)
				repo.On("UpdateJob", mock.Anything, mock.MatchedBy(func(j *domain.Job) bool {
					return j.Status() == domain.JobStatusPaused
				})).Return(nil)
			},
			initialStatus: domain.JobStatusPausing,
			targetStatus:  domain.JobStatusPaused,
			wantErr:       false,
		},
		{
			name: "valid transition from paused to running",
			setup: func(repo *mockJobRepository) {
				job := domain.NewJobWithStatus(uuid.New(), domain.JobStatusPaused)
				repo.On("GetJob", mock.Anything, mock.Anything).Return(job, nil)
				repo.On("UpdateJob", mock.Anything, mock.MatchedBy(func(j *domain.Job) bool {
					return j.Status() == domain.JobStatusRunning
				})).Return(nil)
			},
			initialStatus: domain.JobStatusPaused,
			targetStatus:  domain.JobStatusRunning,
			wantErr:       false,
		},
		{
			name: "invalid transition from queued to pausing",
			setup: func(repo *mockJobRepository) {
				job := domain.NewJobWithStatus(uuid.New(), domain.JobStatusQueued)
				repo.On("GetJob", mock.Anything, mock.Anything).Return(job, nil)
			},
			initialStatus: domain.JobStatusQueued,
			targetStatus:  domain.JobStatusPausing,
			wantErr:       true,
		},

		{
			name: "valid transition from running to cancelling",
			setup: func(repo *mockJobRepository) {
				job := domain.NewJobWithStatus(uuid.New(), domain.JobStatusRunning)
				repo.On("GetJob", mock.Anything, mock.Anything).Return(job, nil)
				repo.On("UpdateJob", mock.Anything, mock.MatchedBy(func(j *domain.Job) bool {
					return j.Status() == domain.JobStatusCancelling
				})).Return(nil)
			},
			initialStatus: domain.JobStatusRunning,
			targetStatus:  domain.JobStatusCancelling,
			wantErr:       false,
		},
		{
			name: "valid transition from cancelling to cancelled",
			setup: func(repo *mockJobRepository) {
				job := domain.NewJobWithStatus(uuid.New(), domain.JobStatusCancelling)
				repo.On("GetJob", mock.Anything, mock.Anything).Return(job, nil)
				repo.On("UpdateJob", mock.Anything, mock.MatchedBy(func(j *domain.Job) bool {
					return j.Status() == domain.JobStatusCancelled
				})).Return(nil)
			},
			initialStatus: domain.JobStatusCancelling,
			targetStatus:  domain.JobStatusCancelled,
			wantErr:       false,
		},
		{
			name: "valid transition from paused to cancelling",
			setup: func(repo *mockJobRepository) {
				job := domain.NewJobWithStatus(uuid.New(), domain.JobStatusPaused)
				repo.On("GetJob", mock.Anything, mock.Anything).Return(job, nil)
				repo.On("UpdateJob", mock.Anything, mock.MatchedBy(func(j *domain.Job) bool {
					return j.Status() == domain.JobStatusCancelling
				})).Return(nil)
			},
			initialStatus: domain.JobStatusPaused,
			targetStatus:  domain.JobStatusCancelling,
			wantErr:       false,
		},
		{
			name: "valid transition from enumerating to cancelling",
			setup: func(repo *mockJobRepository) {
				job := domain.NewJobWithStatus(uuid.New(), domain.JobStatusEnumerating)
				repo.On("GetJob", mock.Anything, mock.Anything).Return(job, nil)
				repo.On("UpdateJob", mock.Anything, mock.MatchedBy(func(j *domain.Job) bool {
					return j.Status() == domain.JobStatusCancelling
				})).Return(nil)
			},
			initialStatus: domain.JobStatusEnumerating,
			targetStatus:  domain.JobStatusCancelling,
			wantErr:       false,
		},
		{
			name: "invalid transition from cancelled to running",
			setup: func(repo *mockJobRepository) {
				job := domain.NewJobWithStatus(uuid.New(), domain.JobStatusCancelled)
				repo.On("GetJob", mock.Anything, mock.Anything).Return(job, nil)
			},
			initialStatus: domain.JobStatusCancelled,
			targetStatus:  domain.JobStatusRunning,
			wantErr:       true,
		},
		{
			name: "invalid transition from cancelled to completed",
			setup: func(repo *mockJobRepository) {
				job := domain.NewJobWithStatus(uuid.New(), domain.JobStatusCancelled)
				repo.On("GetJob", mock.Anything, mock.Anything).Return(job, nil)
			},
			initialStatus: domain.JobStatusCancelled,
			targetStatus:  domain.JobStatusCompleted,
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			suite := newJobTaskService(t)
			tt.setup(suite.jobRepo.(*mockJobRepository))

			job := domain.NewJobWithStatus(uuid.New(), tt.initialStatus)
			err := suite.UpdateJobStatus(context.Background(), job.JobID(), tt.targetStatus)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			suite.jobRepo.(*mockJobRepository).AssertExpectations(t)
		})
	}
}

type mockTimeProvider struct {
	mu  sync.RWMutex
	now time.Time
}

func (m *mockTimeProvider) SetNow(duration time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.now = m.now.Add(duration)
}

func (m *mockTimeProvider) Now() time.Time {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.now
}

func (m *mockTimeProvider) Sleep(duration time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.now = m.now.Add(duration)
}

func TestStartTask(t *testing.T) {
	jobID := uuid.MustParse("429735d7-ec1b-4d96-8749-938ca0a744be")
	taskID := uuid.MustParse("b1f7eff4-2921-4e6c-9d88-da2de5707a2b")
	scannerID := uuid.MustParse("8b2b37e0-da29-4aef-9c24-9dc7b22cb329")

	tests := []struct {
		name      string
		setup     func(*mockTaskRepository)
		cmd       domain.StartTaskCommand
		wantErr   bool
		errorType interface{}
	}{
		{
			name: "successful task start",
			setup: func(repo *mockTaskRepository) {
				task := scanning.NewScanTask(
					jobID,
					shared.SourceTypeGitHub,
					taskID,
					"https://github.com/org/repo",
				)
				// Task should be in PENDING state initially.
				require.Equal(t, scanning.TaskStatusPending, task.Status())

				repo.On("GetTask", mock.Anything, taskID).Return(task, nil)
				repo.On("UpdateTask", mock.Anything, mock.MatchedBy(func(t *scanning.Task) bool {
					return t.Status() == scanning.TaskStatusInProgress &&
						t.HasScanner() &&
						*t.ScannerID() == scannerID
				})).Return(nil)
			},
			cmd: domain.StartTaskCommand{
				ScannerID:   scannerID,
				TaskID:      taskID,
				ResourceURI: "https://github.com/org/repo",
			},
			wantErr: false,
		},
		{
			name: "task already has scanner assigned",
			setup: func(repo *mockTaskRepository) {
				task := scanning.NewScanTask(
					jobID,
					shared.SourceTypeGitHub,
					taskID,
					"https://github.com/org/repo",
				)
				// Pre-assign a scanner - this is an invalid state.
				existingScannerId := uuid.New()
				err := task.SetScannerID(existingScannerId)
				require.NoError(t, err)

				repo.On("GetTask", mock.Anything, taskID).Return(task, nil)
			},
			cmd: domain.StartTaskCommand{
				ScannerID:   scannerID,
				TaskID:      taskID,
				ResourceURI: "https://github.com/org/repo",
			},
			wantErr:   true,
			errorType: scanning.TaskScannerAlreadyAssignedError{},
		},
		{
			name: "invalid state transition",
			setup: func(repo *mockTaskRepository) {
				task := scanning.NewScanTask(
					jobID,
					shared.SourceTypeGitHub,
					taskID,
					"https://github.com/org/repo",
				)
				// Set task to FAILED state - can't transition to IN_PROGRESS from FAILED.
				err := task.Fail()
				require.NoError(t, err)

				repo.On("GetTask", mock.Anything, mock.Anything).Return(task, nil)
			},
			cmd: domain.StartTaskCommand{
				ScannerID:   scannerID,
				TaskID:      taskID,
				ResourceURI: "https://github.com/org/repo",
			},
			wantErr:   true,
			errorType: scanning.TaskInvalidStateError{},
		},
		{
			name: "task not found",
			setup: func(repo *mockTaskRepository) {
				repo.On("GetTask", mock.Anything, mock.Anything).
					Return(nil, assert.AnError)
			},
			cmd: domain.StartTaskCommand{
				ScannerID:   scannerID,
				TaskID:      uuid.New(),
				ResourceURI: "https://github.com/org/repo",
			},
			wantErr: true,
		},
		{
			name: "update task fails",
			setup: func(repo *mockTaskRepository) {
				task := scanning.NewScanTask(
					jobID,
					shared.SourceTypeGitHub,
					taskID,
					"https://github.com/org/repo",
				)
				repo.On("GetTask", mock.Anything, mock.Anything).Return(task, nil)
				repo.On("UpdateTask", mock.Anything, mock.Anything).
					Return(assert.AnError)
			},
			cmd: domain.StartTaskCommand{
				ScannerID:   scannerID,
				TaskID:      taskID,
				ResourceURI: "https://github.com/org/repo",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			suite := newJobTaskService(t)
			tt.setup(suite.taskRepo.(*mockTaskRepository))

			err := suite.StartTask(context.Background(), tt.cmd)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errorType != nil {
					switch tt.errorType.(type) {
					case scanning.TaskScannerAlreadyAssignedError:
						var scannerErr scanning.TaskScannerAlreadyAssignedError
						require.True(t, errors.As(err, &scannerErr), "Expected error of type TaskScannerAlreadyAssignedError, got %T", err)
					case scanning.TaskInvalidStateError:
						var invalidStateErr scanning.TaskInvalidStateError
						require.True(t, errors.As(err, &invalidStateErr), "Expected error of type TaskInvalidStateError, got %T", err)
					default:
					}
				}
				return
			}

			require.NoError(t, err)
			suite.taskRepo.(*mockTaskRepository).AssertExpectations(t)
		})
	}
}

func TestUpdateTaskProgress(t *testing.T) {
	jobID := uuid.MustParse("c30b6e0a-25e9-4856-aada-5f2ad03718f2")
	taskID := uuid.MustParse("0ee1a5ba-2543-4ab8-8ceb-fba7aefd7947")

	tests := []struct {
		name    string
		setup   func(*mockTaskRepository, *scanning.Progress)
		wantErr bool
	}{
		{
			name: "successful progress update",
			setup: func(repo *mockTaskRepository, progress *scanning.Progress) {
				task := scanning.ReconstructTask(
					taskID,
					jobID,
					"test-resource-uri",
					scanning.TaskStatusInProgress,
					0,
					time.Now().Add(-2*time.Hour),
					time.Now().Add(-2*time.Hour),
					time.Now(),
					100,
					nil,
					nil,
					scanning.ReasonPtr(scanning.StallReasonNoProgress),
					time.Time{},
					time.Time{},
					0,
					uuid.New(),
				)

				repo.On("GetTask", mock.Anything, taskID).
					Return(task, nil)

				repo.On("UpdateTask", mock.Anything, mock.MatchedBy(func(t *scanning.Task) bool {
					return t.LastSequenceNum() == progress.SequenceNum()
				})).Return(nil)
			},
			wantErr: false,
		},
		{
			name: "task not found",
			setup: func(repo *mockTaskRepository, progress *scanning.Progress) {
				repo.On("GetTask", mock.Anything, taskID).
					Return(nil, assert.AnError)
			},
			wantErr: true,
		},
		{
			name: "task in completed state - progress update should fail",
			setup: func(repo *mockTaskRepository, progress *scanning.Progress) {
				task := scanning.ReconstructTask(
					taskID,
					jobID,
					"test-resource-uri",
					scanning.TaskStatusCompleted, // Task is already completed
					0,
					time.Now().Add(-2*time.Hour),
					time.Now().Add(-2*time.Hour),
					time.Now(),
					100,
					nil,
					nil,
					nil,
					time.Time{},
					time.Now(), // Completion time set
					0,
					uuid.New(),
				)

				repo.On("GetTask", mock.Anything, taskID).
					Return(task, nil)
				// No UpdateTask call expected since applying progress should fail
			},
			wantErr: true,
		},
		{
			name: "task in failed state - progress update should fail",
			setup: func(repo *mockTaskRepository, progress *scanning.Progress) {
				task := scanning.ReconstructTask(
					taskID,
					jobID,
					"test-resource-uri",
					scanning.TaskStatusFailed, // Task has failed
					0,
					time.Now().Add(-2*time.Hour),
					time.Now().Add(-2*time.Hour),
					time.Now(),
					100,
					nil,
					nil,
					nil,
					time.Time{},
					time.Time{},
					0,
					uuid.New(),
				)

				repo.On("GetTask", mock.Anything, taskID).
					Return(task, nil)
				// No UpdateTask call expected since applying progress should fail
			},
			wantErr: true,
		},
		{
			name: "task repository update fails",
			setup: func(repo *mockTaskRepository, progress *scanning.Progress) {
				task := scanning.ReconstructTask(
					taskID,
					jobID,
					"test-resource-uri",
					scanning.TaskStatusInProgress,
					0,
					time.Now().Add(-2*time.Hour),
					time.Now().Add(-2*time.Hour),
					time.Now(),
					100,
					nil,
					nil,
					nil,
					time.Time{},
					time.Time{},
					0,
					uuid.New(),
				)

				repo.On("GetTask", mock.Anything, taskID).
					Return(task, nil)

				repo.On("UpdateTask", mock.Anything, mock.MatchedBy(func(t *scanning.Task) bool {
					return t.LastSequenceNum() == progress.SequenceNum()
				})).Return(errors.New("database error"))
			},
			wantErr: true,
		},
		{
			name: "progress sequence number less than current task sequence",
			setup: func(repo *mockTaskRepository, progress *scanning.Progress) {
				task := scanning.ReconstructTask(
					taskID,
					jobID,
					"test-resource-uri",
					scanning.TaskStatusInProgress,
					2, // Task has already processed sequence 2
					time.Now().Add(-2*time.Hour),
					time.Now().Add(-2*time.Hour),
					time.Now(),
					100,
					nil,
					nil,
					nil,
					time.Time{},
					time.Time{},
					0,
					uuid.New(),
				)

				repo.On("GetTask", mock.Anything, taskID).
					Return(task, nil)

				// For this test, we need to create a new progress with seq num < current
				// No UpdateTask call expected since sequence is outdated.
			},
			wantErr: true, // Should return OutOfOrderProgressError.
		},
		{
			name: "paused task can receive progress updates, resumes task",
			setup: func(repo *mockTaskRepository, progress *scanning.Progress) {
				task := scanning.ReconstructTask(
					taskID,
					jobID,
					"test-resource-uri",
					scanning.TaskStatusPaused, // Task is paused
					0,
					time.Now().Add(-2*time.Hour),
					time.Now().Add(-2*time.Hour),
					time.Now(),
					50,
					nil,
					nil,
					nil,
					time.Time{},
					time.Now().Add(-1*time.Hour), // Paused 1 hour ago
					0,
					uuid.New(),
				)

				repo.On("GetTask", mock.Anything, taskID).
					Return(task, nil)

				repo.On("UpdateTask", mock.Anything, mock.MatchedBy(func(t *scanning.Task) bool {
					return t.LastSequenceNum() == progress.SequenceNum() &&
						t.Status() == scanning.TaskStatusInProgress
				})).Return(nil)
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			suite := newJobTaskService(t)
			progress := scanning.NewProgress(
				taskID,
				jobID,
				1,
				time.Now(),
				100,
				0,
				"processing",
				nil,
				nil,
			)

			tt.setup(suite.taskRepo.(*mockTaskRepository), &progress)

			task, err := suite.UpdateTaskProgress(context.Background(), progress)
			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.NotNil(t, task)
			assert.Equal(t, int64(1), task.LastSequenceNum())
			suite.taskRepo.(*mockTaskRepository).AssertExpectations(t)
		})
	}
}

func TestPauseTask(t *testing.T) {
	tests := []struct {
		name        string
		taskID      uuid.UUID
		progress    domain.Progress
		requestedBy string
		setupTask   func(*scanning.Task)
		mockSetup   func(*mockTaskRepository)
		wantErr     bool
	}{
		{
			name:        "successful pause with progress",
			taskID:      uuid.New(),
			requestedBy: "test-user",
			progress: domain.ReconstructProgress(
				uuid.New(), // taskID
				uuid.New(), // jobID
				1,          // sequence number > 0
				time.Now(),
				100,
				0,
				"test progress",
				nil,
				nil,
			),
			setupTask: func(task *scanning.Task) {
				task.Start()
			},
			mockSetup: func(m *mockTaskRepository) {
				task := scanning.NewScanTask(uuid.New(), shared.SourceTypeGitHub, uuid.New(), "test://uri")
				err := task.Start() // Transition to IN_PROGRESS state
				require.NoError(t, err)
				m.On("GetTask", mock.Anything, mock.Anything).Return(task, nil)
				m.On("UpdateTask", mock.Anything, mock.Anything).Return(nil)
			},
			wantErr: false,
		},
		{
			name:        "successful pause without progress",
			taskID:      uuid.New(),
			requestedBy: "test-user",
			progress: domain.ReconstructProgress(
				uuid.New(), // taskID
				uuid.New(), // jobID
				1,          // sequence number > 0
				time.Now(),
				0,
				0,
				"",
				nil,
				nil,
			),
			setupTask: func(task *scanning.Task) {
				task.Start()
			},
			mockSetup: func(m *mockTaskRepository) {
				task := scanning.NewScanTask(uuid.New(), shared.SourceTypeGitHub, uuid.New(), "test://uri")
				err := task.Start() // Transition to IN_PROGRESS state
				require.NoError(t, err)
				m.On("GetTask", mock.Anything, mock.Anything).Return(task, nil)
				m.On("UpdateTask", mock.Anything, mock.Anything).Return(nil)
			},
			wantErr: false,
		},
		{
			name:        "task not found",
			taskID:      uuid.New(),
			requestedBy: "test-user",
			progress:    domain.Progress{},
			setupTask:   func(task *scanning.Task) {},
			mockSetup: func(m *mockTaskRepository) {
				m.On("GetTask", mock.Anything, mock.Anything).
					Return(nil, errors.New("task not found"))
			},
			wantErr: true,
		},
		{
			name:        "update task failure",
			taskID:      uuid.New(),
			requestedBy: "test-user",
			progress:    scanning.NewProgress(uuid.New(), uuid.New(), 1, time.Now(), 50, 100, "", nil, nil),
			setupTask: func(task *scanning.Task) {
				task.Start()
			},
			mockSetup: func(m *mockTaskRepository) {
				task := scanning.NewScanTask(uuid.New(), shared.SourceTypeGitHub, uuid.New(), "test://uri")
				err := task.Start() // Transition to IN_PROGRESS state
				require.NoError(t, err)

				m.On("GetTask", mock.Anything, mock.Anything).Return(task, nil)
				m.On("UpdateTask", mock.Anything, mock.MatchedBy(func(t *scanning.Task) bool {
					return t.Status() == scanning.TaskStatusPaused
				})).Return(errors.New("update failed")).Once()
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := newJobTaskService(t)
			tt.mockSetup(svc.taskRepo.(*mockTaskRepository))

			cmd := domain.NewPauseTaskCommand(tt.taskID, tt.progress, tt.requestedBy)
			_, err := svc.PauseTask(context.Background(), cmd)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			svc.taskRepo.(*mockTaskRepository).AssertExpectations(t)
		})
	}
}

func TestCompleteTask(t *testing.T) {
	jobID := uuid.MustParse("429735d7-ec1b-4d96-8749-938ca0a744be")
	taskID := uuid.MustParse("b1f7eff4-2921-4e6c-9d88-da2de5707a2b")

	tests := []struct {
		name    string
		setup   func(*mockTaskRepository)
		wantErr bool
	}{
		{
			name: "successful task completion",
			setup: func(repo *mockTaskRepository) {
				// Create a task that's IN_PROGRESS (valid state for completion).
				task := domain.NewScanTask(jobID, shared.SourceTypeGitHub, taskID, "https://example.com")
				err := task.Start() // Transition to IN_PROGRESS first
				require.NoError(t, err)

				repo.On("GetTask", mock.Anything, taskID).
					Return(task, nil)

				repo.On("UpdateTask", mock.Anything, mock.MatchedBy(func(t *domain.Task) bool {
					return t.Status() == domain.TaskStatusCompleted
				})).Return(nil)
			},
			wantErr: false,
		},
		{
			name: "task not found",
			setup: func(repo *mockTaskRepository) {
				repo.On("GetTask", mock.Anything, taskID).
					Return(nil, assert.AnError)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			suite := newJobTaskService(t)
			tt.setup(suite.taskRepo.(*mockTaskRepository))

			task, err := suite.CompleteTask(context.Background(), taskID)
			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.NotNil(t, task)
			assert.Equal(t, scanning.TaskStatusCompleted, task.Status())
			suite.taskRepo.(*mockTaskRepository).AssertExpectations(t)
		})
	}
}

func TestFailTask(t *testing.T) {
	jobID := uuid.MustParse("429735d7-ec1b-4d96-8749-938ca0a744be")
	taskID := uuid.MustParse("b1f7eff4-2921-4e6c-9d88-da2de5707a2b")

	tests := []struct {
		name    string
		setup   func(*mockTaskRepository)
		wantErr bool
	}{
		{
			name: "successful task failure",
			setup: func(repo *mockTaskRepository) {
				// Create a task that's IN_PROGRESS (valid state for failing)
				task := domain.NewScanTask(jobID, shared.SourceTypeGitHub, taskID, "https://example.com")
				err := task.Start() // Transition to IN_PROGRESS first
				require.NoError(t, err)
				err = task.ApplyProgress(domain.NewProgress(
					taskID,
					jobID,
					1,
					time.Now(),
					100,
					0,
					"processing",
					nil,
					nil,
				))
				require.NoError(t, err)

				repo.On("GetTask", mock.Anything, taskID).
					Return(task, nil)

				repo.On("UpdateTask", mock.Anything, mock.MatchedBy(func(t *domain.Task) bool {
					return t.Status() == domain.TaskStatusFailed
				})).Return(nil)
			},
			wantErr: false,
		},
		{
			name: "task not found",
			setup: func(repo *mockTaskRepository) {
				repo.On("GetTask", mock.Anything, taskID).
					Return(nil, assert.AnError)
			},
			wantErr: true,
		},
		{
			name: "update task fails",
			setup: func(repo *mockTaskRepository) {
				task := domain.NewScanTask(jobID, shared.SourceTypeGitHub, taskID, "https://example.com")
				repo.On("GetTask", mock.Anything, taskID).
					Return(task, nil)
				repo.On("UpdateTask", mock.Anything, mock.MatchedBy(func(t *domain.Task) bool {
					return t.TaskID() == taskID && t.Status() == domain.TaskStatusFailed
				})).Return(assert.AnError)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			suite := newJobTaskService(t)
			tt.setup(suite.taskRepo.(*mockTaskRepository))

			task, err := suite.FailTask(context.Background(), taskID)
			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.NotNil(t, task)
			assert.Equal(t, scanning.TaskStatusFailed, task.Status())
			suite.taskRepo.(*mockTaskRepository).AssertExpectations(t)
		})
	}
}

func TestMarkTaskStale(t *testing.T) {
	jobID := uuid.MustParse("429735d7-ec1b-4d96-8749-938ca0a744be")
	taskID := uuid.MustParse("b1f7eff4-2921-4e6c-9d88-da2de5707a2b")

	tests := []struct {
		name        string
		setup       func(*mockTaskRepository)
		stallReason domain.StallReason
		wantErr     bool
	}{
		{
			name: "successful mark task as stale",
			setup: func(repo *mockTaskRepository) {
				// Create a task that's IN_PROGRESS (valid state for marking stale)
				task := domain.NewScanTask(jobID, shared.SourceTypeGitHub, taskID, "https://example.com")
				err := task.Start() // Transition to IN_PROGRESS first
				require.NoError(t, err)
				err = task.ApplyProgress(domain.NewProgress(
					taskID,
					jobID,
					1,
					time.Now(),
					100,
					0,
					"processing",
					nil,
					nil,
				))
				require.NoError(t, err)

				repo.On("GetTask", mock.Anything, taskID).
					Return(task, nil)

				repo.On("UpdateTask", mock.Anything, mock.MatchedBy(func(t *domain.Task) bool {
					return t.Status() == domain.TaskStatusStale &&
						t.StallReason() != nil &&
						*t.StallReason() == domain.StallReasonNoProgress &&
						!t.StalledAt().IsZero()
				})).Return(nil)
			},
			stallReason: domain.StallReasonNoProgress,
			wantErr:     false,
		},
		{
			name: "task not found",
			setup: func(repo *mockTaskRepository) {
				repo.On("GetTask", mock.Anything, taskID).
					Return(nil, assert.AnError)
			},
			stallReason: domain.StallReasonNoProgress,
			wantErr:     true,
		},
		{
			name: "task update fails",
			setup: func(repo *mockTaskRepository) {
				task := domain.NewScanTask(jobID, shared.SourceTypeGitHub, taskID, "https://example.com")

				repo.On("GetTask", mock.Anything, taskID).
					Return(task, nil)

				repo.On("UpdateTask", mock.Anything, mock.Anything).
					Return(assert.AnError)
			},
			stallReason: domain.StallReasonNoProgress,
			wantErr:     true,
		},
		{
			name: "invalid state transition",
			setup: func(repo *mockTaskRepository) {
				task := domain.ReconstructTask(
					taskID,
					jobID,
					"test-resource-uri",
					scanning.TaskStatusCompleted,
					0,
					time.Now(),
					time.Now(),
					time.Now(),
					0,
					nil,
					nil,
					nil,
					time.Time{},
					time.Time{},
					0,
					uuid.New(),
				)

				repo.On("GetTask", mock.Anything, taskID).
					Return(task, nil)
			},
			stallReason: domain.StallReasonNoProgress,
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			suite := newJobTaskService(t)
			tt.setup(suite.taskRepo.(*mockTaskRepository))

			task, err := suite.MarkTaskStale(context.Background(), taskID, tt.stallReason)
			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.NotNil(t, task)
			assert.Equal(t, scanning.TaskStatusStale, task.Status())
			assert.Equal(t, tt.stallReason, *task.StallReason())
			assert.False(t, task.StalledAt().IsZero())
			suite.taskRepo.(*mockTaskRepository).AssertExpectations(t)
		})
	}
}

func TestGetTask(t *testing.T) {
	taskID := uuid.MustParse("b1f7eff4-2921-4e6c-9d88-da2de5707a2b")

	tests := []struct {
		name    string
		taskID  uuid.UUID
		setup   func(*mockTaskRepository)
		wantErr bool
	}{
		{
			name:   "successfully get task from repository",
			taskID: taskID,
			setup: func(repo *mockTaskRepository) {
				task := scanning.NewScanTask(uuid.New(), shared.SourceTypeGitHub, taskID, "test://resource")
				repo.On("GetTask", mock.Anything, taskID).
					Return(task, nil)
			},
			wantErr: false,
		},
		{
			name:   "repository error",
			taskID: taskID,
			setup: func(repo *mockTaskRepository) {
				repo.On("GetTask", mock.Anything, taskID).
					Return(nil, assert.AnError)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			suite := newJobTaskService(t)
			tt.setup(suite.taskRepo.(*mockTaskRepository))

			task, err := suite.GetTask(context.Background(), tt.taskID)
			if tt.wantErr {
				require.Error(t, err)
				require.Nil(t, task)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, task)
			assert.Equal(t, tt.taskID, task.TaskID())

			suite.taskRepo.(*mockTaskRepository).AssertExpectations(t)
		})
	}
}

func TestGetJobMetrics(t *testing.T) {
	jobID := uuid.MustParse("429735d7-ec1b-4d96-8749-938ca0a744be")

	tests := []struct {
		name    string
		setup   func(*mockJobRepository)
		wantErr bool
	}{
		{
			name: "successfully get job metrics",
			setup: func(repo *mockJobRepository) {
				metrics := domain.NewJobMetrics()
				repo.On("GetJobMetrics", mock.Anything, jobID).
					Return(metrics, nil)
			},
			wantErr: false,
		},
		{
			name: "repository error",
			setup: func(repo *mockJobRepository) {
				repo.On("GetJobMetrics", mock.Anything, jobID).
					Return(nil, assert.AnError)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			suite := newJobTaskService(t)
			tt.setup(suite.jobRepo.(*mockJobRepository))

			metrics, err := suite.GetJobMetrics(context.Background(), jobID)
			if tt.wantErr {
				require.Error(t, err)
				require.Nil(t, metrics)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, metrics)
			suite.jobRepo.(*mockJobRepository).AssertExpectations(t)
		})
	}
}

func TestGetCheckpoints(t *testing.T) {
	jobID := uuid.MustParse("429735d7-ec1b-4d96-8749-938ca0a744be")

	tests := []struct {
		name    string
		setup   func(*mockJobRepository)
		wantErr bool
		want    map[int32]int64
	}{
		{
			name: "successfully get checkpoints",
			setup: func(repo *mockJobRepository) {
				checkpoints := map[int32]int64{
					0: 100,
					1: 200,
				}
				repo.On("GetCheckpoints", mock.Anything, jobID).
					Return(checkpoints, nil)
			},
			wantErr: false,
			want: map[int32]int64{
				0: 100,
				1: 200,
			},
		},
		{
			name: "repository error",
			setup: func(repo *mockJobRepository) {
				repo.On("GetCheckpoints", mock.Anything, jobID).
					Return(nil, assert.AnError)
			},
			wantErr: true,
			want:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			suite := newJobTaskService(t)
			tt.setup(suite.jobRepo.(*mockJobRepository))

			checkpoints, err := suite.GetCheckpoints(context.Background(), jobID)
			if tt.wantErr {
				require.Error(t, err)
				require.Nil(t, checkpoints)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.want, checkpoints)
			suite.jobRepo.(*mockJobRepository).AssertExpectations(t)
		})
	}
}

func TestUpdateMetricsAndCheckpoint(t *testing.T) {
	jobID := uuid.MustParse("429735d7-ec1b-4d96-8749-938ca0a744be")
	metrics := domain.NewJobMetrics()
	partition := int32(0)
	offset := int64(100)

	tests := []struct {
		name    string
		setup   func(*mockJobRepository)
		wantErr bool
	}{
		{
			name: "successfully update metrics and checkpoint",
			setup: func(repo *mockJobRepository) {
				repo.On("UpdateMetricsAndCheckpoint", mock.Anything, jobID, metrics, partition, offset).
					Return(nil)
			},
			wantErr: false,
		},
		{
			name: "repository error",
			setup: func(repo *mockJobRepository) {
				repo.On("UpdateMetricsAndCheckpoint", mock.Anything, jobID, metrics, partition, offset).
					Return(assert.AnError)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			suite := newJobTaskService(t)
			tt.setup(suite.jobRepo.(*mockJobRepository))

			err := suite.UpdateMetricsAndCheckpoint(context.Background(), jobID, metrics, partition, offset)
			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			suite.jobRepo.(*mockJobRepository).AssertExpectations(t)
		})
	}
}

func TestCancelTask(t *testing.T) {
	jobID := uuid.MustParse("429735d7-ec1b-4d96-8749-938ca0a744be")
	taskID := uuid.MustParse("b1f7eff4-2921-4e6c-9d88-da2de5707a2b")
	requestedBy := "test-admin"

	tests := []struct {
		name        string
		setup       func(*mockTaskRepository)
		requestedBy string
		wantErr     bool
	}{
		{
			name: "successful task cancellation",
			setup: func(repo *mockTaskRepository) {
				// Create a task that's IN_PROGRESS (valid state for cancellation)
				task := domain.NewScanTask(jobID, shared.SourceTypeGitHub, taskID, "https://example.com")
				err := task.Start() // Transition to IN_PROGRESS first
				require.NoError(t, err)

				repo.On("GetTask", mock.Anything, taskID).
					Return(task, nil)

				repo.On("UpdateTask", mock.Anything, mock.MatchedBy(func(t *domain.Task) bool {
					return t.Status() == domain.TaskStatusCancelled
				})).Return(nil)
			},
			requestedBy: requestedBy,
			wantErr:     false,
		},
		{
			name: "task not found",
			setup: func(repo *mockTaskRepository) {
				repo.On("GetTask", mock.Anything, taskID).
					Return(nil, assert.AnError)
			},
			requestedBy: requestedBy,
			wantErr:     true,
		},
		{
			name: "invalid state transition (already completed)",
			setup: func(repo *mockTaskRepository) {
				task := domain.NewScanTask(jobID, shared.SourceTypeGitHub, taskID, "https://example.com")
				err := task.Start() // Transition to IN_PROGRESS first
				require.NoError(t, err)
				err = task.Complete() // Then complete it
				require.NoError(t, err)

				repo.On("GetTask", mock.Anything, taskID).
					Return(task, nil)
			},
			requestedBy: requestedBy,
			wantErr:     true,
		},
		{
			name: "update task fails",
			setup: func(repo *mockTaskRepository) {
				task := domain.NewScanTask(jobID, shared.SourceTypeGitHub, taskID, "https://example.com")
				err := task.Start() // Transition to IN_PROGRESS
				require.NoError(t, err)

				repo.On("GetTask", mock.Anything, taskID).
					Return(task, nil)

				repo.On("UpdateTask", mock.Anything, mock.MatchedBy(func(t *domain.Task) bool {
					return t.Status() == domain.TaskStatusCancelled
				})).Return(assert.AnError)
			},
			requestedBy: requestedBy,
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			suite := newJobTaskService(t)
			tt.setup(suite.taskRepo.(*mockTaskRepository))

			task, err := suite.CancelTask(context.Background(), taskID, tt.requestedBy)
			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.NotNil(t, task)
			assert.Equal(t, scanning.TaskStatusCancelled, task.Status())
			suite.taskRepo.(*mockTaskRepository).AssertExpectations(t)
		})
	}
}

func TestGetTasksToResume(t *testing.T) {
	jobID := uuid.MustParse("429735d7-ec1b-4d96-8749-938ca0a744be")

	tests := []struct {
		name        string
		jobID       uuid.UUID
		setupJob    func(*mockJobRepository)
		setupTask   func(*mockTaskRepository)
		wantErr     bool
		expectedLen int
	}{
		{
			name:  "successfully get paused tasks",
			jobID: jobID,
			setupJob: func(repo *mockJobRepository) {
				// Return a job in PAUSED state.
				job := domain.NewJobWithStatus(jobID, domain.JobStatusPaused)
				repo.On("GetJob", mock.Anything, jobID).Return(job, nil)
			},
			setupTask: func(repo *mockTaskRepository) {
				// Create 3 sample ResumeTaskInfo objects.
				tasks := []domain.ResumeTaskInfo{
					domain.NewResumeTaskInfo(
						uuid.New(),
						jobID,
						shared.SourceTypeGitHub,
						"https://github.com/org/repo1",
						10,
						domain.NewCheckpoint(uuid.New(), []byte("token1"), map[string]string{"pos": "1"}),
					),
					domain.NewResumeTaskInfo(
						uuid.New(),
						jobID,
						shared.SourceTypeGitHub,
						"https://github.com/org/repo2",
						20,
						domain.NewCheckpoint(uuid.New(), []byte("token2"), map[string]string{"pos": "2"}),
					),
					domain.NewResumeTaskInfo(
						uuid.New(),
						jobID,
						shared.SourceTypeGitHub,
						"https://github.com/org/repo3",
						30,
						domain.NewCheckpoint(uuid.New(), []byte("token3"), map[string]string{"pos": "3"}),
					),
				}
				repo.On("GetTasksToResume", mock.Anything, jobID).Return(tasks, nil)
			},
			wantErr:     false,
			expectedLen: 3,
		},
		{
			name:  "job not in paused state",
			jobID: jobID,
			setupJob: func(repo *mockJobRepository) {
				// Return a job in RUNNING state, which should cause validation to fail.
				job := domain.NewJobWithStatus(jobID, domain.JobStatusRunning)
				repo.On("GetJob", mock.Anything, jobID).Return(job, nil)
			},
			setupTask: func(repo *mockTaskRepository) {
				// Expect no calls to GetTasksToResume.
			},
			wantErr:     true,
			expectedLen: 0,
		},
		{
			name:  "job not found",
			jobID: jobID,
			setupJob: func(repo *mockJobRepository) {
				// Simulate job not found.
				repo.On("GetJob", mock.Anything, jobID).Return(nil, domain.ErrJobNotFound)
			},
			setupTask: func(repo *mockTaskRepository) {
				// Expect no calls to GetTasksToResume.
			},
			wantErr:     true,
			expectedLen: 0,
		},
		{
			name:  "task repository error",
			jobID: jobID,
			setupJob: func(repo *mockJobRepository) {
				// Return a job in PAUSED state.
				job := domain.NewJobWithStatus(jobID, domain.JobStatusPaused)
				repo.On("GetJob", mock.Anything, jobID).Return(job, nil)
			},
			setupTask: func(repo *mockTaskRepository) {
				repo.On("GetTasksToResume", mock.Anything, jobID).Return([]domain.ResumeTaskInfo{}, assert.AnError)
			},
			wantErr:     true,
			expectedLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			suite := newJobTaskService(t)

			tt.setupJob(suite.jobRepo.(*mockJobRepository))
			tt.setupTask(suite.taskRepo.(*mockTaskRepository))

			tasks, err := suite.GetTasksToResume(context.Background(), tt.jobID)
			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expectedLen, len(tasks))

			for _, task := range tasks {
				assert.Equal(t, tt.jobID, task.JobID())
				assert.NotNil(t, task.Checkpoint(), "Checkpoint should not be nil")
				assert.NotZero(t, task.SequenceNum(), "Sequence number should not be zero")
			}

			suite.jobRepo.(*mockJobRepository).AssertExpectations(t)
			suite.taskRepo.(*mockTaskRepository).AssertExpectations(t)
		})
	}
}
