package scanning

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	domain "github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
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
		setup   func(*mockJobRepository)
		wantErr bool
	}{
		{
			name: "successful job creation",
			setup: func(repo *mockJobRepository) {
				repo.On("CreateJob", mock.Anything, mock.MatchedBy(func(job *scanning.Job) bool {
					return job.Status() == scanning.JobStatusQueued
				})).Return(nil)
			},
			wantErr: false,
		},
		{
			name: "repository error",
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

			err := suite.CreateJobFromID(context.Background(), uuid.New())
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

	tests := []struct {
		name    string
		setup   func(*mockJobRepository)
		wantErr bool
		errMsg  string
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
			errMsg:  "failed to associate targets with job",
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
			errMsg:  "failed to increment total tasks for job",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			suite := newJobTaskService(t)
			tt.setup(suite.jobRepo.(*mockJobRepository))

			err := suite.AssociateEnumeratedTargets(context.Background(), jobID, targetIDs)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
				return
			}

			require.NoError(t, err)
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
		errMsg        string
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
			errMsg:        "invalid job status transition from COMPLETED to RUNNING",
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
			errMsg:        "invalid job status transition from FAILED to COMPLETED",
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
			errMsg:        "invalid job status transition from QUEUED to RUNNING",
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
			errMsg:        "failed to update job status",
		},
		{
			name: "job load failure",
			setup: func(repo *mockJobRepository) {
				repo.On("GetJob", mock.Anything, mock.Anything).Return(nil, assert.AnError)
			},
			initialStatus: domain.JobStatusEnumerating,
			targetStatus:  domain.JobStatusRunning,
			wantErr:       true,
			errMsg:        "failed to load job",
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
				assert.Contains(t, err.Error(), tt.errMsg)
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

func TestStartTask(t *testing.T) {
	jobID := uuid.MustParse("429735d7-ec1b-4d96-8749-938ca0a744be")
	taskID := uuid.MustParse("b1f7eff4-2921-4e6c-9d88-da2de5707a2b")

	tests := []struct {
		name    string
		setup   func(*mockTaskRepository)
		taskID  uuid.UUID
		wantErr bool
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
				// Task should be in PENDING state initially
				require.Equal(t, scanning.TaskStatusPending, task.Status())

				repo.On("GetTask", mock.Anything, taskID).Return(task, nil)
				repo.On("UpdateTask", mock.Anything, mock.MatchedBy(func(t *scanning.Task) bool {
					return t.Status() == scanning.TaskStatusInProgress
				})).Return(nil)
			},
			taskID:  taskID,
			wantErr: false,
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
				// Set task to FAILED state - can't transition to IN_PROGRESS from FAILED
				err := task.Fail()
				require.NoError(t, err)

				repo.On("GetTask", mock.Anything, mock.Anything).Return(task, nil)
			},
			taskID:  taskID,
			wantErr: true,
		},
		{
			name: "task not found",
			setup: func(repo *mockTaskRepository) {
				repo.On("GetTask", mock.Anything, mock.Anything).
					Return(nil, assert.AnError)
			},
			taskID:  uuid.New(),
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
			taskID:  taskID,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			suite := newJobTaskService(t)
			tt.setup(suite.taskRepo.(*mockTaskRepository))

			err := suite.StartTask(context.Background(), tt.taskID, "https://github.com/org/repo")
			if tt.wantErr {
				require.Error(t, err)
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
			suite.taskRepo.(*mockTaskRepository).AssertExpectations(t)
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
				// Create a task that's IN_PROGRESS (valid state for completion)
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

func TestGetTaskSourceType(t *testing.T) {
	taskID := uuid.MustParse("b1f7eff4-2921-4e6c-9d88-da2de5707a2b")

	tests := []struct {
		name           string
		setup          func(*mockTaskRepository)
		wantErr        bool
		wantSourceType shared.SourceType
	}{
		{
			name: "successful source type retrieval",
			setup: func(repo *mockTaskRepository) {
				repo.On("GetTaskSourceType", mock.Anything, taskID).
					Return(shared.SourceTypeGitHub, nil)
			},
			wantErr:        false,
			wantSourceType: shared.SourceTypeGitHub,
		},
		{
			name: "task not found",
			setup: func(repo *mockTaskRepository) {
				repo.On("GetTaskSourceType", mock.Anything, taskID).
					Return(shared.SourceTypeUnspecified, assert.AnError)
			},
			wantErr:        true,
			wantSourceType: shared.SourceTypeUnspecified,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			suite := newJobTaskService(t)
			tt.setup(suite.taskRepo.(*mockTaskRepository))

			sourceType, err := suite.GetTaskSourceType(context.Background(), taskID)
			if tt.wantErr {
				require.Error(t, err)
				assert.Empty(t, sourceType)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantSourceType, sourceType)
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
