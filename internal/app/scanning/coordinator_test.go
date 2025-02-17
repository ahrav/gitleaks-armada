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
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	domain "github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
)

// mockJobRepository helps test coordinator interactions with job persistence.
type mockJobRepository struct {
	mock.Mock
}

func (m *mockJobRepository) CreateJob(ctx context.Context, job *scanning.Job) error {
	return m.Called(ctx, job).Error(0)
}

func (m *mockJobRepository) UpdateJob(ctx context.Context, job *scanning.Job) error {
	return m.Called(ctx, job).Error(0)
}

func (m *mockJobRepository) AssociateTargets(ctx context.Context, jobID uuid.UUID, targetIDs []uuid.UUID) error {
	return m.Called(ctx, jobID, targetIDs).Error(0)
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
	return nil, nil
}

func (m *mockJobRepository) StoreCheckpoint(ctx context.Context, jobID uuid.UUID, partitionID int32, offset int64) error {
	return m.Called(ctx, jobID, partitionID, offset).Error(0)
}

func (m *mockJobRepository) GetCheckpoints(ctx context.Context, jobID uuid.UUID) (map[int32]int64, error) {
	return nil, nil
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

type coordinatorTestSuite struct {
	jobRepo  *mockJobRepository
	taskRepo *mockTaskRepository
	coord    *scanJobCoordinator
	tracer   trace.Tracer
	taskID   uuid.UUID
}

func newCoordinatorTestSuite(t *testing.T) *coordinatorTestSuite {
	t.Helper()

	jobRepo := new(mockJobRepository)
	taskRepo := new(mockTaskRepository)
	tracer := noop.NewTracerProvider().Tracer("test")

	return &coordinatorTestSuite{
		jobRepo:  jobRepo,
		taskRepo: taskRepo,
		coord: &scanJobCoordinator{
			jobRepo:  jobRepo,
			taskRepo: taskRepo,
			tracer:   tracer,
		},
		tracer: tracer,
	}
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

			suite := newCoordinatorTestSuite(t)
			tt.setup(suite.jobRepo)

			job, err := suite.coord.CreateJob(context.Background())
			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.NotNil(t, job)
			assert.Equal(t, scanning.JobStatusQueued, job.Status())
			suite.jobRepo.AssertExpectations(t)
		})
	}
}

func TestLinkTargets(t *testing.T) {
	tests := []struct {
		name      string
		jobID     uuid.UUID
		targetIDs []uuid.UUID
		setup     func(*mockJobRepository)
		wantErr   bool
	}{
		{
			name:      "successful target linking",
			jobID:     uuid.New(),
			targetIDs: []uuid.UUID{uuid.New(), uuid.New()},
			setup: func(repo *mockJobRepository) {
				repo.On("AssociateTargets", mock.Anything, mock.Anything, mock.MatchedBy(func(targets []uuid.UUID) bool {
					return len(targets) == 2
				})).Return(nil)
			},
			wantErr: false,
		},
		{
			name:      "empty target list",
			jobID:     uuid.New(),
			targetIDs: []uuid.UUID{},
			setup: func(repo *mockJobRepository) {
				repo.On("AssociateTargets", mock.Anything, mock.Anything, mock.MatchedBy(func(targets []uuid.UUID) bool {
					return len(targets) == 0
				})).Return(nil)
			},
			wantErr: false,
		},
		{
			name:      "repository error",
			jobID:     uuid.New(),
			targetIDs: []uuid.UUID{uuid.New()},
			setup: func(repo *mockJobRepository) {
				repo.On("AssociateTargets", mock.Anything, mock.Anything, mock.Anything).
					Return(assert.AnError)
			},
			wantErr: true,
		},
		{
			name:      "nil target list",
			jobID:     uuid.New(),
			targetIDs: nil,
			setup: func(repo *mockJobRepository) {
				repo.On("AssociateTargets", mock.Anything, mock.Anything, mock.MatchedBy(func(targets []uuid.UUID) bool {
					return targets == nil
				})).Return(nil)
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			suite := newCoordinatorTestSuite(t)
			tt.setup(suite.jobRepo)

			err := suite.coord.LinkTargets(context.Background(), tt.jobID, tt.targetIDs)
			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			suite.jobRepo.AssertExpectations(t)
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
	tests := []struct {
		name    string
		setup   func(*mockTaskRepository)
		jobID   uuid.UUID
		taskID  uuid.UUID
		wantErr bool
	}{
		{
			name: "successful task start",
			setup: func(repo *mockTaskRepository) {
				task := scanning.NewScanTask(
					uuid.MustParse("429735d7-ec1b-4d96-8749-938ca0a744be"),
					shared.SourceTypeGitHub,
					uuid.MustParse("b1f7eff4-2921-4e6c-9d88-da2de5707a2b"),
					"https://github.com/org/repo",
				)
				repo.On("GetTask", mock.Anything, mock.Anything).Return(task, nil)
				repo.On("UpdateTask", mock.Anything, mock.MatchedBy(func(t *scanning.Task) bool {
					return t.Status() == scanning.TaskStatusInProgress
				})).Return(nil)
			},
			jobID:   uuid.MustParse("429735d7-ec1b-4d96-8749-938ca0a744be"),
			taskID:  uuid.MustParse("b1f7eff4-2921-4e6c-9d88-da2de5707a2b"),
			wantErr: false,
		},
		{
			name: "task not found",
			setup: func(repo *mockTaskRepository) {
				repo.On("GetTask", mock.Anything, mock.Anything).
					Return(nil, assert.AnError)
			},
			jobID:   uuid.New(),
			taskID:  uuid.New(),
			wantErr: true,
		},
		{
			name: "update task fails",
			setup: func(repo *mockTaskRepository) {
				task := scanning.NewScanTask(
					uuid.MustParse("429735d7-ec1b-4d96-8749-938ca0a744be"),
					shared.SourceTypeGitHub,
					uuid.MustParse("b1f7eff4-2921-4e6c-9d88-da2de5707a2b"),
					"https://github.com/org/repo",
				)
				repo.On("GetTask", mock.Anything, mock.Anything).Return(task, nil)
				repo.On("UpdateTask", mock.Anything, mock.Anything).
					Return(assert.AnError)
			},
			jobID:   uuid.New(),
			taskID:  uuid.New(),
			wantErr: true,
		},
		{
			name: "invalid state transition",
			setup: func(repo *mockTaskRepository) {
				task := scanning.NewScanTask(
					uuid.MustParse("429735d7-ec1b-4d96-8749-938ca0a744be"),
					shared.SourceTypeGitHub,
					uuid.MustParse("b1f7eff4-2921-4e6c-9d88-da2de5707a2b"),
					"https://github.com/org/repo",
				)
				// Set task to a state that can't transition to IN_PROGRESS.
				err := task.Complete()
				require.NoError(t, err)
				repo.On("GetTask", mock.Anything, mock.Anything).Return(task, nil)
			},
			jobID:   uuid.New(),
			taskID:  uuid.New(),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			suite := newCoordinatorTestSuite(t)
			tt.setup(suite.taskRepo)

			err := suite.coord.StartTask(context.Background(), tt.jobID, tt.taskID, "https://github.com/org/repo")
			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			suite.taskRepo.AssertExpectations(t)
		})
	}
}

func TestUpdateTaskProgress(t *testing.T) {
	jobID := uuid.MustParse("c30b6e0a-25e9-4856-aada-5f2ad03718f2")
	taskID := uuid.MustParse("0ee1a5ba-2543-4ab8-8ceb-fba7aefd7947")

	tests := []struct {
		name    string
		setup   func(*coordinatorTestSuite, *scanning.Progress)
		wantErr bool
	}{
		{
			name: "successful progress update",
			setup: func(s *coordinatorTestSuite, progress *scanning.Progress) {
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
					0,
				)

				job := scanning.ReconstructJob(
					jobID,
					scanning.JobStatusRunning,
					scanning.NewTimeline(&mockTimeProvider{}),
					[]uuid.UUID{},
					scanning.NewJobMetrics(),
				)
				err := job.AddTask(task)
				require.NoError(t, err)

				s.taskRepo.On("GetTask", mock.Anything, taskID).
					Return(task, nil)

				s.taskRepo.On("UpdateTask", mock.Anything, mock.MatchedBy(func(t *scanning.Task) bool {
					return t.LastSequenceNum() == progress.SequenceNum()
				})).Return(nil)
			},
			wantErr: false,
		},
		{
			name: "task not found",
			setup: func(s *coordinatorTestSuite, progress *scanning.Progress) {
				s.taskRepo.On("GetTask", mock.Anything, taskID).
					Return(nil, assert.AnError)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			suite := newCoordinatorTestSuite(t)
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

			tt.setup(suite, &progress)

			task, err := suite.coord.UpdateTaskProgress(context.Background(), progress)
			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.NotNil(t, task)
			suite.taskRepo.AssertExpectations(t)
		})
	}
}

func TestCompleteTask(t *testing.T) {
	jobID := uuid.MustParse("429735d7-ec1b-4d96-8749-938ca0a744be")
	taskID := uuid.MustParse("b1f7eff4-2921-4e6c-9d88-da2de5707a2b")

	tests := []struct {
		name    string
		setup   func(*coordinatorTestSuite)
		wantErr bool
	}{
		{
			name: "successful task completion",
			setup: func(s *coordinatorTestSuite) {
				// Create initial task in IN_PROGRESS state
				task := scanning.NewScanTask(jobID, shared.SourceTypeGitHub, taskID, "https://example.com")
				err := task.ApplyProgress(scanning.NewProgress(
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

				// First mock: Return the task when GetTask is called
				s.taskRepo.On("GetTask", mock.Anything, taskID).
					Return(task, nil)

				// Second mock: Verify the task update with proper status check
				s.taskRepo.On("UpdateTask", mock.Anything, mock.MatchedBy(func(updatedTask *scanning.Task) bool {
					return updatedTask.TaskID() == taskID &&
						updatedTask.JobID() == jobID &&
						updatedTask.Status() == scanning.TaskStatusCompleted &&
						updatedTask.ResourceURI() == "https://example.com"
				})).Return(nil)
			},
			wantErr: false,
		},
		{
			name: "task not found",
			setup: func(s *coordinatorTestSuite) {
				s.taskRepo.On("GetTask", mock.Anything, taskID).
					Return(nil, assert.AnError)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			suite := newCoordinatorTestSuite(t)
			tt.setup(suite)

			task, err := suite.coord.CompleteTask(context.Background(), jobID, taskID)
			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.NotNil(t, task)
			assert.Equal(t, scanning.TaskStatusCompleted, task.Status())
			suite.taskRepo.AssertExpectations(t)
		})
	}
}

func TestFailTask(t *testing.T) {
	jobID := uuid.MustParse("429735d7-ec1b-4d96-8749-938ca0a744be")
	taskID := uuid.MustParse("b1f7eff4-2921-4e6c-9d88-da2de5707a2b")

	tests := []struct {
		name    string
		setup   func(*coordinatorTestSuite)
		wantErr bool
	}{
		{
			name: "successful task failure",
			setup: func(s *coordinatorTestSuite) {
				task := scanning.NewScanTask(jobID, shared.SourceTypeGitHub, taskID, "https://example.com")
				err := task.ApplyProgress(scanning.NewProgress(
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

				s.taskRepo.On("GetTask", mock.Anything, taskID).
					Return(task, nil)

				s.taskRepo.On("UpdateTask", mock.Anything, mock.MatchedBy(func(t *scanning.Task) bool {
					isMatch := t.TaskID() == taskID &&
						t.JobID() == jobID &&
						t.Status() == scanning.TaskStatusFailed &&
						t.ResourceURI() == "https://example.com"
					return isMatch
				})).Return(nil)
			},
			wantErr: false,
		},
		{
			name: "task not found",
			setup: func(s *coordinatorTestSuite) {
				s.taskRepo.On("GetTask", mock.Anything, taskID).
					Return(nil, assert.AnError)
			},
			wantErr: true,
		},
		{
			name: "update task fails",
			setup: func(s *coordinatorTestSuite) {
				task := scanning.NewScanTask(jobID, shared.SourceTypeGitHub, taskID, "https://example.com")
				s.taskRepo.On("GetTask", mock.Anything, taskID).
					Return(task, nil)
				s.taskRepo.On("UpdateTask", mock.Anything, mock.MatchedBy(func(t *scanning.Task) bool {
					return t.TaskID() == taskID && t.Status() == scanning.TaskStatusFailed
				})).Return(assert.AnError)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			suite := newCoordinatorTestSuite(t)
			tt.setup(suite)

			task, err := suite.coord.FailTask(context.Background(), jobID, taskID)
			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.NotNil(t, task)
			assert.Equal(t, scanning.TaskStatusFailed, task.Status())
			suite.taskRepo.AssertExpectations(t)
		})
	}
}

func TestMarkTaskStale(t *testing.T) {
	jobID := uuid.MustParse("429735d7-ec1b-4d96-8749-938ca0a744be")
	taskID := uuid.MustParse("b1f7eff4-2921-4e6c-9d88-da2de5707a2b")

	tests := []struct {
		name        string
		setup       func(*coordinatorTestSuite)
		stallReason scanning.StallReason
		wantErr     bool
	}{
		{
			name: "successful mark task as stale",
			setup: func(s *coordinatorTestSuite) {
				task := scanning.NewScanTask(jobID, shared.SourceTypeGitHub, taskID, "https://example.com")
				err := task.ApplyProgress(scanning.NewProgress(
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

				s.taskRepo.On("GetTask", mock.Anything, taskID).
					Return(task, nil)

				s.taskRepo.On("UpdateTask", mock.Anything, mock.MatchedBy(func(t *scanning.Task) bool {
					return t.Status() == scanning.TaskStatusStale &&
						t.StallReason() != nil &&
						*t.StallReason() == scanning.StallReasonNoProgress &&
						!t.StalledAt().IsZero()
				})).Return(nil)
			},
			stallReason: scanning.StallReasonNoProgress,
			wantErr:     false,
		},
		{
			name: "task not found",
			setup: func(s *coordinatorTestSuite) {
				s.taskRepo.On("GetTask", mock.Anything, taskID).
					Return(nil, assert.AnError)
			},
			stallReason: scanning.StallReasonNoProgress,
			wantErr:     true,
		},
		{
			name: "task update fails",
			setup: func(s *coordinatorTestSuite) {
				task := scanning.NewScanTask(jobID, shared.SourceTypeGitHub, taskID, "https://example.com")

				s.taskRepo.On("GetTask", mock.Anything, taskID).
					Return(task, nil)

				s.taskRepo.On("UpdateTask", mock.Anything, mock.Anything).
					Return(assert.AnError)
			},
			stallReason: scanning.StallReasonNoProgress,
			wantErr:     true,
		},
		{
			name: "invalid state transition",
			setup: func(s *coordinatorTestSuite) {
				task := scanning.ReconstructTask(
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
					0,
				)

				s.taskRepo.On("GetTask", mock.Anything, taskID).
					Return(task, nil)
			},
			stallReason: scanning.StallReasonNoProgress,
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			suite := newCoordinatorTestSuite(t)
			tt.setup(suite)

			task, err := suite.coord.MarkTaskStale(context.Background(), jobID, taskID, tt.stallReason)
			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.NotNil(t, task)
			assert.Equal(t, scanning.TaskStatusStale, task.Status())
			assert.Equal(t, tt.stallReason, *task.StallReason())
			assert.False(t, task.StalledAt().IsZero())
			suite.taskRepo.AssertExpectations(t)
		})
	}
}

func TestGetTask(t *testing.T) {
	tests := []struct {
		name    string
		taskID  uuid.UUID
		setup   func(*coordinatorTestSuite)
		wantErr bool
	}{
		{
			name:   "successfully get task from repository",
			taskID: uuid.New(),
			setup: func(s *coordinatorTestSuite) {
				task := scanning.NewScanTask(uuid.New(), shared.SourceTypeGitHub, s.taskID, "test://resource")
				s.taskRepo.On("GetTask", mock.Anything, s.taskID).
					Return(task, nil)
			},
			wantErr: false,
		},
		{
			name:   "repository error",
			taskID: uuid.New(),
			setup: func(s *coordinatorTestSuite) {
				s.taskRepo.On("GetTask", mock.Anything, s.taskID).
					Return(nil, assert.AnError)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			suite := newCoordinatorTestSuite(t)
			suite.taskID = tt.taskID
			tt.setup(suite)

			task, err := suite.coord.GetTask(context.Background(), tt.taskID)
			if tt.wantErr {
				require.Error(t, err)
				require.Nil(t, task)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, task)
			assert.Equal(t, tt.taskID, task.TaskID())

			suite.taskRepo.AssertExpectations(t)
		})
	}
}

func TestGetTaskSourceType(t *testing.T) {
	taskID := uuid.MustParse("b1f7eff4-2921-4e6c-9d88-da2de5707a2b")

	tests := []struct {
		name           string
		setup          func(*coordinatorTestSuite)
		wantErr        bool
		wantSourceType shared.SourceType
	}{
		{
			name: "successful source type retrieval",
			setup: func(s *coordinatorTestSuite) {
				s.taskRepo.On("GetTaskSourceType", mock.Anything, taskID).
					Return(shared.SourceTypeGitHub, nil)
			},
			wantErr:        false,
			wantSourceType: shared.SourceTypeGitHub,
		},
		{
			name: "task not found",
			setup: func(s *coordinatorTestSuite) {
				s.taskRepo.On("GetTaskSourceType", mock.Anything, taskID).
					Return(shared.SourceTypeUnspecified, assert.AnError)
			},
			wantErr:        true,
			wantSourceType: shared.SourceTypeUnspecified,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			suite := newCoordinatorTestSuite(t)
			tt.setup(suite)

			sourceType, err := suite.coord.GetTaskSourceType(context.Background(), taskID)
			if tt.wantErr {
				require.Error(t, err)
				assert.Empty(t, sourceType)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantSourceType, sourceType)
			suite.taskRepo.AssertExpectations(t)
		})
	}
}
