package scanning

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
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

// mockTaskRepository helps test coordinator interactions with task persistence.
type mockTaskRepository struct {
	mock.Mock
}

func (m *mockTaskRepository) CreateTask(ctx context.Context, task *scanning.Task) error {
	return m.Called(ctx, task).Error(0)
}

func (m *mockTaskRepository) GetTask(ctx context.Context, taskID uuid.UUID) (*scanning.Task, error) {
	args := m.Called(ctx, taskID)
	if task := args.Get(0); task != nil {
		return task.(*scanning.Task), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockTaskRepository) UpdateTask(ctx context.Context, task *scanning.Task) error {
	return m.Called(ctx, task).Error(0)
}

func (m *mockTaskRepository) ListTasksByJobAndStatus(ctx context.Context, jobID uuid.UUID, status scanning.TaskStatus) ([]*scanning.Task, error) {
	args := m.Called(ctx, jobID, status)
	return args.Get(0).([]*scanning.Task), args.Error(1)
}

type coordinatorTestSuite struct {
	jobRepo  *mockJobRepository
	taskRepo *mockTaskRepository
	coord    ScanJobCoordinator
	tracer   trace.Tracer
}

func newCoordinatorTestSuite(t *testing.T) *coordinatorTestSuite {
	t.Helper()

	jobRepo := new(mockJobRepository)
	taskRepo := new(mockTaskRepository)
	tracer := noop.NewTracerProvider().Tracer("test")

	return &coordinatorTestSuite{
		jobRepo:  jobRepo,
		taskRepo: taskRepo,
		coord: NewScanJobCoordinator(
			jobRepo,
			taskRepo,
			time.Second,   // persistInterval
			time.Minute*5, // staleTimeout
			tracer,
		),
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
				assert.ErrorContains(t, err, "failed to associate targets")
				return
			}

			require.NoError(t, err)
			suite.jobRepo.AssertExpectations(t)
		})
	}
}

type mockTimeProvider struct {
	now time.Time
}

func (m *mockTimeProvider) Now() time.Time { return m.now }

func TestStartTask(t *testing.T) {
	jobID := uuid.MustParse("429735d7-ec1b-4d96-8749-938ca0a744be")
	taskID := uuid.MustParse("b1f7eff4-2921-4e6c-9d88-da2de5707a2b")

	tests := []struct {
		name    string
		setup   func(*coordinatorTestSuite)
		wantErr bool
	}{
		{
			name: "successful task start",
			setup: func(s *coordinatorTestSuite) {
				job := scanning.ReconstructJob(
					jobID,
					scanning.JobStatusRunning,
					scanning.NewTimeline(&mockTimeProvider{now: time.Now()}),
					[]uuid.UUID{},
					scanning.NewJobMetrics(),
				)

				s.taskRepo.On("CreateTask", mock.Anything, mock.MatchedBy(func(task *scanning.Task) bool {
					return task.JobID() == jobID && task.TaskID() == taskID
				})).Return(nil)

				s.jobRepo.On("GetJob", mock.Anything, jobID).
					Return(job, nil)

				s.jobRepo.On("UpdateJob", mock.Anything, mock.MatchedBy(func(j *scanning.Job) bool {
					// Verify the job has been updated with the task and correct status.
					correctStatus := j.Status() == scanning.JobStatusRunning
					correctJobID := j.JobID() == jobID
					return correctStatus && correctJobID
				})).Return(nil)
			},
			wantErr: false,
		},
		{
			name: "job not found",
			setup: func(s *coordinatorTestSuite) {
				s.taskRepo.On("CreateTask", mock.Anything, mock.MatchedBy(func(task *scanning.Task) bool {
					return task.JobID() == jobID && task.TaskID() == taskID
				})).Return(nil)

				s.jobRepo.On("GetJob", mock.Anything, jobID).
					Return(nil, assert.AnError)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			suite := newCoordinatorTestSuite(t)
			tt.setup(suite)

			task, err := suite.coord.StartTask(context.Background(), jobID, taskID)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.NotNil(t, task)
			assert.Equal(t, scanning.TaskStatusInProgress, task.Status())
			suite.jobRepo.AssertExpectations(t)
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
					scanning.TaskStatusInProgress,
					0,
					time.Now().Add(-2*time.Hour),
					time.Now().Add(-2*time.Hour),
					100,
					nil,
					nil,
					scanning.StallReasonNoProgress,
					time.Time{},
				)

				job := scanning.ReconstructJob(
					jobID,
					scanning.JobStatusRunning,
					scanning.NewTimeline(&mockTimeProvider{}),
					[]uuid.UUID{},
					scanning.NewJobMetrics(),
				)
				job.AddTask(task)

				s.taskRepo.On("GetTask", mock.Anything, taskID).
					Return(task, nil)

				s.taskRepo.On("UpdateTask", mock.Anything, mock.MatchedBy(func(t *scanning.Task) bool {
					return t.LastSequenceNum() == progress.SequenceNum()
				})).Return(nil)

				s.jobRepo.On("GetJob", mock.Anything, jobID).
					Return(job, nil)

				s.jobRepo.On("UpdateJob", mock.Anything, mock.MatchedBy(func(j *scanning.Job) bool {
					return j.JobID() == jobID
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
			suite.jobRepo.AssertExpectations(t)
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
				task := scanning.NewScanTask(jobID, taskID)
				job := scanning.NewJob()
				job.AddTask(task)

				s.taskRepo.On("GetTask", mock.Anything, taskID).
					Return(task, nil)

				s.jobRepo.On("GetJob", mock.Anything, jobID).
					Return(job, nil)

				s.taskRepo.On("UpdateTask", mock.Anything, mock.MatchedBy(func(t *scanning.Task) bool {
					return t.Status() == scanning.TaskStatusCompleted
				})).Return(nil)

				s.jobRepo.On("UpdateJob", mock.Anything, mock.AnythingOfType("*scanning.Job")).Return(nil)
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
			name: "job not found",
			setup: func(s *coordinatorTestSuite) {
				task := scanning.NewScanTask(jobID, taskID)
				s.taskRepo.On("GetTask", mock.Anything, taskID).
					Return(task, nil)
				s.jobRepo.On("GetJob", mock.Anything, jobID).
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
			suite.jobRepo.AssertExpectations(t)
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
				task := scanning.NewScanTask(jobID, taskID)
				job := scanning.NewJob()
				job.AddTask(task)

				s.taskRepo.On("GetTask", mock.Anything, taskID).
					Return(task, nil)

				s.jobRepo.On("GetJob", mock.Anything, jobID).
					Return(job, nil)

				s.taskRepo.On("UpdateTask", mock.Anything, mock.MatchedBy(func(t *scanning.Task) bool {
					return t.Status() == scanning.TaskStatusFailed
				})).Return(nil)

				s.jobRepo.On("UpdateJob", mock.Anything, mock.AnythingOfType("*scanning.Job")).Return(nil)
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
			name: "job not found",
			setup: func(s *coordinatorTestSuite) {
				task := scanning.NewScanTask(jobID, taskID)
				s.taskRepo.On("GetTask", mock.Anything, taskID).
					Return(task, nil)
				s.jobRepo.On("GetJob", mock.Anything, jobID).
					Return(nil, assert.AnError)
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
			suite.jobRepo.AssertExpectations(t)
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
				task := scanning.NewScanTask(jobID, taskID)

				s.taskRepo.On("GetTask", mock.Anything, taskID).
					Return(task, nil)

				s.taskRepo.On("UpdateTask", mock.Anything, mock.MatchedBy(func(t *scanning.Task) bool {
					return t.Status() == scanning.TaskStatusStale &&
						t.StallReason() == scanning.StallReasonNoProgress &&
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
				task := scanning.NewScanTask(jobID, taskID)

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
					scanning.TaskStatusCompleted,
					0,
					time.Now(),
					time.Now(),
					0,
					nil,
					nil,
					scanning.StallReasonNoProgress,
					time.Time{},
				)

				s.taskRepo.On("GetTask", mock.Anything, taskID).
					Return(task, nil)
			},
			stallReason: scanning.StallReasonNoProgress,
			wantErr:     true,
		},
		{
			name: "mark task stale with high errors",
			setup: func(s *coordinatorTestSuite) {
				task := scanning.NewScanTask(jobID, taskID)

				s.taskRepo.On("GetTask", mock.Anything, taskID).
					Return(task, nil)

				s.taskRepo.On("UpdateTask", mock.Anything, mock.MatchedBy(func(t *scanning.Task) bool {
					return t.Status() == scanning.TaskStatusStale &&
						t.StallReason() == scanning.StallReasonHighErrors &&
						!t.StalledAt().IsZero()
				})).Return(nil)
			},
			stallReason: scanning.StallReasonHighErrors,
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			suite := newCoordinatorTestSuite(t)
			tt.setup(suite)

			beforeStale := time.Now()
			task, err := suite.coord.MarkTaskStale(context.Background(), jobID, taskID, tt.stallReason)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.NotNil(t, task)
			assert.Equal(t, scanning.TaskStatusStale, task.Status())
			assert.Equal(t, tt.stallReason, task.StallReason())
			assert.True(t, task.StalledAt().After(beforeStale) ||
				task.StalledAt().Equal(beforeStale))
			suite.taskRepo.AssertExpectations(t)
		})
	}
}
