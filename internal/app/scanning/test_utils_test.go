package scanning

import (
	"context"
	"time"

	"github.com/stretchr/testify/mock"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
	"github.com/ahrav/gitleaks-armada/pkg/common/uuid"
)

// mockDomainEventPublisher implements events.DomainEventPublisher for testing.
type mockDomainEventPublisher struct{ mock.Mock }

func (m *mockDomainEventPublisher) PublishDomainEvent(ctx context.Context, event events.DomainEvent, opts ...events.PublishOption) error {
	args := m.Called(ctx, event, opts)
	return args.Error(0)
}

// mockJobTaskSvc implements domain.JobTaskService for testing.
type mockJobTaskSvc struct{ mock.Mock }

func (m *mockJobTaskSvc) CreateJob(ctx context.Context, cmd scanning.CreateJobCommand) error {
	args := m.Called(ctx, cmd)
	return args.Error(0)
}

func (m *mockJobTaskSvc) AssociateEnumeratedTargets(ctx context.Context, jobID uuid.UUID, targetIDs []uuid.UUID) error {
	args := m.Called(ctx, jobID, targetIDs)
	return args.Error(0)
}

func (m *mockJobTaskSvc) GetJobConfigInfo(ctx context.Context, jobID uuid.UUID) (*scanning.JobConfigInfo, error) {
	args := m.Called(ctx, jobID)
	if configInfo := args.Get(0); configInfo != nil {
		return configInfo.(*scanning.JobConfigInfo), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockJobTaskSvc) UpdateJobStatus(ctx context.Context, jobID uuid.UUID, status scanning.JobStatus) error {
	args := m.Called(ctx, jobID, status)
	return args.Error(0)
}

func (m *mockJobTaskSvc) CompleteEnumeration(ctx context.Context, jobID uuid.UUID) (*scanning.JobMetrics, error) {
	args := m.Called(ctx, jobID)
	if metrics := args.Get(0); metrics != nil {
		return metrics.(*scanning.JobMetrics), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockJobTaskSvc) CreateTask(ctx context.Context, task *scanning.Task) error {
	args := m.Called(ctx, task)
	return args.Error(0)
}

func (m *mockJobTaskSvc) StartTask(ctx context.Context, taskID uuid.UUID, resourceURI string) error {
	args := m.Called(ctx, taskID, resourceURI)
	return args.Error(0)
}

func (m *mockJobTaskSvc) UpdateTaskProgress(ctx context.Context, progress scanning.Progress) (*scanning.Task, error) {
	args := m.Called(ctx, progress)
	if task := args.Get(0); task != nil {
		return task.(*scanning.Task), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockJobTaskSvc) PauseTask(ctx context.Context, taskID uuid.UUID, progress scanning.Progress, requestedBy string) (*scanning.Task, error) {
	args := m.Called(ctx, taskID, progress, requestedBy)
	if task := args.Get(0); task != nil {
		return task.(*scanning.Task), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockJobTaskSvc) CompleteTask(ctx context.Context, taskID uuid.UUID) (*scanning.Task, error) {
	args := m.Called(ctx, taskID)
	if task := args.Get(0); task != nil {
		return task.(*scanning.Task), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockJobTaskSvc) FailTask(ctx context.Context, taskID uuid.UUID) (*scanning.Task, error) {
	args := m.Called(ctx, taskID)
	if task := args.Get(0); task != nil {
		return task.(*scanning.Task), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockJobTaskSvc) MarkTaskStale(ctx context.Context, taskID uuid.UUID, reason scanning.StallReason) (*scanning.Task, error) {
	args := m.Called(ctx, taskID, reason)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*scanning.Task), args.Error(1)
}

func (m *mockJobTaskSvc) CancelTask(ctx context.Context, taskID uuid.UUID, requestedBy string) (*scanning.Task, error) {
	args := m.Called(ctx, taskID, requestedBy)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*scanning.Task), args.Error(1)
}

func (m *mockJobTaskSvc) GetTask(ctx context.Context, taskID uuid.UUID) (*scanning.Task, error) {
	args := m.Called(ctx, taskID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*scanning.Task), args.Error(1)
}

func (m *mockJobTaskSvc) GetTaskSourceType(ctx context.Context, taskID uuid.UUID) (shared.SourceType, error) {
	args := m.Called(ctx, taskID)
	return args.Get(0).(shared.SourceType), args.Error(1)
}

func (m *mockJobTaskSvc) UpdateHeartbeats(ctx context.Context, heartbeats map[uuid.UUID]time.Time) (int64, error) {
	args := m.Called(ctx, heartbeats)
	return args.Get(0).(int64), args.Error(1)
}

func (m *mockJobTaskSvc) FindStaleTasks(ctx context.Context, controllerID string, cutoff time.Time) ([]scanning.StaleTaskInfo, error) {
	args := m.Called(ctx, controllerID, cutoff)
	return args.Get(0).([]scanning.StaleTaskInfo), args.Error(1)
}

func (m *mockJobTaskSvc) GetJobMetrics(ctx context.Context, jobID uuid.UUID) (*scanning.JobMetrics, error) {
	args := m.Called(ctx, jobID)
	if metrics := args.Get(0); metrics != nil {
		return metrics.(*scanning.JobMetrics), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockJobTaskSvc) GetCheckpoints(ctx context.Context, jobID uuid.UUID) (map[int32]int64, error) {
	args := m.Called(ctx, jobID)
	if checkpoints := args.Get(0); checkpoints != nil {
		return checkpoints.(map[int32]int64), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockJobTaskSvc) UpdateMetricsAndCheckpoint(ctx context.Context, jobID uuid.UUID, metrics *scanning.JobMetrics, partition int32, offset int64) error {
	args := m.Called(ctx, jobID, metrics, partition, offset)
	return args.Error(0)
}

func (m *mockJobTaskSvc) ListTasksByJobAndStatus(ctx context.Context, jobID uuid.UUID, status scanning.TaskStatus) ([]*scanning.Task, error) {
	args := m.Called(ctx, jobID, status)
	return args.Get(0).([]*scanning.Task), args.Error(1)
}

func (m *mockJobTaskSvc) GetTasksToResume(ctx context.Context, jobID uuid.UUID) ([]scanning.ResumeTaskInfo, error) {
	args := m.Called(ctx, jobID)
	return args.Get(0).([]scanning.ResumeTaskInfo), args.Error(1)
}
