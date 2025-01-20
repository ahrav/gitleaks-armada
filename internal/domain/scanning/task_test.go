package scanning

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewScanTask(t *testing.T) {
	t.Parallel()

	jobID := uuid.New()
	taskID := uuid.New()
	mockTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	mockProvider := &mockTimeProvider{currentTime: mockTime}

	task := NewScanTask(jobID, taskID, WithTimeProvider(mockProvider))

	assert.NotNil(t, task)
	assert.Equal(t, jobID, task.JobID())
	assert.Equal(t, taskID, task.TaskID())
	assert.Equal(t, TaskStatusInProgress, task.Status())

	assert.Equal(t, mockTime, task.StartTime())
	assert.Equal(t, mockTime, task.LastUpdateTime())

	assert.Equal(t, int64(0), task.LastSequenceNum())
	assert.Equal(t, int64(0), task.ItemsProcessed())
	assert.Nil(t, task.LastCheckpoint())
	assert.Nil(t, task.ProgressDetails())
}

func TestNewScanTask_DefaultTimeProvider(t *testing.T) {
	t.Parallel()

	jobID := uuid.New()
	taskID := uuid.New()
	beforeCreate := time.Now()

	task := NewScanTask(jobID, taskID) // No time provider specified

	assert.NotNil(t, task)
	assert.True(t, task.StartTime().After(beforeCreate) || task.StartTime().Equal(beforeCreate))
	assert.True(t, task.LastUpdateTime().After(beforeCreate) || task.LastUpdateTime().Equal(beforeCreate))
}

// mockTimeProvider implements TimeProvider for testing
type mockTimeProvider struct{ currentTime time.Time }

func (m *mockTimeProvider) Now() time.Time { return m.currentTime }

func TestTask_ApplyProgress(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		setupTask   func() *Task
		progress    Progress
		wantStatus  TaskStatus
		wantItems   int64
		wantSeqNum  int64
		wantErr     bool
		checkpoints bool
	}{
		{
			name: "basic progress update",
			setupTask: func() *Task {
				return NewScanTask(uuid.New(), uuid.New())
			},
			progress: Progress{
				sequenceNum:    1,
				itemsProcessed: 100,
				timestamp:      time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			},
			wantStatus: TaskStatusInProgress,
			wantItems:  100,
			wantSeqNum: 1,
		},
		{
			name: "update with checkpoint",
			setupTask: func() *Task {
				return NewScanTask(uuid.New(), uuid.New())
			},
			progress: Progress{
				sequenceNum: 1,
				checkpoint: &Checkpoint{
					resumeToken: []byte("token"),
				},
			},
			wantStatus:  TaskStatusInProgress,
			wantSeqNum:  1,
			checkpoints: true,
		},
		{
			name: "out of order update",
			setupTask: func() *Task {
				task := NewScanTask(uuid.New(), uuid.New())
				_ = task.ApplyProgress(Progress{
					sequenceNum: 2,
				})
				return task
			},
			progress: Progress{
				sequenceNum: 1, // Lower than current
			},
			wantStatus: TaskStatusInProgress, // Should not change
			wantSeqNum: 2,                    // Should not change
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			task := tt.setupTask()
			tt.progress.taskID = task.TaskID()
			if tt.progress.Checkpoint() != nil {
				tt.progress.Checkpoint().taskID = task.TaskID()
			}

			err := task.ApplyProgress(tt.progress)
			if tt.wantErr {
				require.Error(t, err)
				var outOfOrderErr *OutOfOrderProgressError
				assert.ErrorAs(t, err, &outOfOrderErr)
			} else {
				require.NoError(t, err)
			}

			assert.Equal(t, tt.wantStatus, task.Status())
			assert.Equal(t, tt.wantItems, task.ItemsProcessed())
			assert.Equal(t, tt.wantSeqNum, task.LastSequenceNum())
			if tt.checkpoints {
				assert.NotNil(t, task.LastCheckpoint())
				assert.Equal(t, tt.progress.Checkpoint().ResumeToken(), task.LastCheckpoint().ResumeToken())
			}
		})
	}
}

func TestTask_GetSummary(t *testing.T) {
	t.Parallel()

	mockTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	mockProvider := &mockTimeProvider{currentTime: mockTime}

	taskID := uuid.New()
	jobID := uuid.New()
	task := NewScanTask(jobID, taskID, WithTimeProvider(mockProvider))

	progress := Progress{
		taskID:         taskID,
		sequenceNum:    1,
		itemsProcessed: 100,
		timestamp:      mockTime,
	}

	err := task.ApplyProgress(progress)
	require.NoError(t, err)

	duration := 5 * time.Minute
	summary := task.GetSummary(duration)

	assert.Equal(t, taskID, summary.GetTaskID())
	assert.Equal(t, TaskStatusInProgress, summary.GetStatus())
	assert.Equal(t, int64(100), summary.itemsProcessed)
	assert.Equal(t, duration, summary.duration)
	assert.Equal(t, progress.Timestamp(), summary.GetLastUpdateTimestamp())
}

func TestTask_ToStalledTask(t *testing.T) {
	t.Parallel()

	taskID := uuid.New()
	jobID := uuid.New()
	task := NewScanTask(jobID, taskID)

	stallTime := time.Now().Add(-10 * time.Minute)
	stalledTask := task.ToStalledTask(StallReasonNoProgress, stallTime)

	assert.Equal(t, taskID, stalledTask.TaskID)
	assert.Equal(t, jobID, stalledTask.JobID)
	assert.Equal(t, StallReasonNoProgress, stalledTask.StallReason)
	assert.True(t, stalledTask.StalledDuration >= 10*time.Minute)
}

func TestTask_Complete(t *testing.T) {
	t.Parallel()

	mockTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name           string
		setupTask      func(*mockTimeProvider) *Task
		expectedError  error
		expectedReason TaskInvalidStateReason
	}{
		{
			name: "successful completion",
			setupTask: func(tp *mockTimeProvider) *Task {
				task := NewScanTask(uuid.New(), uuid.New(), WithTimeProvider(tp))
				task.itemsProcessed = 100
				return task
			},
		},
		{
			name: "already completed task",
			setupTask: func(tp *mockTimeProvider) *Task {
				task := NewScanTask(uuid.New(), uuid.New(), WithTimeProvider(tp))
				task.status = TaskStatusCompleted
				return task
			},
			expectedReason: TaskInvalidStateReasonWrongStatus,
		},
		{
			name: "failed task",
			setupTask: func(tp *mockTimeProvider) *Task {
				task := NewScanTask(uuid.New(), uuid.New(), WithTimeProvider(tp))
				task.status = TaskStatusFailed
				return task
			},
			expectedReason: TaskInvalidStateReasonWrongStatus,
		},
		{
			name: "no items processed",
			setupTask: func(tp *mockTimeProvider) *Task {
				return NewScanTask(uuid.New(), uuid.New(), WithTimeProvider(tp))
			},
			expectedReason: TaskInvalidStateReasonNoProgress,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tp := &mockTimeProvider{currentTime: mockTime}
			task := tt.setupTask(tp)

			tp.currentTime = tp.currentTime.Add(time.Second)
			err := task.Complete()

			if tt.expectedReason != "" {
				require.Error(t, err)
				var stateErr TaskInvalidStateError
				require.ErrorAs(t, err, &stateErr)
				assert.Equal(t, tt.expectedReason, stateErr.Reason())
			} else {
				require.NoError(t, err)
				assert.Equal(t, TaskStatusCompleted, task.Status())
				assert.Equal(t, tp.Now(), task.LastUpdateTime())
			}
		})
	}
}
