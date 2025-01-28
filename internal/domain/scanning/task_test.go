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

	task := NewScanTask(jobID, taskID, "https://example.com", WithTimeProvider(mockProvider))

	assert.NotNil(t, task)
	assert.Equal(t, jobID, task.JobID())
	assert.Equal(t, taskID, task.TaskID())
	assert.Equal(t, TaskStatusPending, task.Status())

	assert.True(t, task.StartTime().IsZero())
	assert.True(t, task.EndTime().IsZero())

	assert.Equal(t, int64(0), task.LastSequenceNum())
	assert.Equal(t, int64(0), task.ItemsProcessed())
	assert.Nil(t, task.LastCheckpoint())
	assert.Nil(t, task.ProgressDetails())
	assert.Equal(t, "https://example.com", task.ResourceURI())
}

func TestNewScanTask_DefaultTimeProvider(t *testing.T) {
	t.Parallel()

	jobID := uuid.New()
	taskID := uuid.New()

	task := NewScanTask(jobID, taskID, "https://example.com") // No time provider specified

	assert.NotNil(t, task)
	assert.True(t, task.StartTime().IsZero())
}

// mockTimeProvider implements TimeProvider for testing
type mockTimeProvider struct{ currentTime time.Time }

func (m *mockTimeProvider) Now() time.Time { return m.currentTime }

func TestTask_ApplyProgress(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                 string
		setupTask            func() *Task
		progress             Progress
		wantStatus           TaskStatus
		wantItems            int64
		wantSeqNum           int64
		wantErr              bool
		checkpoints          bool
		wantRecoveryAttempts int
	}{
		{
			name: "basic progress update",
			setupTask: func() *Task {
				return NewScanTask(uuid.New(), uuid.New(), "https://example.com")
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
				return NewScanTask(uuid.New(), uuid.New(), "https://example.com")
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
				task := NewScanTask(uuid.New(), uuid.New(), "https://example.com")
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
		{
			name: "recover from stale state",
			setupTask: func() *Task {
				task := NewScanTask(uuid.New(), uuid.New(), "https://example.com")

				_ = task.ApplyProgress(Progress{
					taskID:      task.TaskID(),
					sequenceNum: 1,
				})

				reason := StallReasonNoProgress
				_ = task.MarkStale(&reason)
				return task
			},
			progress: Progress{
				sequenceNum:    2,
				itemsProcessed: 100,
				timestamp:      time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			},
			wantStatus:           TaskStatusInProgress,
			wantItems:            100,
			wantSeqNum:           2,
			wantRecoveryAttempts: 1,
		},
		{
			name: "multiple recoveries from stale state",
			setupTask: func() *Task {
				task := NewScanTask(uuid.New(), uuid.New(), "https://example.com")
				reason := StallReasonNoProgress

				_ = task.ApplyProgress(Progress{
					taskID:      task.TaskID(),
					sequenceNum: 1,
				})

				// First stale cycle.
				_ = task.MarkStale(&reason)
				_ = task.ApplyProgress(Progress{
					taskID:      task.TaskID(),
					sequenceNum: 2,
				})

				// Second stale cycle.
				_ = task.MarkStale(&reason)
				return task
			},
			progress: Progress{
				sequenceNum:    3,
				itemsProcessed: 100,
				timestamp:      time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			},
			wantStatus:           TaskStatusInProgress,
			wantItems:            100,
			wantSeqNum:           3,
			wantRecoveryAttempts: 2,
		},
	}

	for _, tt := range tests {
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
			assert.Equal(t, tt.wantRecoveryAttempts, task.RecoveryAttempts())

			if tt.wantRecoveryAttempts > 0 {
				assert.Nil(t, task.StallReason())
				assert.True(t, task.StalledAt().IsZero())
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
	task := NewScanTask(jobID, taskID, "https://example.com", WithTimeProvider(mockProvider))

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

func TestTask_Complete(t *testing.T) {
	t.Parallel()

	mockTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name           string
		setupTask      func(*mockTimeProvider) *Task
		expectedReason TaskInvalidStateReason
		verifyBehavior func(*testing.T, *Task, *mockTimeProvider)
	}{
		{
			name: "successful completion",
			setupTask: func(tp *mockTimeProvider) *Task {
				task := NewScanTask(uuid.New(), uuid.New(), "https://example.com", WithTimeProvider(tp))
				task.status = TaskStatusInProgress
				task.itemsProcessed = 100
				return task
			},
			verifyBehavior: func(t *testing.T, task *Task, tp *mockTimeProvider) {
				assert.Equal(t, TaskStatusCompleted, task.Status())
				assert.Equal(t, tp.Now(), task.EndTime())
			},
		},
		{
			name: "idempotent completion - already completed task",
			setupTask: func(tp *mockTimeProvider) *Task {
				task := NewScanTask(uuid.New(), uuid.New(), "https://example.com", WithTimeProvider(tp))
				task.status = TaskStatusCompleted
				task.timeline.MarkCompleted()
				return task
			},
			verifyBehavior: func(t *testing.T, task *Task, tp *mockTimeProvider) {
				// Verify the task remains completed and the end time wasn't updated
				assert.Equal(t, TaskStatusCompleted, task.Status())
				assert.NotEqual(t, tp.Now(), task.EndTime())
				assert.True(t, task.EndTime().Before(tp.Now()))
			},
		},
		{
			name: "failed task",
			setupTask: func(tp *mockTimeProvider) *Task {
				task := NewScanTask(uuid.New(), uuid.New(), "https://example.com", WithTimeProvider(tp))
				task.status = TaskStatusFailed
				return task
			},
			expectedReason: TaskInvalidStateReasonWrongStatus,
		},
		// TODO: Uncomment once progress is tracked in source scanners.
		// {
		// 	name: "no items processed",
		// 	setupTask: func(tp *mockTimeProvider) *Task {
		// 		return NewScanTask(uuid.New(), uuid.New(), WithTimeProvider(tp))
		// 	},
		// 	expectedReason: TaskInvalidStateReasonNoProgress,
		// },
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tp := &mockTimeProvider{currentTime: mockTime}
			task := tt.setupTask(tp)

			// Advance time to simulate some processing.
			tp.currentTime = tp.currentTime.Add(time.Second)
			err := task.Complete()

			if tt.expectedReason != "" {
				require.Error(t, err)
				var stateErr TaskInvalidStateError
				require.ErrorAs(t, err, &stateErr)
				assert.Equal(t, tt.expectedReason, stateErr.Reason())
				return
			}

			require.NoError(t, err)

			// If there's custom verification logic, run it.
			if tt.verifyBehavior != nil {
				tt.verifyBehavior(t, task, tp)
			}

			// Try completing again to verify idempotency.
			if task.Status() == TaskStatusCompleted {
				originalEndTime := task.EndTime()
				tp.currentTime = tp.currentTime.Add(time.Second)

				err = task.Complete()
				require.NoError(t, err, "second completion should succeed")
				assert.Equal(t, TaskStatusCompleted, task.Status())
				assert.Equal(t, originalEndTime, task.EndTime(), "end time should not change on repeated completion")
			}
		})
	}
}

func TestTask_Fail(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		initialTask *Task
		wantErr     bool
		errType     error
	}{
		{
			name: "successfully fail task from in progress",
			initialTask: ReconstructTask(
				uuid.New(),
				uuid.New(),
				"",
				TaskStatusInProgress,
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
			),
			wantErr: false,
		},
		{
			name: "successfully fail task from stale",
			initialTask: ReconstructTask(
				uuid.New(),
				uuid.New(),
				"",
				TaskStatusStale,
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
			),
			wantErr: false,
		},
		{
			name: "fail to transition from completed state",
			initialTask: ReconstructTask(
				uuid.New(),
				uuid.New(),
				"",
				TaskStatusCompleted,
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
			),
			wantErr: true,
			errType: TaskInvalidStateError{},
		},
		{
			name: "fail to transition from failed state",
			initialTask: ReconstructTask(
				uuid.New(),
				uuid.New(),
				"",
				TaskStatusFailed,
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
			),
			wantErr: true,
			errType: TaskInvalidStateError{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.initialTask.Fail()
			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got nil")
					return
				}

				if _, ok := err.(TaskInvalidStateError); !ok {
					t.Errorf("expected TaskInvalidStateError but got %T", err)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if tt.initialTask.Status() != TaskStatusFailed {
				t.Errorf("expected status %s but got %s", TaskStatusFailed, tt.initialTask.Status())
			}
		})
	}
}

func TestTask_MarkStale(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		initialTask *Task
		reason      *StallReason
		wantErr     bool
	}{
		{
			name: "successfully mark task as stale from in progress",
			initialTask: ReconstructTask(
				uuid.New(),
				uuid.New(),
				"",
				TaskStatusInProgress,
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
			),
			reason:  ReasonPtr(StallReasonNoProgress),
			wantErr: false,
		},
		{
			name: "fail to mark completed task as stale",
			initialTask: ReconstructTask(
				uuid.New(),
				uuid.New(),
				"",
				TaskStatusCompleted,
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
			),
			reason:  nil,
			wantErr: true,
		},
		{
			name: "fail to mark failed task as stale",
			initialTask: ReconstructTask(
				uuid.New(),
				uuid.New(),
				"",
				TaskStatusFailed,
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
			),
			reason:  nil,
			wantErr: true,
		},
		{
			name: "fail to mark already stale task as stale",
			initialTask: ReconstructTask(
				uuid.New(),
				uuid.New(),
				"",
				TaskStatusStale,
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
			),
			reason:  nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			beforeStale := time.Now()
			err := tt.initialTask.MarkStale(tt.reason)

			if tt.wantErr {
				require.Error(t, err)
				var stateErr TaskInvalidStateError
				require.ErrorAs(t, err, &stateErr)
				assert.Equal(t, TaskInvalidStateReasonWrongStatus, stateErr.Reason())
				return
			}

			require.NoError(t, err)
			assert.Equal(t, TaskStatusStale, tt.initialTask.Status())
			assert.Equal(t, tt.reason, tt.initialTask.StallReason())
			assert.True(t, tt.initialTask.StalledAt().After(beforeStale) ||
				tt.initialTask.StalledAt().Equal(beforeStale))
			assert.Greater(t, tt.initialTask.StalledDuration(), time.Duration(0))
		})
	}
}
