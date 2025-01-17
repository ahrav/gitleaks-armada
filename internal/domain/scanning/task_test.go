package scanning

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
				SequenceNum:    1,
				Status:         TaskStatusInProgress,
				ItemsProcessed: 100,
				Timestamp:      time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
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
				SequenceNum: 1,
				Status:      TaskStatusInProgress,
				Checkpoint: &Checkpoint{
					ResumeToken: []byte("token"),
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
					SequenceNum: 2,
					Status:      TaskStatusInProgress,
				})
				return task
			},
			progress: Progress{
				SequenceNum: 1, // Lower than current
				Status:      TaskStatusCompleted,
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
			tt.progress.TaskID = task.TaskID()
			if tt.progress.Checkpoint != nil {
				tt.progress.Checkpoint.TaskID = task.TaskID()
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
				assert.Equal(t, tt.progress.Checkpoint.ResumeToken, task.LastCheckpoint().ResumeToken)
			}
		})
	}
}

func TestTask_GetSummary(t *testing.T) {
	t.Parallel()

	taskID := uuid.New()
	jobID := uuid.New()
	task := NewScanTask(jobID, taskID)

	progress := Progress{
		TaskID:         taskID,
		SequenceNum:    1,
		Status:         TaskStatusInProgress,
		ItemsProcessed: 100,
		Timestamp:      time.Now(),
	}

	err := task.ApplyProgress(progress)
	require.NoError(t, err)

	duration := 5 * time.Minute
	summary := task.GetSummary(duration)

	assert.Equal(t, taskID, summary.GetTaskID())
	assert.Equal(t, TaskStatusInProgress, summary.GetStatus())
	assert.Equal(t, int64(100), summary.itemsProcessed)
	assert.Equal(t, duration, summary.duration)
	assert.Equal(t, progress.Timestamp, summary.GetLastUpdateTimestamp())
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
