package scanning

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
)

func TestScanTask_UpdateProgress(t *testing.T) {
	tests := []struct {
		name     string
		task     *Task
		progress Progress
		want     *Task
	}{
		{
			name: "basic update",
			task: func() *Task {
				taskID := uuid.New()
				jobID := uuid.New()
				return &Task{
					CoreTask: shared.CoreTask{
						TaskID: taskID,
					},
					jobID:           jobID,
					lastSequenceNum: 0,
					itemsProcessed:  0,
				}
			}(),
			progress: func() Progress {
				taskID := uuid.New() // Will be overwritten in test
				jobID := uuid.New()  // Will be overwritten in test
				return Progress{
					TaskID:         taskID,
					JobID:          jobID,
					SequenceNum:    1,
					Status:         TaskStatusInProgress,
					ItemsProcessed: 100,
					Timestamp:      time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
				}
			}(),
			want: func() *Task {
				taskID := uuid.New() // Will be overwritten in test
				jobID := uuid.New()  // Will be overwritten in test
				return &Task{
					CoreTask: shared.CoreTask{
						TaskID: taskID,
					},
					jobID:           jobID,
					lastSequenceNum: 1,
					status:          TaskStatusInProgress,
					itemsProcessed:  100,
					lastUpdate:      time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
				}
			}(),
		},
		{
			name: "update with checkpoint",
			task: func() *Task {
				taskID := uuid.New()
				jobID := uuid.New()
				return &Task{
					CoreTask: shared.CoreTask{
						TaskID: taskID,
					},
					jobID:           jobID,
					lastSequenceNum: 0,
				}
			}(),
			progress: func() Progress {
				taskID := uuid.New() // Will be overwritten in test
				jobID := uuid.New()  // Will be overwritten in test
				return Progress{
					TaskID:      taskID,
					JobID:       jobID,
					SequenceNum: 1,
					Checkpoint: &Checkpoint{
						TaskID:      taskID,
						JobID:       jobID,
						ResumeToken: []byte("token"),
					},
				}
			}(),
			want: func() *Task {
				taskID := uuid.New() // Will be overwritten in test
				jobID := uuid.New()  // Will be overwritten in test
				return &Task{
					CoreTask: shared.CoreTask{
						TaskID: taskID,
					},
					jobID:           jobID,
					lastSequenceNum: 1,
					lastCheckpoint: &Checkpoint{
						TaskID:      taskID,
						JobID:       jobID,
						ResumeToken: []byte("token"),
					},
				}
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Sync the IDs across task, progress, and want
			tt.progress.TaskID = tt.task.TaskID
			tt.progress.JobID = tt.task.jobID
			tt.want.TaskID = tt.task.TaskID
			tt.want.jobID = tt.task.jobID

			if tt.progress.Checkpoint != nil {
				tt.progress.Checkpoint.TaskID = tt.task.TaskID
				tt.progress.Checkpoint.JobID = tt.task.jobID
				tt.want.lastCheckpoint.TaskID = tt.task.TaskID
				tt.want.lastCheckpoint.JobID = tt.task.jobID
			}

			tt.task.UpdateProgress(tt.progress)
			assert.Equal(t, tt.want.lastSequenceNum, tt.task.lastSequenceNum)
			assert.Equal(t, tt.want.status, tt.task.status)
			assert.Equal(t, tt.want.itemsProcessed, tt.task.itemsProcessed)
			assert.Equal(t, tt.want.lastCheckpoint, tt.task.lastCheckpoint)
		})
	}
}
