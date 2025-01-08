package scanning

import (
	"testing"
	"time"

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
			task: &Task{
				CoreTask: shared.CoreTask{
					TaskID: "task1",
				},
				jobID:           "job1",
				lastSequenceNum: 0,
				itemsProcessed:  0,
			},
			progress: Progress{
				TaskID:         "task1",
				JobID:          "job1",
				SequenceNum:    1,
				Status:         TaskStatusInProgress,
				ItemsProcessed: 100,
				Timestamp:      time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			},
			want: &Task{
				CoreTask: shared.CoreTask{
					TaskID: "task1",
				},
				jobID:           "job1",
				lastSequenceNum: 1,
				status:          TaskStatusInProgress,
				itemsProcessed:  100,
				lastUpdate:      time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			},
		},
		{
			name: "update with checkpoint",
			task: &Task{
				CoreTask: shared.CoreTask{
					TaskID: "task1",
				},
				jobID:           "job1",
				lastSequenceNum: 0,
			},
			progress: Progress{
				TaskID:      "task1",
				JobID:       "job1",
				SequenceNum: 1,
				Checkpoint: &Checkpoint{
					TaskID:      "task1",
					JobID:       "job1",
					ResumeToken: []byte("token"),
				},
			},
			want: &Task{
				CoreTask: shared.CoreTask{
					TaskID: "task1",
				},
				jobID:           "job1",
				lastSequenceNum: 1,
				lastCheckpoint: &Checkpoint{
					TaskID:      "task1",
					JobID:       "job1",
					ResumeToken: []byte("token"),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.task.UpdateProgress(tt.progress)
			assert.Equal(t, tt.want.lastSequenceNum, tt.task.lastSequenceNum)
			assert.Equal(t, tt.want.status, tt.task.status)
			assert.Equal(t, tt.want.itemsProcessed, tt.task.itemsProcessed)
			assert.Equal(t, tt.want.lastCheckpoint, tt.task.lastCheckpoint)
		})
	}
}
