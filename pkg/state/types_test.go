package state

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestScanTask_UpdateProgress(t *testing.T) {
	tests := []struct {
		name     string
		task     *ScanTask
		progress ScanProgress
		want     *ScanTask
	}{
		{
			name: "basic update",
			task: &ScanTask{
				taskID:          "task1",
				jobID:           "job1",
				lastSequenceNum: 0,
				itemsProcessed:  0,
			},
			progress: ScanProgress{
				TaskID:         "task1",
				JobID:          "job1",
				SequenceNum:    1,
				Status:         TaskStatusInProgress,
				ItemsProcessed: 100,
				Timestamp:      time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			},
			want: &ScanTask{
				taskID:          "task1",
				jobID:           "job1",
				lastSequenceNum: 1,
				status:          TaskStatusInProgress,
				itemsProcessed:  100,
				lastUpdate:      time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			},
		},
		{
			name: "update with checkpoint",
			task: &ScanTask{
				taskID: "task1",
				jobID:  "job1",
			},
			progress: ScanProgress{
				TaskID:      "task1",
				JobID:       "job1",
				SequenceNum: 1,
				Checkpoint: &Checkpoint{
					TaskID:      "task1",
					JobID:       "job1",
					ResumeToken: []byte("token"),
				},
			},
			want: &ScanTask{
				taskID:          "task1",
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

func TestScanJob_AddTask(t *testing.T) {
	tests := []struct {
		name string
		job  *ScanJob
		task *ScanTask
		want struct {
			totalTasks     int
			completedTasks int
			failedTasks    int
			status         JobStatus
		}
	}{
		{
			name: "add first task",
			job:  NewScanJob("job1"),
			task: &ScanTask{
				taskID: "task1",
				jobID:  "job1",
				status: TaskStatusInitialized,
			},
			want: struct {
				totalTasks     int
				completedTasks int
				failedTasks    int
				status         JobStatus
			}{
				totalTasks:     1,
				completedTasks: 0,
				failedTasks:    0,
				status:         JobStatusInitialized,
			},
		},
		{
			name: "add completed task",
			job: &ScanJob{
				jobID: "job1",
				tasks: make(map[string]*ScanTask),
			},
			task: &ScanTask{
				taskID: "task1",
				jobID:  "job1",
				status: TaskStatusCompleted,
			},
			want: struct {
				totalTasks     int
				completedTasks int
				failedTasks    int
				status         JobStatus
			}{
				totalTasks:     1,
				completedTasks: 1,
				failedTasks:    0,
				status:         JobStatusCompleted,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			beforeAdd := time.Now()
			tt.job.AddTask(tt.task)
			afterAdd := time.Now()

			assert.Equal(t, tt.want.totalTasks, tt.job.totalTasks)
			assert.Equal(t, tt.want.completedTasks, tt.job.completedTasks)
			assert.Equal(t, tt.want.failedTasks, tt.job.failedTasks)
			assert.Equal(t, tt.want.status, tt.job.status)
			assert.True(t, tt.job.lastUpdateTime.After(beforeAdd) || tt.job.lastUpdateTime.Equal(beforeAdd))
			assert.True(t, tt.job.lastUpdateTime.Before(afterAdd) || tt.job.lastUpdateTime.Equal(afterAdd))
		})
	}
}

func TestScanJob_UpdateTask(t *testing.T) {
	tests := []struct {
		name     string
		job      *ScanJob
		taskID   string
		updateFn func(*ScanTask)
		want     struct {
			updated        bool
			totalTasks     int
			completedTasks int
			failedTasks    int
			status         JobStatus
		}
	}{
		{
			name: "update non-existent task",
			job: &ScanJob{
				jobID:  "job1",
				tasks:  make(map[string]*ScanTask),
				status: JobStatusInitialized,
			},
			taskID:   "task1",
			updateFn: func(task *ScanTask) {},
			want: struct {
				updated        bool
				totalTasks     int
				completedTasks int
				failedTasks    int
				status         JobStatus
			}{
				updated:        false,
				totalTasks:     0,
				completedTasks: 0,
				failedTasks:    0,
				status:         JobStatusInitialized,
			},
		},
		{
			name: "update existing task to completed",
			job: &ScanJob{
				jobID: "job1",
				tasks: map[string]*ScanTask{
					"task1": {
						taskID: "task1",
						status: TaskStatusInProgress,
					},
				},
				totalTasks: 1,
			},
			taskID: "task1",
			updateFn: func(task *ScanTask) {
				task.status = TaskStatusCompleted
			},
			want: struct {
				updated        bool
				totalTasks     int
				completedTasks int
				failedTasks    int
				status         JobStatus
			}{
				updated:        true,
				totalTasks:     1,
				completedTasks: 1,
				failedTasks:    0,
				status:         JobStatusCompleted,
			},
		},
		{
			name: "update task to failed",
			job: &ScanJob{
				jobID: "job1",
				tasks: map[string]*ScanTask{
					"task1": {
						taskID: "task1",
						status: TaskStatusInProgress,
					},
				},
				totalTasks: 1,
			},
			taskID: "task1",
			updateFn: func(task *ScanTask) {
				task.status = TaskStatusFailed
			},
			want: struct {
				updated        bool
				totalTasks     int
				completedTasks int
				failedTasks    int
				status         JobStatus
			}{
				updated:        true,
				totalTasks:     1,
				completedTasks: 0,
				failedTasks:    1,
				status:         JobStatusFailed,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			beforeUpdate := time.Now()
			updated := tt.job.UpdateTask(tt.taskID, tt.updateFn)
			afterUpdate := time.Now()

			assert.Equal(t, tt.want.updated, updated)
			assert.Equal(t, tt.want.totalTasks, tt.job.totalTasks)
			assert.Equal(t, tt.want.completedTasks, tt.job.completedTasks)
			assert.Equal(t, tt.want.failedTasks, tt.job.failedTasks)
			assert.Equal(t, tt.want.status, tt.job.status)

			if updated {
				assert.True(t, tt.job.lastUpdateTime.After(beforeUpdate) || tt.job.lastUpdateTime.Equal(beforeUpdate))
				assert.True(t, tt.job.lastUpdateTime.Before(afterUpdate) || tt.job.lastUpdateTime.Equal(afterUpdate))
			}
		})
	}
}
