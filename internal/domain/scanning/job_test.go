package scanning

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
)

func TestScanJob_AddTask(t *testing.T) {
	tests := []struct {
		name string
		job  *ScanJob
		task *Task
		want struct {
			totalTasks     int
			completedTasks int
			failedTasks    int
			status         JobStatus
		}
	}{
		{
			name: "add first task",
			job:  NewScanJob(),
			task: &Task{
				CoreTask: shared.CoreTask{
					TaskID: uuid.New(),
				},
				jobID:  uuid.New(),
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
				jobID: uuid.New(),
				tasks: make(map[uuid.UUID]*Task),
			},
			task: &Task{
				CoreTask: shared.CoreTask{
					TaskID: uuid.New(),
				},
				jobID:  uuid.New(),
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
		taskID   uuid.UUID
		updateFn func(*Task)
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
				jobID:  uuid.New(),
				tasks:  make(map[uuid.UUID]*Task),
				status: JobStatusInitialized,
			},
			taskID:   uuid.New(),
			updateFn: func(task *Task) {},
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
			job: func() *ScanJob {
				taskID := uuid.New()
				return &ScanJob{
					jobID: uuid.New(),
					tasks: map[uuid.UUID]*Task{
						taskID: {
							CoreTask: shared.CoreTask{
								TaskID: taskID,
							},
							status: TaskStatusInProgress,
						},
					},
					totalTasks: 1,
				}
			}(),
			taskID: uuid.New(),
			updateFn: func(task *Task) {
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
			job: func() *ScanJob {
				taskID := uuid.New()
				return &ScanJob{
					jobID: uuid.New(),
					tasks: map[uuid.UUID]*Task{
						taskID: {
							CoreTask: shared.CoreTask{
								TaskID: taskID,
							},
							status: TaskStatusInProgress,
						},
					},
					totalTasks: 1,
				}
			}(),
			taskID: uuid.New(),
			updateFn: func(task *Task) {
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
			if len(tt.job.tasks) > 0 {
				for k := range tt.job.tasks {
					tt.taskID = k
					break
				}
			}

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
