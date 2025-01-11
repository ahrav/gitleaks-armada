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
				status:         JobStatusQueued,
			},
		},
		{
			name: "add completed task",
			job: &ScanJob{
				jobID:    uuid.New(),
				tasks:    make(map[uuid.UUID]*Task),
				metrics:  NewJobMetrics(),
				timeline: NewTimeline(new(realTimeProvider)),
				status:   JobStatusQueued,
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
			t.Parallel()

			beforeAdd := time.Now()
			tt.job.AddTask(tt.task)
			afterAdd := time.Now()

			assert.Equal(t, tt.want.totalTasks, tt.job.metrics.TotalTasks())
			assert.Equal(t, tt.want.completedTasks, tt.job.metrics.CompletedTasks())
			assert.Equal(t, tt.want.failedTasks, tt.job.metrics.FailedTasks())
			assert.Equal(t, tt.want.status, tt.job.status)
			assert.True(t, tt.job.timeline.LastUpdate().After(beforeAdd) || tt.job.timeline.LastUpdate().Equal(beforeAdd))
			assert.True(t, tt.job.timeline.LastUpdate().Before(afterAdd) || tt.job.timeline.LastUpdate().Equal(afterAdd))
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
				jobID:    uuid.New(),
				timeline: NewTimeline(new(realTimeProvider)),
				metrics:  NewJobMetrics(),
				tasks:    make(map[uuid.UUID]*Task),
				status:   JobStatusQueued,
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
				status:         JobStatusQueued,
			},
		},
		{
			name: "update existing task to completed",
			job: func() *ScanJob {
				taskID := uuid.New()
				job := &ScanJob{
					jobID: uuid.New(),
					tasks: map[uuid.UUID]*Task{
						taskID: {
							CoreTask: shared.CoreTask{
								TaskID: taskID,
							},
							status: TaskStatusInProgress,
						},
					},
					metrics:  NewJobMetrics(),
					timeline: NewTimeline(new(realTimeProvider)),
				}
				job.metrics.SetTotalTasks(len(job.tasks))
				return job
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
				job := &ScanJob{
					jobID: uuid.New(),
					tasks: map[uuid.UUID]*Task{
						taskID: {
							CoreTask: shared.CoreTask{
								TaskID: taskID,
							},
							status: TaskStatusInProgress,
						},
					},
					metrics:  NewJobMetrics(),
					timeline: NewTimeline(new(realTimeProvider)),
				}
				job.metrics.SetTotalTasks(len(job.tasks))
				return job
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
			t.Parallel()

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
			assert.Equal(t, tt.want.totalTasks, tt.job.metrics.TotalTasks())
			assert.Equal(t, tt.want.completedTasks, tt.job.metrics.CompletedTasks())
			assert.Equal(t, tt.want.failedTasks, tt.job.metrics.FailedTasks())
			assert.Equal(t, tt.want.status, tt.job.status)

			if updated {
				assert.True(t, tt.job.timeline.LastUpdate().After(beforeUpdate) || tt.job.timeline.LastUpdate().Equal(beforeUpdate))
				assert.True(t, tt.job.timeline.LastUpdate().Before(afterUpdate) || tt.job.timeline.LastUpdate().Equal(afterUpdate))
			}
		})
	}
}
