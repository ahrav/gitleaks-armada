package scanning

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
)

func TestScanJob_AddTask(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		setupJob  func() *ScanJob
		wantErr   bool
		wantState JobStatus
	}{
		{
			name: "add first task to queued job",
			setupJob: func() *ScanJob {
				return NewScanJob()
			},
			wantErr:   false,
			wantState: JobStatusRunning,
		},
		{
			name: "add task to already running job",
			setupJob: func() *ScanJob {
				job := NewScanJob()
				task := NewScanTask(job.GetJobID(), uuid.New())
				_ = job.AddTask(task) // First task transitions to running
				return job
			},
			wantErr:   false,
			wantState: JobStatusRunning,
		},
		{
			name: "add task to completed job",
			setupJob: func() *ScanJob {
				job := NewScanJob()
				job.status = JobStatusCompleted
				return job
			},
			wantErr:   true,
			wantState: JobStatusCompleted,
		},
		{
			name: "add task to failed job",
			setupJob: func() *ScanJob {
				job := NewScanJob()
				job.status = JobStatusFailed
				return job
			},
			wantErr:   true,
			wantState: JobStatusFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			job := tt.setupJob()
			beforeAdd := time.Now()
			err := job.AddTask(NewScanTask(job.GetJobID(), uuid.New()))
			afterAdd := time.Now()

			if tt.wantErr {
				assert.Error(t, err)
				var jobStartErr *JobStartError
				assert.ErrorAs(t, err, &jobStartErr)
			} else {
				assert.NoError(t, err)
				assert.True(t, job.timeline.LastUpdate().After(beforeAdd) ||
					job.timeline.LastUpdate().Equal(beforeAdd))
				assert.True(t, job.timeline.LastUpdate().Before(afterAdd) ||
					job.timeline.LastUpdate().Equal(afterAdd))
			}

			assert.Equal(t, tt.wantState, job.GetStatus())
		})
	}
}

func TestScanJob_UpdateTask(t *testing.T) {
	t.Parallel()

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

func TestScanJob_AssociateTarget(t *testing.T) {
	t.Parallel()

	job := NewScanJob()
	targetID := uuid.New()
	job.AssociateTargets([]uuid.UUID{targetID})

	assert.Equal(t, job.targetIDs, []uuid.UUID{targetID})
}
