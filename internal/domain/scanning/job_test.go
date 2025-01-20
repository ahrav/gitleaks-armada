package scanning

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestScanJob_AddTask(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		setupJob  func() *Job
		wantErr   bool
		wantState JobStatus
	}{
		{
			name: "add first task to queued job",
			setupJob: func() *Job {
				return NewJob()
			},
			wantErr:   false,
			wantState: JobStatusRunning,
		},
		{
			name: "add task to already running job",
			setupJob: func() *Job {
				job := NewJob()
				task := NewScanTask(job.JobID(), uuid.New())
				_ = job.AddTask(task) // First task transitions to running
				return job
			},
			wantErr:   false,
			wantState: JobStatusRunning,
		},
		{
			name: "add task to completed job",
			setupJob: func() *Job {
				job := NewJob()
				job.status = JobStatusCompleted
				return job
			},
			wantErr:   true,
			wantState: JobStatusCompleted,
		},
		{
			name: "add task to failed job",
			setupJob: func() *Job {
				job := NewJob()
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
			err := job.AddTask(NewScanTask(job.JobID(), uuid.New()))
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

			assert.Equal(t, tt.wantState, job.Status())
		})
	}
}

func TestScanJob_AssociateTarget(t *testing.T) {
	t.Parallel()

	job := NewJob()
	targetID := uuid.New()
	job.AssociateTargets([]uuid.UUID{targetID})

	assert.Equal(t, job.targetIDs, []uuid.UUID{targetID})
}
