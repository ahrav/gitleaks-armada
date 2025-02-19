package scanning

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestJob_UpdateStatus(t *testing.T) {
	tests := []struct {
		name          string
		currentStatus JobStatus
		newStatus     JobStatus
		wantErr       bool
	}{
		{
			name:          "valid transition from queued to enumerating",
			currentStatus: JobStatusQueued,
			newStatus:     JobStatusEnumerating,
			wantErr:       false,
		},
		{
			name:          "valid transition from enumerating to running",
			currentStatus: JobStatusEnumerating,
			newStatus:     JobStatusRunning,
			wantErr:       false,
		},
		{
			name:          "valid transition from running to completed",
			currentStatus: JobStatusRunning,
			newStatus:     JobStatusCompleted,
			wantErr:       false,
		},
		{
			name:          "valid transition from running to failed",
			currentStatus: JobStatusRunning,
			newStatus:     JobStatusFailed,
			wantErr:       false,
		},
		{
			name:          "invalid transition from queued to running",
			currentStatus: JobStatusQueued,
			newStatus:     JobStatusRunning,
			wantErr:       true,
		},
		{
			name:          "invalid transition from completed to running",
			currentStatus: JobStatusCompleted,
			newStatus:     JobStatusRunning,
			wantErr:       true,
		},
		{
			name:          "invalid transition from failed to running",
			currentStatus: JobStatusFailed,
			newStatus:     JobStatusRunning,
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			job := NewJobWithStatus(uuid.New(), tt.currentStatus)

			err := job.UpdateStatus(tt.newStatus)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Equal(t, tt.currentStatus, job.Status(), "status should not change on error")
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.newStatus, job.Status(), "status should be updated")
			}
		})
	}
}

func TestJob_CompleteEnumeration(t *testing.T) {
	tests := []struct {
		name       string
		initialJob *Job
		metrics    *JobMetrics
		wantStatus JobStatus
		wantErr    bool
	}{
		{
			name: "successful completion with tasks",
			initialJob: NewJobWithStatus(
				uuid.New(),
				JobStatusEnumerating,
			),
			metrics:    &JobMetrics{totalTasks: 5},
			wantStatus: JobStatusRunning,
			wantErr:    false,
		},
		{
			name: "successful completion without tasks",
			initialJob: NewJobWithStatus(
				uuid.New(),
				JobStatusEnumerating,
			),
			metrics:    &JobMetrics{totalTasks: 0},
			wantStatus: JobStatusCompleted,
			wantErr:    false,
		},
		{
			name: "error when not in enumerating state",
			initialJob: NewJobWithStatus(
				uuid.New(),
				JobStatusQueued,
			),
			metrics:    &JobMetrics{totalTasks: 1},
			wantStatus: JobStatusQueued,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.initialJob.CompleteEnumeration(tt.metrics)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Equal(t, tt.wantStatus, tt.initialJob.Status(), "status should not change on error")
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantStatus, tt.initialJob.Status(), "status should be updated")
			}
		})
	}
}
