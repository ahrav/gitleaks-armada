package scanning

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
)

func TestAddTask(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name               string
		initialJobStatus   JobStatus
		taskStatusToAdd    TaskStatus
		expectedTotal      int
		expectedInProgress int
		expectedCompleted  int
		expectedFailed     int
		expectedJobStatus  JobStatus
	}{
		{
			name:               "Add IN_PROGRESS Task to QUEUED Job",
			initialJobStatus:   JobStatusQueued,
			taskStatusToAdd:    TaskStatusInProgress,
			expectedTotal:      1,
			expectedInProgress: 1,
			expectedCompleted:  0,
			expectedFailed:     0,
			expectedJobStatus:  JobStatusRunning,
		},
		{
			name:               "Add STALE Task to QUEUED Job",
			initialJobStatus:   JobStatusQueued,
			taskStatusToAdd:    TaskStatusStale,
			expectedTotal:      1,
			expectedInProgress: 1, // STALE counts as in-progress
			expectedCompleted:  0,
			expectedFailed:     0,
			expectedJobStatus:  JobStatusRunning,
		},
		{
			name:               "Add COMPLETED Task to QUEUED Job",
			initialJobStatus:   JobStatusQueued,
			taskStatusToAdd:    TaskStatusCompleted,
			expectedTotal:      1,
			expectedInProgress: 0,
			expectedCompleted:  1,
			expectedFailed:     0,
			// By our logic, if all tasks are completed, job is COMPLETED
			expectedJobStatus: JobStatusCompleted,
		},
		{
			name:               "Add FAILED Task to QUEUED Job",
			initialJobStatus:   JobStatusQueued,
			taskStatusToAdd:    TaskStatusFailed,
			expectedTotal:      1,
			expectedInProgress: 0,
			expectedCompleted:  0,
			expectedFailed:     1,
			// If all tasks are failed => job is FAILED
			expectedJobStatus: JobStatusFailed,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			job := NewJob()

			task := &Task{
				CoreTask: shared.CoreTask{ID: uuid.New()},
				status:   tc.taskStatusToAdd,
			}

			err := job.AddTask(task)
			require.NoError(t, err, "AddTask should succeed")

			metrics := job.Metrics()
			require.Equal(t, tc.expectedTotal, metrics.TotalTasks(), "TotalTasks mismatch")
			require.Equal(t, tc.expectedInProgress, metrics.InProgressTasks(), "InProgressTasks mismatch")
			require.Equal(t, tc.expectedCompleted, metrics.CompletedTasks(), "CompletedTasks mismatch")
			require.Equal(t, tc.expectedFailed, metrics.FailedTasks(), "FailedTasks mismatch")

			require.Equal(t, tc.expectedJobStatus, job.Status(), "Job status mismatch")
		})
	}
}

func TestUpdateTask(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name               string
		initialTaskStatus  TaskStatus
		newTaskStatus      TaskStatus
		expectErr          bool
		expectedInProgress int
		expectedCompleted  int
		expectedFailed     int
		expectedJobStatus  JobStatus
	}{
		// Valid transitions
		{
			name:               "IN_PROGRESS -> COMPLETED",
			initialTaskStatus:  TaskStatusInProgress,
			newTaskStatus:      TaskStatusCompleted,
			expectErr:          false,
			expectedInProgress: 0,
			expectedCompleted:  1,
			expectedFailed:     0,
			expectedJobStatus:  JobStatusCompleted,
		},
		{
			name:               "IN_PROGRESS -> FAILED",
			initialTaskStatus:  TaskStatusInProgress,
			newTaskStatus:      TaskStatusFailed,
			expectErr:          false,
			expectedInProgress: 0,
			expectedCompleted:  0,
			expectedFailed:     1,
			expectedJobStatus:  JobStatusFailed,
		},
		{
			name:               "STALE -> COMPLETED",
			initialTaskStatus:  TaskStatusStale,
			newTaskStatus:      TaskStatusCompleted,
			expectErr:          false,
			expectedInProgress: 0,
			expectedCompleted:  1,
			expectedFailed:     0,
			expectedJobStatus:  JobStatusCompleted,
		},
		// Invalid transitions.
		{
			name:               "COMPLETED -> FAILED",
			initialTaskStatus:  TaskStatusCompleted,
			newTaskStatus:      TaskStatusFailed,
			expectErr:          true,
			expectedInProgress: 0,
			expectedCompleted:  0,
			expectedFailed:     1,
			expectedJobStatus:  JobStatusFailed,
		},
		{
			name:              "COMPLETED -> IN_PROGRESS is not allowed",
			initialTaskStatus: TaskStatusCompleted,
			newTaskStatus:     TaskStatusInProgress,
			expectErr:         true,
		},
		{
			name:              "FAILED -> STALE is not allowed",
			initialTaskStatus: TaskStatusFailed,
			newTaskStatus:     TaskStatusStale,
			expectErr:         true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			job := NewJob()

			// 1) Add an initial task in the old (initial) status.
			taskID := uuid.New()
			initialTask := &Task{
				CoreTask: shared.CoreTask{ID: taskID},
				status:   tc.initialTaskStatus,
			}
			err := job.AddTask(initialTask)
			require.NoError(t, err, "failed to add initial task")

			// 2) Attempt to update the task to the new status.
			updatedTask := &Task{
				CoreTask: shared.CoreTask{ID: taskID},
				status:   tc.newTaskStatus,
			}
			err = job.UpdateTask(updatedTask)

			if tc.expectErr {
				require.Error(t, err, "UpdateTask should have returned an error for invalid transition")
				return // no further checks needed
			} else {
				require.NoError(t, err, "UpdateTask failed unexpectedly for a valid transition")
			}

			// If no error, verify counters and status.
			metrics := job.Metrics()
			require.Equal(t, 1, metrics.TotalTasks(), "Should still have exactly 1 task")
			require.Equal(t, tc.expectedInProgress, metrics.InProgressTasks(), "InProgress mismatch")
			require.Equal(t, tc.expectedCompleted, metrics.CompletedTasks(), "Completed mismatch")
			require.Equal(t, tc.expectedFailed, metrics.FailedTasks(), "Failed mismatch")

			require.Equal(t, tc.expectedJobStatus, job.Status(), "Job status mismatch")
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
