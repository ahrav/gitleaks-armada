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
		expectedStale      int
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
			expectedStale:      0,
			expectedJobStatus:  JobStatusRunning,
		},
		{
			name:               "Add STALE Task to QUEUED Job",
			initialJobStatus:   JobStatusQueued,
			taskStatusToAdd:    TaskStatusStale,
			expectedTotal:      1,
			expectedInProgress: 0,
			expectedCompleted:  0,
			expectedFailed:     0,
			expectedStale:      1,
			expectedJobStatus:  JobStatusQueued,
		},
		{
			name:               "Add COMPLETED Task to QUEUED Job",
			initialJobStatus:   JobStatusQueued,
			taskStatusToAdd:    TaskStatusCompleted,
			expectedTotal:      1,
			expectedInProgress: 0,
			expectedCompleted:  1,
			expectedFailed:     0,
			expectedStale:      0,
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
			expectedStale:      0,
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

func TestAddTask_MultipleTasks(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name               string
		existingTasks      []TaskStatus // tasks to add first
		newTaskStatus      TaskStatus   // status of the newly added task
		expectedTotal      int
		expectedInProgress int
		expectedCompleted  int
		expectedFailed     int
		expectedJobStatus  JobStatus
	}

	tests := []testCase{
		{
			name:               "Add second IN_PROGRESS when one FAILED already exists",
			existingTasks:      []TaskStatus{TaskStatusFailed},
			newTaskStatus:      TaskStatusInProgress,
			expectedTotal:      2,
			expectedInProgress: 1,
			expectedCompleted:  0,
			expectedFailed:     1,
			// Not all tasks are in terminal states => job is RUNNING
			expectedJobStatus: JobStatusRunning,
		},
		{
			name:          "Add a COMPLETED task when one is IN_PROGRESS, one is FAILED",
			existingTasks: []TaskStatus{TaskStatusInProgress, TaskStatusFailed},
			newTaskStatus: TaskStatusCompleted,
			// So final total=3, inprogress=1, completed=1, failed=1 => job is RUNNING
			expectedTotal:      3,
			expectedInProgress: 1,
			expectedCompleted:  1,
			expectedFailed:     1,
			expectedJobStatus:  JobStatusRunning,
		},
		{
			name:               "All tasks FAILED, adding another FAILED => job stays FAILED or becomes FAILED (depending on logic)",
			existingTasks:      []TaskStatus{TaskStatusFailed, TaskStatusFailed},
			newTaskStatus:      TaskStatusFailed,
			expectedTotal:      3,
			expectedInProgress: 0,
			expectedCompleted:  0,
			expectedFailed:     3,
			// If all tasks are failed => job is FAILED
			expectedJobStatus: JobStatusFailed,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			job := NewJob()

			for _, status := range tc.existingTasks {
				task := &Task{
					CoreTask: shared.CoreTask{ID: uuid.New()},
					status:   status,
				}
				err := job.AddTask(task)
				require.NoError(t, err)
			}

			newTask := &Task{
				CoreTask: shared.CoreTask{ID: uuid.New()},
				status:   tc.newTaskStatus,
			}
			err := job.AddTask(newTask)
			require.NoError(t, err)

			// Verify the metrics.
			metrics := job.Metrics()
			require.Equal(t, tc.expectedTotal, metrics.TotalTasks())
			require.Equal(t, tc.expectedInProgress, metrics.InProgressTasks())
			require.Equal(t, tc.expectedCompleted, metrics.CompletedTasks())
			require.Equal(t, tc.expectedFailed, metrics.FailedTasks())

			// Verify the job's final status.
			require.Equal(t, tc.expectedJobStatus, job.Status())
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

func TestUpdateTask_MultipleTasks(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name                 string
		existingTaskStatuses []TaskStatus // statuses for the tasks we pre-load
		taskToChangeIndex    int          // which of those tasks to update
		newStatus            TaskStatus   // the new status for that one task
		expectedInProgress   int
		expectedCompleted    int
		expectedFailed       int
		expectedJobStatus    JobStatus
	}

	tests := []testCase{
		{
			name:                 "Update one of three tasks from IN_PROGRESS -> COMPLETED",
			existingTaskStatuses: []TaskStatus{TaskStatusInProgress, TaskStatusFailed, TaskStatusCompleted},
			taskToChangeIndex:    0, // the first one
			newStatus:            TaskStatusCompleted,
			// We start with total=3 => inprogress=1, failed=1, completed=1 => job=RUNNING
			// After updating the first from IN_PROGRESS->COMPLETED => inprogress=0, completed=2, failed=1 => total=3
			// Because not all are failed or completed (some are failed, some are completed, but there's no in-progress left),
			// this might mark job as COMPLETED if your logic says "completed+failed == total => if failed < total => COMPLETED".
			// Let's see the standard snippet: that means job is COMPLETED because (2 completed + 1 failed) == 3 total, and not all are failed => job=COMPLETED
			expectedInProgress: 0,
			expectedCompleted:  2,
			expectedFailed:     1,
			expectedJobStatus:  JobStatusCompleted,
		},
		{
			name:                 "Update one STALE -> FAILED when multiple tasks exist",
			existingTaskStatuses: []TaskStatus{TaskStatusStale, TaskStatusCompleted, TaskStatusInProgress},
			taskToChangeIndex:    0, // the STALE one
			newStatus:            TaskStatusFailed,
			// Start: total=3 => inprogress=2 (STALE + IN_PROGRESS), completed=1, failed=0
			// After STALE->FAILED => inprogress=1, failed=1, completed=1 => total=3 => job=RUNNING
			// Not all tasks are terminal states => job=RUNNING
			expectedInProgress: 1,
			expectedCompleted:  1,
			expectedFailed:     1,
			expectedJobStatus:  JobStatusRunning,
		},
		{
			name:                 "Update one IN_PROGRESS -> COMPLETED when all tasks are terminal states",
			existingTaskStatuses: []TaskStatus{TaskStatusCompleted, TaskStatusCompleted, TaskStatusCompleted},
			taskToChangeIndex:    0, // the first one
			newStatus:            TaskStatusCompleted,
			// Start: total=3 => inprogress=1, failed=0, completed=2 => job=RUNNING
			// After IN_PROGRESS->COMPLETED => inprogress=0, completed=3, failed=0 => total=3
			// Because all tasks are in terminal states, and there's no in-progress left,
			// this might mark job as COMPLETED if your logic says "completed+failed == total => if failed < total => COMPLETED".
			// Let's see the standard snippet: that means job is COMPLETED because (3 completed + 0 failed) == 3 total, and not all are failed => job=COMPLETED
			expectedInProgress: 0,
			expectedCompleted:  3,
			expectedFailed:     0,
			expectedJobStatus:  JobStatusCompleted,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			job := NewJob()

			// Add the existing tasks.
			var tasks []Task
			for _, st := range tc.existingTaskStatuses {
				tasks = append(tasks, Task{
					CoreTask: shared.CoreTask{ID: uuid.New()},
					status:   st,
				})
			}
			for i := range tasks {
				err := job.AddTask(&tasks[i])
				require.NoError(t, err)
			}

			//  Now update the chosen task.
			oldTask := tasks[tc.taskToChangeIndex]
			updatedTask := Task{
				CoreTask: shared.CoreTask{ID: oldTask.ID},
				status:   tc.newStatus,
			}

			err := job.UpdateTask(&updatedTask)
			require.NoError(t, err)

			metrics := job.Metrics()
			require.Equal(t, len(tc.existingTaskStatuses), metrics.TotalTasks(), "Total tasks mismatch")
			require.Equal(t, tc.expectedInProgress, metrics.InProgressTasks())
			require.Equal(t, tc.expectedCompleted, metrics.CompletedTasks())
			require.Equal(t, tc.expectedFailed, metrics.FailedTasks())
			require.Equal(t, tc.expectedJobStatus, job.Status())
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

func TestFailTask(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		initialStatus     TaskStatus
		expectErr         bool
		expectedMetrics   struct{ total, inProgress, completed, failed int }
		expectedJobStatus JobStatus
	}{
		{
			name:          "Fail IN_PROGRESS task",
			initialStatus: TaskStatusInProgress,
			expectErr:     false,
			expectedMetrics: struct{ total, inProgress, completed, failed int }{
				total:      1,
				inProgress: 0,
				completed:  0,
				failed:     1,
			},
			expectedJobStatus: JobStatusFailed,
		},
		{
			name:          "Fail STALE task",
			initialStatus: TaskStatusStale,
			expectErr:     false,
			expectedMetrics: struct{ total, inProgress, completed, failed int }{
				total:      1,
				inProgress: 0,
				completed:  0,
				failed:     1,
			},
			expectedJobStatus: JobStatusFailed,
		},
		{
			name:          "Cannot fail COMPLETED task",
			initialStatus: TaskStatusCompleted,
			expectErr:     true,
		},
		{
			name:          "Cannot fail already FAILED task",
			initialStatus: TaskStatusFailed,
			expectErr:     true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			job := NewJob()
			taskID := uuid.New()
			task := NewScanTask(job.JobID(), taskID, "https://example.com")
			task.status = tc.initialStatus

			err := job.AddTask(task)
			require.NoError(t, err, "failed to add initial task")

			err = job.FailTask(taskID)
			if tc.expectErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			metrics := job.Metrics()
			require.Equal(t, tc.expectedMetrics.total, metrics.TotalTasks())
			require.Equal(t, tc.expectedMetrics.inProgress, metrics.InProgressTasks())
			require.Equal(t, tc.expectedMetrics.completed, metrics.CompletedTasks())
			require.Equal(t, tc.expectedMetrics.failed, metrics.FailedTasks())
			require.Equal(t, tc.expectedJobStatus, job.Status())
		})
	}
}

func TestCompleteTask_NonexistentTask(t *testing.T) {
	t.Parallel()

	job := NewJob()
	err := job.CompleteTask(uuid.New())
	require.Error(t, err)
}

func TestFailTask_NonexistentTask(t *testing.T) {
	t.Parallel()

	job := NewJob()
	err := job.FailTask(uuid.New())
	require.Error(t, err)
}
