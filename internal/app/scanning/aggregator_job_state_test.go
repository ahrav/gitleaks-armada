package scanning

import (
	"testing"

	"github.com/stretchr/testify/assert"

	domain "github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/pkg/common/uuid"
)

func TestAggregatorJobState_UpdateTaskCounts(t *testing.T) {
	tests := []struct {
		name      string
		oldStatus domain.TaskStatus
		newStatus domain.TaskStatus
		initial   AggregatorJobState
		expected  AggregatorJobState
	}{
		{
			name:      "new task completion",
			oldStatus: domain.TaskStatusInProgress,
			newStatus: domain.TaskStatusCompleted,
			initial:   AggregatorJobState{completedCount: 0},
			expected:  AggregatorJobState{completedCount: 1},
		},
		{
			name:      "new task failure",
			oldStatus: domain.TaskStatusInProgress,
			newStatus: domain.TaskStatusFailed,
			initial:   AggregatorJobState{failedCount: 0},
			expected:  AggregatorJobState{failedCount: 1},
		},
		{
			name:      "new task paused",
			oldStatus: domain.TaskStatusInProgress,
			newStatus: domain.TaskStatusPaused,
			initial:   AggregatorJobState{pausedCount: 0, jobPaused: false},
			expected:  AggregatorJobState{pausedCount: 1, jobPaused: false},
		},
		{
			name:      "task unpaused",
			oldStatus: domain.TaskStatusPaused,
			newStatus: domain.TaskStatusInProgress,
			initial:   AggregatorJobState{pausedCount: 1, jobPaused: true},
			expected:  AggregatorJobState{pausedCount: 0, jobPaused: false},
		},
		{
			name:      "task cancelled",
			oldStatus: domain.TaskStatusInProgress,
			newStatus: domain.TaskStatusCancelled,
			initial:   AggregatorJobState{cancelledCount: 0},
			expected:  AggregatorJobState{cancelledCount: 1},
		},
		{
			name:      "retry failed task",
			oldStatus: domain.TaskStatusFailed,
			newStatus: domain.TaskStatusInProgress,
			initial:   AggregatorJobState{failedCount: 1},
			expected:  AggregatorJobState{failedCount: 0},
		},
		{
			name:      "no change for same status",
			oldStatus: domain.TaskStatusCompleted,
			newStatus: domain.TaskStatusCompleted,
			initial:   AggregatorJobState{completedCount: 1},
			expected:  AggregatorJobState{completedCount: 1},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := tt.initial
			state.updateTaskCounts(tt.oldStatus, tt.newStatus)

			assert.Equal(t, tt.expected.completedCount, state.completedCount)
			assert.Equal(t, tt.expected.failedCount, state.failedCount)
			assert.Equal(t, tt.expected.pausedCount, state.pausedCount)
			assert.Equal(t, tt.expected.cancelledCount, state.cancelledCount)
		})
	}
}

func TestAggregatorJobState_ShouldPauseJob(t *testing.T) {
	tests := []struct {
		name     string
		state    AggregatorJobState
		expected bool
	}{
		{
			name:     "no tasks yet",
			state:    AggregatorJobState{finalTaskCount: 0, pausedCount: 0},
			expected: false,
		},
		{
			name:     "already paused",
			state:    AggregatorJobState{finalTaskCount: 5, pausedCount: 5, jobPaused: true},
			expected: false,
		},
		{
			name: "all active tasks paused",
			state: AggregatorJobState{
				finalTaskCount: 10,
				completedCount: 2,
				failedCount:    3,
				pausedCount:    5, // 10 - (2+3) = 5 active tasks
				jobPaused:      false,
			},
			expected: true,
		},
		{
			name: "some active tasks not paused",
			state: AggregatorJobState{
				finalTaskCount: 10,
				completedCount: 2,
				failedCount:    3,
				pausedCount:    4, // 10 - (2+3) = 5 active tasks, only 4 paused
				jobPaused:      false,
			},
			expected: false,
		},
		{
			name: "no active tasks",
			state: AggregatorJobState{
				finalTaskCount: 5,
				completedCount: 3,
				failedCount:    2,
				pausedCount:    0,
				jobPaused:      false,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.state.shouldPauseJob()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAggregatorJobState_ShouldCancelJob(t *testing.T) {
	tests := []struct {
		name     string
		state    AggregatorJobState
		expected bool
	}{
		{
			name:     "no tasks yet",
			state:    AggregatorJobState{finalTaskCount: 0, cancelledCount: 0},
			expected: false,
		},
		{
			name:     "already cancelled",
			state:    AggregatorJobState{finalTaskCount: 5, cancelledCount: 5, jobCancelled: true},
			expected: false,
		},
		{
			name: "all active tasks cancelled",
			state: AggregatorJobState{
				finalTaskCount: 10,
				completedCount: 2,
				failedCount:    3,
				cancelledCount: 5, // 10 - (2+3) = 5 active tasks
				jobCancelled:   false,
			},
			expected: true,
		},
		{
			name: "some active tasks not cancelled",
			state: AggregatorJobState{
				finalTaskCount: 10,
				completedCount: 2,
				failedCount:    3,
				cancelledCount: 4, // 10 - (2+3) = 5 active tasks, only 4 cancelled
				jobCancelled:   false,
			},
			expected: false,
		},
		{
			name: "no active tasks",
			state: AggregatorJobState{
				finalTaskCount: 5,
				completedCount: 3,
				failedCount:    2,
				cancelledCount: 0,
				jobCancelled:   false,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.state.shouldCancelJob()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAggregatorJobState_ShouldResumeJob(t *testing.T) {
	tests := []struct {
		name     string
		state    AggregatorJobState
		expected bool
	}{
		{
			name: "job not paused",
			state: AggregatorJobState{
				finalTaskCount: 5,
				pausedCount:    3,
				jobPaused:      false,
			},
			expected: false,
		},
		{
			name: "no tasks yet",
			state: AggregatorJobState{
				finalTaskCount: 0,
				pausedCount:    0,
				jobPaused:      true,
			},
			expected: false,
		},
		{
			name: "all active tasks still paused",
			state: AggregatorJobState{
				finalTaskCount: 10,
				completedCount: 2,
				failedCount:    3,
				cancelledCount: 0,
				pausedCount:    5, // All 5 remaining active tasks are paused
				jobPaused:      true,
			},
			expected: false,
		},
		{
			name: "some active tasks resumed",
			state: AggregatorJobState{
				finalTaskCount: 10,
				completedCount: 2,
				failedCount:    3,
				cancelledCount: 0,
				pausedCount:    4, // Only 4 of 5 active tasks are paused
				jobPaused:      true,
			},
			expected: true,
		},
		{
			name: "all active tasks resumed",
			state: AggregatorJobState{
				finalTaskCount: 10,
				completedCount: 5,
				failedCount:    3,
				cancelledCount: 0,
				pausedCount:    0, // No tasks paused
				jobPaused:      true,
			},
			expected: true,
		},
		{
			name: "no active tasks, all complete or failed",
			state: AggregatorJobState{
				finalTaskCount: 10,
				completedCount: 6,
				failedCount:    4,
				cancelledCount: 0,
				pausedCount:    0,
				jobPaused:      true,
			},
			expected: false,
		},
		{
			name: "with cancelled tasks",
			state: AggregatorJobState{
				finalTaskCount: 10,
				completedCount: 3,
				failedCount:    2,
				cancelledCount: 3,
				pausedCount:    1, // 1 of 2 remaining active tasks still paused
				jobPaused:      true,
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.state.shouldResumeJob()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAggregatorJobState_SetEnumerationComplete(t *testing.T) {
	tests := []struct {
		name      string
		taskCount int
		initial   AggregatorJobState
		expected  AggregatorJobState
	}{
		{
			name:      "set with zero tasks",
			taskCount: 0,
			initial:   AggregatorJobState{enumerationDone: false, finalTaskCount: 0},
			expected:  AggregatorJobState{enumerationDone: true, finalTaskCount: 0},
		},
		{
			name:      "set with positive task count",
			taskCount: 42,
			initial:   AggregatorJobState{enumerationDone: false, finalTaskCount: 0},
			expected:  AggregatorJobState{enumerationDone: true, finalTaskCount: 42},
		},
		{
			name:      "overwrite existing count",
			taskCount: 100,
			initial:   AggregatorJobState{enumerationDone: false, finalTaskCount: 50},
			expected:  AggregatorJobState{enumerationDone: true, finalTaskCount: 100},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := tt.initial
			state.setEnumerationComplete(tt.taskCount)

			assert.Equal(t, tt.expected.enumerationDone, state.enumerationDone)
			assert.Equal(t, tt.expected.finalTaskCount, state.finalTaskCount)
		})
	}
}

func TestAggregatorJobState_IsDone(t *testing.T) {
	tests := []struct {
		name     string
		state    AggregatorJobState
		expected bool
	}{
		{
			name: "not enumerated yet",
			state: AggregatorJobState{
				enumerationDone: false,
				finalTaskCount:  10,
				completedCount:  5,
				failedCount:     5,
			},
			expected: false,
		},
		{
			name: "enumerated but no tasks",
			state: AggregatorJobState{
				enumerationDone: true,
				finalTaskCount:  0,
				completedCount:  0,
				failedCount:     0,
			},
			expected: false,
		},
		{
			name: "tasks in progress",
			state: AggregatorJobState{
				enumerationDone: true,
				finalTaskCount:  10,
				completedCount:  5,
				failedCount:     2,
			},
			expected: false,
		},
		{
			name: "all tasks completed",
			state: AggregatorJobState{
				enumerationDone: true,
				finalTaskCount:  10,
				completedCount:  10,
				failedCount:     0,
			},
			expected: true,
		},
		{
			name: "all tasks failed",
			state: AggregatorJobState{
				enumerationDone: true,
				finalTaskCount:  10,
				completedCount:  0,
				failedCount:     10,
			},
			expected: true,
		},
		{
			name: "mix of completed and failed",
			state: AggregatorJobState{
				enumerationDone: true,
				finalTaskCount:  10,
				completedCount:  7,
				failedCount:     3,
			},
			expected: true,
		},
		{
			name: "tasks paused but not done",
			state: AggregatorJobState{
				enumerationDone: true,
				finalTaskCount:  10,
				completedCount:  5,
				failedCount:     2,
				pausedCount:     3,
			},
			expected: false,
		},
		{
			name: "tasks cancelled but not done",
			state: AggregatorJobState{
				enumerationDone: true,
				finalTaskCount:  10,
				completedCount:  5,
				failedCount:     2,
				cancelledCount:  3,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.state.isDone()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAggregatorJobState_CompleteWorkflow(t *testing.T) {
	// Test a complete workflow from start to finish
	state := AggregatorJobState{jobID: uuid.New()}

	// 1. Set enumeration complete with 3 tasks.
	state.setEnumerationComplete(3)
	assert.True(t, state.enumerationDone)
	assert.Equal(t, 3, state.finalTaskCount)
	assert.False(t, state.isDone())

	// 2. Complete first task.
	state.updateTaskCounts(domain.TaskStatusInProgress, domain.TaskStatusCompleted)
	assert.Equal(t, 1, state.completedCount)
	assert.False(t, state.isDone())

	// 3. Fail second task.
	state.updateTaskCounts(domain.TaskStatusInProgress, domain.TaskStatusFailed)
	assert.Equal(t, 1, state.failedCount)
	assert.False(t, state.isDone())

	// 4. Complete third task.
	state.updateTaskCounts(domain.TaskStatusInProgress, domain.TaskStatusCompleted)
	assert.Equal(t, 2, state.completedCount)
	assert.True(t, state.isDone())
}

func TestAggregatorJobState_PauseWorkflow(t *testing.T) {
	// Test a workflow that gets paused.
	state := AggregatorJobState{jobID: uuid.New()}

	// 1. Set enumeration complete with 3 tasks.
	state.setEnumerationComplete(3)
	assert.False(t, state.shouldPauseJob())

	// 2. Complete first task.
	state.updateTaskCounts(domain.TaskStatusInProgress, domain.TaskStatusCompleted)
	assert.Equal(t, 1, state.completedCount)
	assert.False(t, state.shouldPauseJob())

	// 3. Pause second task.
	state.updateTaskCounts(domain.TaskStatusInProgress, domain.TaskStatusPaused)
	assert.Equal(t, 1, state.pausedCount)
	assert.False(t, state.shouldPauseJob())

	// 4. Pause third task - all remaining active tasks are paused now.
	state.updateTaskCounts(domain.TaskStatusInProgress, domain.TaskStatusPaused)
	assert.Equal(t, 2, state.pausedCount)
	assert.True(t, state.shouldPauseJob())

	// 5. Resume one task.
	state.updateTaskCounts(domain.TaskStatusPaused, domain.TaskStatusInProgress)
	assert.Equal(t, 1, state.pausedCount)
	assert.False(t, state.shouldPauseJob())
}

func TestAggregatorJobState_CancelWorkflow(t *testing.T) {
	// Test a workflow that gets cancelled.
	state := AggregatorJobState{jobID: uuid.New()}

	// 1. Set enumeration complete with 3 tasks.
	state.setEnumerationComplete(3)
	assert.False(t, state.shouldCancelJob())

	// 2. Complete first task.
	state.updateTaskCounts(domain.TaskStatusInProgress, domain.TaskStatusCompleted)
	assert.Equal(t, 1, state.completedCount)
	assert.False(t, state.shouldCancelJob())

	// 3. Cancel second task.
	state.updateTaskCounts(domain.TaskStatusInProgress, domain.TaskStatusCancelled)
	assert.Equal(t, 1, state.cancelledCount)
	assert.False(t, state.shouldCancelJob())

	// 4. Cancel third task - all remaining active tasks are cancelled now.
	state.updateTaskCounts(domain.TaskStatusInProgress, domain.TaskStatusCancelled)
	assert.Equal(t, 2, state.cancelledCount)
	assert.True(t, state.shouldCancelJob())

	// 5. Mark job as cancelled.
	state.jobCancelled = true
	assert.False(t, state.shouldCancelJob())
}

func TestAggregatorJobState_ResumeWorkflow(t *testing.T) {
	// Test a workflow that gets paused and then resumed.
	state := AggregatorJobState{jobID: uuid.New()}

	// 1. Set enumeration complete with 3 tasks.
	state.setEnumerationComplete(3)
	assert.False(t, state.shouldPauseJob())
	assert.False(t, state.shouldResumeJob())

	// 2. Pause all tasks to trigger job pause.
	state.updateTaskCounts(domain.TaskStatusInProgress, domain.TaskStatusPaused)
	state.updateTaskCounts(domain.TaskStatusInProgress, domain.TaskStatusPaused)
	state.updateTaskCounts(domain.TaskStatusInProgress, domain.TaskStatusPaused)
	assert.Equal(t, 3, state.pausedCount)
	assert.True(t, state.shouldPauseJob())

	// 3. Simulate job being marked as paused externally.
	state.jobPaused = true
	assert.False(t, state.shouldPauseJob())  // Already paused
	assert.False(t, state.shouldResumeJob()) // All tasks still paused

	// 4. Resume one task.
	state.updateTaskCounts(domain.TaskStatusPaused, domain.TaskStatusInProgress)
	assert.Equal(t, 2, state.pausedCount)
	assert.True(t, state.shouldResumeJob())

	// 5. Simulate job being resumed externally.
	state.jobPaused = false
	assert.False(t, state.shouldResumeJob()) // Already resumed

	// 6. Resume all tasks.
	state.updateTaskCounts(domain.TaskStatusPaused, domain.TaskStatusInProgress)
	state.updateTaskCounts(domain.TaskStatusPaused, domain.TaskStatusInProgress)
	assert.Equal(t, 0, state.pausedCount)
	assert.False(t, state.shouldPauseJob())
	assert.False(t, state.shouldResumeJob())
}
