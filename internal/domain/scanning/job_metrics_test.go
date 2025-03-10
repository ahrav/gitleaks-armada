package scanning

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewJobMetrics(t *testing.T) {
	metrics := NewJobMetrics()
	assert.NotNil(t, metrics)
	assert.Equal(t, 0, metrics.TotalTasks())
	assert.Equal(t, 0, metrics.CompletedTasks())
	assert.Equal(t, 0, metrics.FailedTasks())
	assert.Equal(t, 0, metrics.CancelledTasks())
	assert.Equal(t, 0, metrics.PausedTasks())
}

func TestJobMetrics_SetTotalTasks(t *testing.T) {
	tests := []struct {
		name      string
		total     int
		expected  int
		initTotal int
	}{
		{
			name:      "set positive total",
			total:     5,
			expected:  5,
			initTotal: 0,
		},
		{
			name:      "update existing total",
			total:     10,
			expected:  10,
			initTotal: 5,
		},
		{
			name:      "set zero total",
			total:     0,
			expected:  0,
			initTotal: 5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics := NewJobMetrics()
			if tt.initTotal > 0 {
				metrics.SetTotalTasks(tt.initTotal)
			}

			metrics.SetTotalTasks(tt.total)
			assert.Equal(t, tt.expected, metrics.TotalTasks())
		})
	}
}

func TestJobMetrics_UpdateTaskCounts(t *testing.T) {
	tests := []struct {
		name      string
		completed int
		failed    int
		want      struct {
			completed int
			failed    int
		}
	}{
		{
			name:      "update with positive values",
			completed: 3,
			failed:    2,
			want: struct {
				completed int
				failed    int
			}{
				completed: 3,
				failed:    2,
			},
		},
		{
			name:      "update with zero values",
			completed: 0,
			failed:    0,
			want: struct {
				completed int
				failed    int
			}{
				completed: 0,
				failed:    0,
			},
		},
		{
			name:      "update completed only",
			completed: 5,
			failed:    0,
			want: struct {
				completed int
				failed    int
			}{
				completed: 5,
				failed:    0,
			},
		},
		{
			name:      "update failed only",
			completed: 0,
			failed:    5,
			want: struct {
				completed int
				failed    int
			}{
				completed: 0,
				failed:    5,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics := NewJobMetrics()
			metrics.UpdateTaskCounts(tt.completed, tt.failed)

			assert.Equal(t, tt.want.completed, metrics.CompletedTasks())
			assert.Equal(t, tt.want.failed, metrics.FailedTasks())
		})
	}
}

func TestJobMetrics_CompletionPercentage(t *testing.T) {
	tests := []struct {
		name      string
		total     int
		completed int
		want      float64
	}{
		{
			name:      "zero total tasks",
			total:     0,
			completed: 0,
			want:      0,
		},
		{
			name:      "all tasks completed",
			total:     10,
			completed: 10,
			want:      100,
		},
		{
			name:      "half tasks completed",
			total:     10,
			completed: 5,
			want:      50,
		},
		{
			name:      "no tasks completed",
			total:     10,
			completed: 0,
			want:      0,
		},
		{
			name:      "partial completion with odd number",
			total:     3,
			completed: 2,
			want:      66.66666666666667,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics := NewJobMetrics()
			metrics.SetTotalTasks(tt.total)
			metrics.UpdateTaskCounts(tt.completed, 0)

			if tt.total != 0 && tt.completed != 0 {
				assert.InEpsilon(t, tt.want, metrics.CompletionPercentage(), 0.0001)
			} else {
				assert.Equal(t, float64(0), metrics.CompletionPercentage())
			}
		})
	}
}

func TestJobMetrics_Getters(t *testing.T) {
	t.Parallel()

	metrics := NewJobMetrics()

	metrics.SetTotalTasks(10)
	metrics.UpdateTaskCounts(5, 2)

	assert.Equal(t, 10, metrics.TotalTasks())
	assert.Equal(t, 5, metrics.CompletedTasks())
	assert.Equal(t, 2, metrics.FailedTasks())
	assert.Equal(t, 0, metrics.CancelledTasks())
	assert.Equal(t, 0, metrics.PausedTasks())
}

func TestJobMetrics_OnTaskAdded(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name               string
		statusesToAdd      []TaskStatus
		expectedTotal      int
		expectedInProgress int
		expectedCompleted  int
		expectedFailed     int
		expectedStale      int
		expectedCancelled  int
		expectedPaused     int
	}

	tests := []testCase{
		{
			name:               "Single IN_PROGRESS",
			statusesToAdd:      []TaskStatus{TaskStatusInProgress},
			expectedTotal:      1,
			expectedInProgress: 1,
			expectedCompleted:  0,
			expectedFailed:     0,
			expectedStale:      0,
			expectedCancelled:  0,
			expectedPaused:     0,
		},
		{
			name:               "Single COMPLETED",
			statusesToAdd:      []TaskStatus{TaskStatusCompleted},
			expectedTotal:      1,
			expectedInProgress: 0,
			expectedCompleted:  1,
			expectedFailed:     0,
			expectedStale:      0,
			expectedCancelled:  0,
			expectedPaused:     0,
		},
		{
			name:               "Single FAILED",
			statusesToAdd:      []TaskStatus{TaskStatusFailed},
			expectedTotal:      1,
			expectedInProgress: 0,
			expectedCompleted:  0,
			expectedFailed:     1,
			expectedStale:      0,
			expectedCancelled:  0,
			expectedPaused:     0,
		},
		{
			name:               "Single STALE",
			statusesToAdd:      []TaskStatus{TaskStatusStale},
			expectedTotal:      1,
			expectedInProgress: 0,
			expectedCompleted:  0,
			expectedFailed:     0,
			expectedStale:      1,
			expectedCancelled:  0,
			expectedPaused:     0,
		},
		{
			name:               "Single CANCELLED",
			statusesToAdd:      []TaskStatus{TaskStatusCancelled},
			expectedTotal:      1,
			expectedInProgress: 0,
			expectedCompleted:  0,
			expectedFailed:     0,
			expectedStale:      0,
			expectedCancelled:  1,
			expectedPaused:     0,
		},
		{
			name:               "Single PAUSED",
			statusesToAdd:      []TaskStatus{TaskStatusPaused},
			expectedTotal:      1,
			expectedInProgress: 0,
			expectedCompleted:  0,
			expectedFailed:     0,
			expectedStale:      0,
			expectedCancelled:  0,
			expectedPaused:     1,
		},
		{
			name: "Multiple Mixed",
			statusesToAdd: []TaskStatus{
				TaskStatusInProgress,
				TaskStatusInProgress,
				TaskStatusCompleted,
				TaskStatusFailed,
				TaskStatusStale,
				TaskStatusCancelled,
				TaskStatusPaused,
			},
			// total = 7
			// in-progress = 2 (two IN_PROGRESS)
			// completed = 1
			// failed = 1
			// stale = 1
			// cancelled = 1
			// paused = 1
			expectedTotal:      7,
			expectedInProgress: 2,
			expectedCompleted:  1,
			expectedFailed:     1,
			expectedStale:      1,
			expectedCancelled:  1,
			expectedPaused:     1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			m := NewJobMetrics()

			for _, status := range tc.statusesToAdd {
				m.OnTaskAdded(status)
			}

			assert.Equal(t, tc.expectedTotal, m.TotalTasks())
			assert.Equal(t, tc.expectedInProgress, m.InProgressTasks())
			assert.Equal(t, tc.expectedCompleted, m.CompletedTasks())
			assert.Equal(t, tc.expectedFailed, m.FailedTasks())
			assert.Equal(t, tc.expectedStale, m.StaleTasks())
			assert.Equal(t, tc.expectedCancelled, m.CancelledTasks())
			assert.Equal(t, tc.expectedPaused, m.PausedTasks())
		})
	}
}

func TestJobMetrics_OnTaskStatusChanged(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name               string
		setupStatuses      []TaskStatus // tasks to add before we do the change
		oldStatus          TaskStatus
		newStatus          TaskStatus
		expectedTotal      int
		expectedInProgress int
		expectedCompleted  int
		expectedFailed     int
		expectedStale      int
		expectedCancelled  int
		expectedPaused     int
	}

	tests := []testCase{
		{
			name:          "IN_PROGRESS -> COMPLETED (single task)",
			setupStatuses: []TaskStatus{TaskStatusInProgress},
			oldStatus:     TaskStatusInProgress,
			newStatus:     TaskStatusCompleted,
			// Initially: total=1, inprogress=1, completed=0, failed=0, stale=0, cancelled=0, paused=0
			// After transition: inprogress=0, completed=1
			expectedTotal:      1,
			expectedInProgress: 0,
			expectedCompleted:  1,
			expectedFailed:     0,
			expectedStale:      0,
			expectedCancelled:  0,
			expectedPaused:     0,
		},
		{
			name: "Multiple Tasks, transition one from STALE->FAILED",
			setupStatuses: []TaskStatus{
				TaskStatusInProgress,
				TaskStatusCompleted,
				TaskStatusStale, // We'll change this one
				TaskStatusFailed,
			},
			oldStatus: TaskStatusStale,
			newStatus: TaskStatusFailed,
			// Setup:
			// total=4
			// inprogress=1 (IN_PROGRESS)
			// completed=1
			// failed=1
			// stale=1
			// Then STALE->FAILED => stale=0, failed=2
			expectedTotal:      4,
			expectedInProgress: 1,
			expectedCompleted:  1,
			expectedFailed:     2,
			expectedStale:      0,
			expectedCancelled:  0,
			expectedPaused:     0,
		},
		{
			name: "Multiple Tasks, transition an IN_PROGRESS to COMPLETED",
			setupStatuses: []TaskStatus{
				TaskStatusInProgress,
				TaskStatusInProgress,
				TaskStatusCompleted,
				TaskStatusFailed,
				TaskStatusStale,
			},
			oldStatus: TaskStatusInProgress,
			newStatus: TaskStatusCompleted,
			// Setup:
			// total=5,
			// inprogress=2 (two IN_PROGRESS),
			// completed=1,
			// failed=1,
			// stale=1
			// After IN_PROGRESS->COMPLETED => inprogress=1, completed=2, failed=1, stale=1
			expectedTotal:      5,
			expectedInProgress: 1,
			expectedCompleted:  2,
			expectedFailed:     1,
			expectedStale:      1,
			expectedCancelled:  0,
			expectedPaused:     0,
		},
		{
			name: "Transition IN_PROGRESS to CANCELLED",
			setupStatuses: []TaskStatus{
				TaskStatusInProgress,
				TaskStatusInProgress,
				TaskStatusCompleted,
			},
			oldStatus: TaskStatusInProgress,
			newStatus: TaskStatusCancelled,
			// Setup:
			// total=3, inprogress=2, completed=1, cancelled=0
			// After transition: inprogress=1, completed=1, cancelled=1
			expectedTotal:      3,
			expectedInProgress: 1,
			expectedCompleted:  1,
			expectedFailed:     0,
			expectedStale:      0,
			expectedCancelled:  1,
			expectedPaused:     0,
		},
		{
			name: "Transition IN_PROGRESS to PAUSED",
			setupStatuses: []TaskStatus{
				TaskStatusInProgress,
				TaskStatusInProgress,
				TaskStatusCompleted,
			},
			oldStatus: TaskStatusInProgress,
			newStatus: TaskStatusPaused,
			// Setup:
			// total=3, inprogress=2, completed=1, paused=0
			// After transition: inprogress=1, completed=1, paused=1
			expectedTotal:      3,
			expectedInProgress: 1,
			expectedCompleted:  1,
			expectedFailed:     0,
			expectedStale:      0,
			expectedCancelled:  0,
			expectedPaused:     1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			m := NewJobMetrics()

			// Seed the metrics with some tasks of various statuses.
			for _, s := range tc.setupStatuses {
				m.OnTaskAdded(s)
			}

			// Change one task from oldStatus -> newStatus.
			m.OnTaskStatusChanged(tc.oldStatus, tc.newStatus)

			// Verify final counters.
			assert.Equal(t, tc.expectedTotal, m.TotalTasks())
			assert.Equal(t, tc.expectedInProgress, m.InProgressTasks())
			assert.Equal(t, tc.expectedCompleted, m.CompletedTasks())
			assert.Equal(t, tc.expectedFailed, m.FailedTasks())
			assert.Equal(t, tc.expectedStale, m.StaleTasks())
			assert.Equal(t, tc.expectedCancelled, m.CancelledTasks())
			assert.Equal(t, tc.expectedPaused, m.PausedTasks())
		})
	}
}

func TestJobMetrics_IsCompleted(t *testing.T) {
	tests := []struct {
		name     string
		metrics  *JobMetrics
		expected bool
	}{
		{
			name: "all tasks completed",
			metrics: &JobMetrics{
				totalTasks:      10,
				completedTasks:  8,
				failedTasks:     2,
				pendingTasks:    0,
				inProgressTasks: 0,
				staleTasks:      0,
				cancelledTasks:  0,
				pausedTasks:     0,
			},
			expected: true,
		},
		{
			name: "has pending tasks",
			metrics: &JobMetrics{
				totalTasks:      10,
				completedTasks:  5,
				failedTasks:     2,
				pendingTasks:    3,
				inProgressTasks: 0,
				staleTasks:      0,
				cancelledTasks:  0,
				pausedTasks:     0,
			},
			expected: false,
		},
		{
			name: "has in-progress tasks",
			metrics: &JobMetrics{
				totalTasks:      10,
				completedTasks:  7,
				failedTasks:     1,
				pendingTasks:    0,
				inProgressTasks: 2,
				staleTasks:      0,
				cancelledTasks:  0,
				pausedTasks:     0,
			},
			expected: false,
		},
		{
			name: "has stale tasks",
			metrics: &JobMetrics{
				totalTasks:      10,
				completedTasks:  8,
				failedTasks:     1,
				pendingTasks:    0,
				inProgressTasks: 0,
				staleTasks:      1,
				cancelledTasks:  0,
				pausedTasks:     0,
			},
			expected: false,
		},
		{
			name: "has cancelled and paused tasks but is still completed",
			metrics: &JobMetrics{
				totalTasks:      10,
				completedTasks:  5,
				failedTasks:     1,
				pendingTasks:    0,
				inProgressTasks: 0,
				staleTasks:      0,
				cancelledTasks:  3,
				pausedTasks:     1,
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.metrics.AllTasksTerminal(); got != tt.expected {
				t.Errorf("JobMetrics.IsCompleted() = %v, want %v", got, tt.expected)
			}
		})
	}
}
