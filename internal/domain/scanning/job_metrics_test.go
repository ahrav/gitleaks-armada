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
}

func TestJobMetrics_OnTaskAdded(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name               string
		status             TaskStatus
		expectedTotal      int
		expectedInProgress int
		expectedCompleted  int
		expectedFailed     int
	}{
		{
			name:               "Add IN_PROGRESS",
			status:             TaskStatusInProgress,
			expectedTotal:      1,
			expectedInProgress: 1,
			expectedCompleted:  0,
			expectedFailed:     0,
		},
		{
			name:               "Add COMPLETED",
			status:             TaskStatusCompleted,
			expectedTotal:      1,
			expectedInProgress: 0,
			expectedCompleted:  1,
			expectedFailed:     0,
		},
		{
			name:               "Add FAILED",
			status:             TaskStatusFailed,
			expectedTotal:      1,
			expectedInProgress: 0,
			expectedCompleted:  0,
			expectedFailed:     1,
		},
		{
			name:               "Add STALE",
			status:             TaskStatusStale,
			expectedTotal:      1,
			expectedInProgress: 1,
			expectedCompleted:  0,
			expectedFailed:     0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			m := NewJobMetrics()

			m.OnTaskAdded(tc.status)

			assert.Equal(t, tc.expectedTotal, m.TotalTasks())
			assert.Equal(t, tc.expectedInProgress, m.InProgressTasks())
			assert.Equal(t, tc.expectedCompleted, m.CompletedTasks())
			assert.Equal(t, tc.expectedFailed, m.FailedTasks())
		})
	}
}

func TestJobMetrics_OnTaskStatusChanged(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name               string
		oldStatus          TaskStatus
		newStatus          TaskStatus
		setupIncrements    []TaskStatus // optional statuses to call OnTaskAdded first
		expectedTotal      int
		expectedInProgress int
		expectedCompleted  int
		expectedFailed     int
	}{
		{
			name:      "IN_PROGRESS -> COMPLETED",
			oldStatus: TaskStatusInProgress,
			newStatus: TaskStatusCompleted,
			setupIncrements: []TaskStatus{
				TaskStatusInProgress, // create 1 existing in-progress
			},
			expectedTotal:      1,
			expectedInProgress: 0,
			expectedCompleted:  1,
			expectedFailed:     0,
		},
		// add more transitions ...
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			m := NewJobMetrics()

			for _, s := range tc.setupIncrements {
				m.OnTaskAdded(s)
			}

			m.OnTaskStatusChanged(tc.oldStatus, tc.newStatus)

			assert.Equal(t, tc.expectedTotal, m.TotalTasks())
			assert.Equal(t, tc.expectedInProgress, m.InProgressTasks())
			assert.Equal(t, tc.expectedCompleted, m.CompletedTasks())
			assert.Equal(t, tc.expectedFailed, m.FailedTasks())
		})
	}
}
