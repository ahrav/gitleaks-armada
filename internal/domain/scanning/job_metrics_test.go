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
	metrics := NewJobMetrics()

	metrics.SetTotalTasks(10)
	metrics.UpdateTaskCounts(5, 2)

	assert.Equal(t, 10, metrics.TotalTasks())
	assert.Equal(t, 5, metrics.CompletedTasks())
	assert.Equal(t, 2, metrics.FailedTasks())
}
