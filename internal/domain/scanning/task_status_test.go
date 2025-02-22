package scanning

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTaskStatus_String(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		status   TaskStatus
		expected string
	}{
		{
			name:     "pending status",
			status:   TaskStatusPending,
			expected: "PENDING",
		},
		{
			name:     "in progress status",
			status:   TaskStatusInProgress,
			expected: "IN_PROGRESS",
		},
		{
			name:     "completed status",
			status:   TaskStatusCompleted,
			expected: "COMPLETED",
		},
		{
			name:     "failed status",
			status:   TaskStatusFailed,
			expected: "FAILED",
		},
		{
			name:     "stale status",
			status:   TaskStatusStale,
			expected: "STALE",
		},
		{
			name:     "paused status",
			status:   TaskStatusPaused,
			expected: "PAUSED",
		},
		{
			name:     "unspecified status",
			status:   TaskStatusUnspecified,
			expected: "UNSPECIFIED",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.status.String())
		})
	}
}

func TestTaskStatus_ValidateTransition(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		currentStatus TaskStatus
		targetStatus  TaskStatus
		wantErr       bool
	}{
		// Valid transitions from PENDING.
		{
			name:          "pending to in progress",
			currentStatus: TaskStatusPending,
			targetStatus:  TaskStatusInProgress,
			wantErr:       false,
		},
		{
			name:          "pending to failed",
			currentStatus: TaskStatusPending,
			targetStatus:  TaskStatusFailed,
			wantErr:       false,
		},
		{
			name:          "pending to completed invalid",
			currentStatus: TaskStatusPending,
			targetStatus:  TaskStatusCompleted,
			wantErr:       true,
		},

		// Valid transitions from IN_PROGRESS.
		{
			name:          "in progress to completed",
			currentStatus: TaskStatusInProgress,
			targetStatus:  TaskStatusCompleted,
			wantErr:       false,
		},
		{
			name:          "in progress to failed",
			currentStatus: TaskStatusInProgress,
			targetStatus:  TaskStatusFailed,
			wantErr:       false,
		},
		{
			name:          "in progress to stale",
			currentStatus: TaskStatusInProgress,
			targetStatus:  TaskStatusStale,
			wantErr:       false,
		},
		{
			name:          "in progress to pending invalid",
			currentStatus: TaskStatusInProgress,
			targetStatus:  TaskStatusPending,
			wantErr:       true,
		},

		// Valid transitions from STALE.
		{
			name:          "stale to in progress",
			currentStatus: TaskStatusStale,
			targetStatus:  TaskStatusInProgress,
			wantErr:       false,
		},
		{
			name:          "stale to failed",
			currentStatus: TaskStatusStale,
			targetStatus:  TaskStatusFailed,
			wantErr:       false,
		},
		{
			name:          "stale to completed",
			currentStatus: TaskStatusStale,
			targetStatus:  TaskStatusCompleted,
			wantErr:       false,
		},
		{
			name:          "stale to pending invalid",
			currentStatus: TaskStatusStale,
			targetStatus:  TaskStatusPending,
			wantErr:       true,
		},

		// Valid transitions to/from PAUSED
		{
			name:          "pending to paused",
			currentStatus: TaskStatusPending,
			targetStatus:  TaskStatusPaused,
			wantErr:       false,
		},
		{
			name:          "in progress to paused",
			currentStatus: TaskStatusInProgress,
			targetStatus:  TaskStatusPaused,
			wantErr:       false,
		},
		{
			name:          "stale to paused",
			currentStatus: TaskStatusStale,
			targetStatus:  TaskStatusPaused,
			wantErr:       false,
		},
		{
			name:          "paused to in progress",
			currentStatus: TaskStatusPaused,
			targetStatus:  TaskStatusInProgress,
			wantErr:       false,
		},
		{
			name:          "paused to failed",
			currentStatus: TaskStatusPaused,
			targetStatus:  TaskStatusFailed,
			wantErr:       false,
		},
		{
			name:          "paused to stale",
			currentStatus: TaskStatusPaused,
			targetStatus:  TaskStatusStale,
			wantErr:       false,
		},

		// Invalid transitions from PAUSED
		{
			name:          "paused to completed invalid",
			currentStatus: TaskStatusPaused,
			targetStatus:  TaskStatusCompleted,
			wantErr:       true,
		},
		{
			name:          "paused to pending invalid",
			currentStatus: TaskStatusPaused,
			targetStatus:  TaskStatusPending,
			wantErr:       true,
		},
		{
			name:          "paused to paused invalid",
			currentStatus: TaskStatusPaused,
			targetStatus:  TaskStatusPaused,
			wantErr:       true,
		},

		// Invalid transitions from terminal states.
		{
			name:          "completed to in progress invalid",
			currentStatus: TaskStatusCompleted,
			targetStatus:  TaskStatusInProgress,
			wantErr:       true,
		},
		{
			name:          "completed to failed invalid",
			currentStatus: TaskStatusCompleted,
			targetStatus:  TaskStatusFailed,
			wantErr:       true,
		},
		{
			name:          "failed to in progress invalid",
			currentStatus: TaskStatusFailed,
			targetStatus:  TaskStatusInProgress,
			wantErr:       true,
		},
		{
			name:          "failed to completed invalid",
			currentStatus: TaskStatusFailed,
			targetStatus:  TaskStatusCompleted,
			wantErr:       true,
		},

		// Invalid transitions from UNSPECIFIED.
		{
			name:          "unspecified to any state invalid",
			currentStatus: TaskStatusUnspecified,
			targetStatus:  TaskStatusInProgress,
			wantErr:       true,
		},

		// Invalid transitions to same state.
		{
			name:          "in progress to in progress invalid",
			currentStatus: TaskStatusInProgress,
			targetStatus:  TaskStatusInProgress,
			wantErr:       true,
		},
		{
			name:          "completed to completed invalid",
			currentStatus: TaskStatusCompleted,
			targetStatus:  TaskStatusCompleted,
			wantErr:       true,
		},

		// Invalid transitions with unknown status.
		{
			name:          "unknown status transition invalid",
			currentStatus: TaskStatus("UNKNOWN"),
			targetStatus:  TaskStatusInProgress,
			wantErr:       true,
		},
		{
			name:          "transition to unknown status invalid",
			currentStatus: TaskStatusPending,
			targetStatus:  TaskStatus("UNKNOWN"),
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.currentStatus.validateTransition(tt.targetStatus)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "invalid task status transition")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestTaskStatus_IsValidTransition(t *testing.T) {
	t.Parallel()

	// Test matrix of all possible transitions.
	statuses := []TaskStatus{
		TaskStatusPending,
		TaskStatusInProgress,
		TaskStatusCompleted,
		TaskStatusFailed,
		TaskStatusStale,
		TaskStatusUnspecified,
		TaskStatus("INVALID"),
	}

	// Create a map of valid transitions for each status.
	validTransitions := map[TaskStatus]map[TaskStatus]bool{
		TaskStatusPending: {
			TaskStatusInProgress: true,
			TaskStatusFailed:     true,
		},
		TaskStatusInProgress: {
			TaskStatusCompleted: true,
			TaskStatusFailed:    true,
			TaskStatusStale:     true,
		},
		TaskStatusStale: {
			TaskStatusInProgress: true,
			TaskStatusFailed:     true,
			TaskStatusCompleted:  true,
		},
		// Terminal states and others have no valid transitions.
		TaskStatusCompleted:   {},
		TaskStatusFailed:      {},
		TaskStatusUnspecified: {},
		TaskStatus("INVALID"): {},
	}

	for _, from := range statuses {
		from := from
		t.Run(string(from), func(t *testing.T) {
			t.Parallel()

			for _, to := range statuses {
				to := to
				t.Run(string(to), func(t *testing.T) {
					t.Parallel()

					isValid := from.isValidTransition(to)
					expectedValid := false

					if transitions, ok := validTransitions[from]; ok {
						expectedValid = transitions[to]
					}

					assert.Equal(t, expectedValid, isValid,
						"Unexpected result for transition from %s to %s", from, to)
				})
			}
		})
	}
}

func TestTaskStatus_Int32(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		status   TaskStatus
		expected int32
	}{
		{
			name:     "pending status",
			status:   TaskStatusPending,
			expected: 1,
		},
		{
			name:     "in progress status",
			status:   TaskStatusInProgress,
			expected: 2,
		},
		{
			name:     "completed status",
			status:   TaskStatusCompleted,
			expected: 3,
		},
		{
			name:     "failed status",
			status:   TaskStatusFailed,
			expected: 4,
		},
		{
			name:     "stale status",
			status:   TaskStatusStale,
			expected: 5,
		},
		{
			name:     "paused status",
			status:   TaskStatusPaused,
			expected: 6,
		},
		{
			name:     "unspecified status",
			status:   TaskStatusUnspecified,
			expected: 0,
		},
		{
			name:     "invalid status",
			status:   "INVALID",
			expected: 0,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.status.Int32())
		})
	}
}

func TestTaskStatus_ProtoString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		status   TaskStatus
		expected string
	}{
		{
			name:     "pending status",
			status:   TaskStatusPending,
			expected: "TASK_STATUS_PENDING",
		},
		{
			name:     "in progress status",
			status:   TaskStatusInProgress,
			expected: "TASK_STATUS_IN_PROGRESS",
		},
		{
			name:     "completed status",
			status:   TaskStatusCompleted,
			expected: "TASK_STATUS_COMPLETED",
		},
		{
			name:     "failed status",
			status:   TaskStatusFailed,
			expected: "TASK_STATUS_FAILED",
		},
		{
			name:     "stale status",
			status:   TaskStatusStale,
			expected: "TASK_STATUS_STALE",
		},
		{
			name:     "paused status",
			status:   TaskStatusPaused,
			expected: "TASK_STATUS_PAUSED",
		},
		{
			name:     "unspecified status",
			status:   TaskStatusUnspecified,
			expected: "TASK_STATUS_UNSPECIFIED",
		},
		{
			name:     "invalid status",
			status:   "INVALID",
			expected: "TASK_STATUS_UNSPECIFIED",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.status.ProtoString())
		})
	}
}

func TestTaskStatusFromInt32(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    int32
		expected TaskStatus
	}{
		{
			name:     "pending status",
			input:    1,
			expected: TaskStatusPending,
		},
		{
			name:     "in progress status",
			input:    2,
			expected: TaskStatusInProgress,
		},
		{
			name:     "completed status",
			input:    3,
			expected: TaskStatusCompleted,
		},
		{
			name:     "failed status",
			input:    4,
			expected: TaskStatusFailed,
		},
		{
			name:     "stale status",
			input:    5,
			expected: TaskStatusStale,
		},
		{
			name:     "paused status",
			input:    6,
			expected: TaskStatusPaused,
		},
		{
			name:     "invalid status",
			input:    99,
			expected: TaskStatusUnspecified,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, TaskStatusFromInt32(tt.input))
		})
	}
}

func TestParseTaskStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected TaskStatus
	}{
		{
			name:     "pending status short",
			input:    "PENDING",
			expected: TaskStatusPending,
		},
		{
			name:     "pending status proto",
			input:    "TASK_STATUS_PENDING",
			expected: TaskStatusPending,
		},
		{
			name:     "in progress status short",
			input:    "IN_PROGRESS",
			expected: TaskStatusInProgress,
		},
		{
			name:     "in progress status proto",
			input:    "TASK_STATUS_IN_PROGRESS",
			expected: TaskStatusInProgress,
		},
		{
			name:     "completed status short",
			input:    "COMPLETED",
			expected: TaskStatusCompleted,
		},
		{
			name:     "completed status proto",
			input:    "TASK_STATUS_COMPLETED",
			expected: TaskStatusCompleted,
		},
		{
			name:     "failed status short",
			input:    "FAILED",
			expected: TaskStatusFailed,
		},
		{
			name:     "failed status proto",
			input:    "TASK_STATUS_FAILED",
			expected: TaskStatusFailed,
		},
		{
			name:     "stale status short",
			input:    "STALE",
			expected: TaskStatusStale,
		},
		{
			name:     "stale status proto",
			input:    "TASK_STATUS_STALE",
			expected: TaskStatusStale,
		},
		{
			name:     "paused status short",
			input:    "PAUSED",
			expected: TaskStatusPaused,
		},
		{
			name:     "paused status proto",
			input:    "TASK_STATUS_PAUSED",
			expected: TaskStatusPaused,
		},
		{
			name:     "invalid status",
			input:    "INVALID",
			expected: TaskStatusUnspecified,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, ParseTaskStatus(tt.input))
		})
	}
}
