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
