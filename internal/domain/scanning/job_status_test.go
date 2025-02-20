package scanning

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateTransition_ValidTransitions(t *testing.T) {
	tests := []struct {
		name    string
		current JobStatus
		target  JobStatus
	}{
		{
			name:    "Queued to Enumerating is valid",
			current: JobStatusQueued,
			target:  JobStatusEnumerating,
		},
		{
			name:    "Enumerating to Running is valid",
			current: JobStatusEnumerating,
			target:  JobStatusRunning,
		},
		{
			name:    "Enumerating to Completed is valid",
			current: JobStatusEnumerating,
			target:  JobStatusCompleted,
		},
		{
			name:    "Enumerating to Failed is valid",
			current: JobStatusEnumerating,
			target:  JobStatusFailed,
		},
		{
			name:    "Running to Completed is valid",
			current: JobStatusRunning,
			target:  JobStatusCompleted,
		},
		{
			name:    "Running to Failed is valid",
			current: JobStatusRunning,
			target:  JobStatusFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.current.validateTransition(tt.target)
			assert.NoError(t, err, "expected valid transition from %s to %s", tt.current, tt.target)
		})
	}
}

func TestValidateTransition_InvalidTransitions(t *testing.T) {
	tests := []struct {
		name    string
		current JobStatus
		target  JobStatus
	}{
		{
			name:    "Queued to Running is invalid",
			current: JobStatusQueued,
			target:  JobStatusRunning,
		},
		{
			name:    "Queued to Completed is invalid",
			current: JobStatusQueued,
			target:  JobStatusCompleted,
		},
		{
			name:    "Queued to Failed is invalid",
			current: JobStatusQueued,
			target:  JobStatusFailed,
		},
		{
			name:    "Queued to Queued is invalid",
			current: JobStatusQueued,
			target:  JobStatusQueued,
		},
		{
			name:    "Enumerating to Enumerating is invalid",
			current: JobStatusEnumerating,
			target:  JobStatusEnumerating,
		},
		{
			name:    "Enumerating to Queued is invalid",
			current: JobStatusEnumerating,
			target:  JobStatusQueued,
		},
		{
			name:    "Running to Running is invalid",
			current: JobStatusRunning,
			target:  JobStatusRunning,
		},
		{
			name:    "Running to Queued is invalid",
			current: JobStatusRunning,
			target:  JobStatusQueued,
		},
		{
			name:    "Running to Enumerating is invalid",
			current: JobStatusRunning,
			target:  JobStatusEnumerating,
		},
		{
			name:    "Completed to any state is invalid",
			current: JobStatusCompleted,
			target:  JobStatusQueued, // or any other target
		},
		{
			name:    "Failed to any state is invalid",
			current: JobStatusFailed,
			target:  JobStatusCompleted, // or any other target
		},
		{
			name:    "Empty status to a valid target is invalid",
			current: "",
			target:  JobStatusQueued,
		},
		{
			name:    "Valid status to empty status is invalid",
			current: JobStatusQueued,
			target:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.current.validateTransition(tt.target)
			assert.Error(t, err, "expected error for invalid transition from %s to %s", tt.current, tt.target)
		})
	}
}
