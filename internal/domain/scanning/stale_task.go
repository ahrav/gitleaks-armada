package scanning

import "github.com/ahrav/gitleaks-armada/pkg/common/uuid"

// StaleTaskInfo represents the minimal information needed for stale task processing.
type StaleTaskInfo struct {
	taskID       uuid.UUID
	jobID        uuid.UUID
	controllerID string
}

// NewStaleTaskInfo creates a new StaleTaskInfo instance.
func NewStaleTaskInfo(taskID, jobID uuid.UUID, controllerID string) StaleTaskInfo {
	return StaleTaskInfo{
		taskID:       taskID,
		jobID:        jobID,
		controllerID: controllerID,
	}
}

// ReconstructStaleTaskInfo reconstructs a StaleTaskInfo from a Task.
func ReconstructStaleTaskInfo(taskID uuid.UUID, jobID uuid.UUID, controllerID string) StaleTaskInfo {
	return StaleTaskInfo{
		taskID:       taskID,
		jobID:        jobID,
		controllerID: controllerID,
	}
}

// TaskID returns the unique identifier for this task.
func (s StaleTaskInfo) TaskID() uuid.UUID { return s.taskID }

// JobID returns the unique identifier for the job containing this task.
func (s StaleTaskInfo) JobID() uuid.UUID { return s.jobID }

// ControllerID returns the identifier of the controller responsible for this task.
func (s StaleTaskInfo) ControllerID() string { return s.controllerID }
