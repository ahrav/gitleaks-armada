package scanning

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/ahrav/gitleaks-armada/pkg/common/uuid"
)

// Checkpoint contains the state needed to resume a scan after interruption.
// This enables fault tolerance by preserving progress markers and context.
type Checkpoint struct {
	taskID      uuid.UUID
	timestamp   time.Time
	resumeToken []byte
	metadata    map[string]string
}

// NewCheckpoint creates a new Checkpoint for tracking scan progress.
// It establishes initial state for resuming interrupted scans.
func NewCheckpoint(
	taskID uuid.UUID,
	resumeToken []byte,
	metadata map[string]string,
) *Checkpoint {
	return &Checkpoint{
		taskID:      taskID,
		timestamp:   time.Now(),
		resumeToken: resumeToken,
		metadata:    metadata,
	}
}

// ReconstructCheckpoint creates a Checkpoint instance from persisted data.
// This should only be used by repositories when reconstructing from storage.
func ReconstructCheckpoint(
	taskID uuid.UUID,
	timestamp time.Time,
	resumeToken []byte,
	metadata map[string]string,
) *Checkpoint {
	return &Checkpoint{
		taskID:      taskID,
		timestamp:   timestamp,
		resumeToken: resumeToken,
		metadata:    metadata,
	}
}

// TaskID returns the unique identifier for this scan task.
func (c *Checkpoint) TaskID() uuid.UUID { return c.taskID }

// Timestamp returns the time the checkpoint was created.
func (c *Checkpoint) Timestamp() time.Time { return c.timestamp }

// ResumeToken returns the token used to resume a scan after interruption.
func (c *Checkpoint) ResumeToken() []byte { return c.resumeToken }

// Metadata returns any additional metadata associated with this checkpoint.
func (c *Checkpoint) Metadata() map[string]string { return c.metadata }

// MarshalJSON serializes the Checkpoint object into a JSON byte array.
func (c *Checkpoint) MarshalJSON() ([]byte, error) {
	// Defensive: if c is nil, return JSON "null" (or error, depending on preference)
	if c == nil {
		return []byte("null"), nil
	}

	// Define an inner type to avoid infinite recursion of MarshalJSON.
	type checkpointDTO struct {
		TaskID      string            `json:"task_id"`
		Timestamp   time.Time         `json:"timestamp"`
		ResumeToken []byte            `json:"resume_token"`
		Metadata    map[string]string `json:"metadata"`
	}

	dto := checkpointDTO{
		TaskID:      c.taskID.String(), // zero-value UUID -> "00000000-0000-0000-0000-000000000000"
		Timestamp:   c.timestamp,
		ResumeToken: c.resumeToken,
		Metadata:    c.metadata,
	}

	return json.Marshal(&dto)
}

// UnmarshalJSON deserializes JSON data into a Checkpoint object.
func (c *Checkpoint) UnmarshalJSON(data []byte) error {
	// Defensive: if c is nil, we can't populate it
	if c == nil {
		return fmt.Errorf("cannot unmarshal JSON into nil Checkpoint")
	}

	// Matching DTO for reading JSON
	type checkpointDTO struct {
		TaskID      string            `json:"task_id"`
		Timestamp   time.Time         `json:"timestamp"`
		ResumeToken []byte            `json:"resume_token"`
		Metadata    map[string]string `json:"metadata"`
	}

	var aux checkpointDTO
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	taskID, err := uuid.Parse(aux.TaskID)
	if err != nil {
		return fmt.Errorf("invalid task ID: %w", err)
	}

	c.taskID = taskID
	c.timestamp = aux.Timestamp
	c.resumeToken = aux.ResumeToken
	c.metadata = aux.Metadata

	return nil
}
