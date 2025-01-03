package enumeration

import (
	"encoding/json"
	"time"
)

// Checkpoint stores progress information for resumable target enumeration.
// It enables reliable scanning of large data sources by tracking the last
// successfully processed position.
type Checkpoint struct {
	ID        int64          `json:"id"`
	TargetID  string         `json:"target_id"`
	Data      map[string]any `json:"data"`
	UpdatedAt time.Time      `json:"updated_at"`
}

// EnumerationStatus represents the lifecycle states of an enumeration session.
type EnumerationStatus string

const (
	// StatusInitialized indicates the session is configured but hasn't started scanning.
	StatusInitialized EnumerationStatus = "initialized"
	// StatusInProgress indicates active scanning and task generation is underway.
	StatusInProgress EnumerationStatus = "in_progress"
	// StatusCompleted indicates all targets were successfully enumerated.
	StatusCompleted EnumerationStatus = "completed"
	// StatusFailed indicates the enumeration encountered an unrecoverable error.
	StatusFailed EnumerationStatus = "failed"
)

// EnumerationState tracks the progress and status of a target enumeration session.
// It maintains configuration, checkpoints, and status to enable resumable scanning
// of large data sources.
type EnumerationState struct {
	SessionID      string            `json:"session_id"`
	SourceType     string            `json:"source_type"`
	Config         json.RawMessage   `json:"config"`
	LastCheckpoint *Checkpoint       `json:"last_checkpoint"`
	LastUpdated    time.Time         `json:"last_updated"`
	Status         EnumerationStatus `json:"status"`
}

// UpdateCheckpoint updates the checkpoint and last updated time.
func (s *EnumerationState) UpdateCheckpoint(checkpoint *Checkpoint) {
	s.LastCheckpoint = checkpoint
	s.LastUpdated = time.Now()
}

// UpdateStatus changes the enumeration status and updates the timestamp.
func (s *EnumerationState) UpdateStatus(status EnumerationStatus) {
	s.Status = status
	s.LastUpdated = time.Now()
}
