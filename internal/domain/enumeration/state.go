package enumeration

import (
	"encoding/json"
	"time"
)

// EnumerationState is an aggregate root that tracks the progress and status of a target enumeration session.
// As an aggregate, it encapsulates the lifecycle and consistency boundaries of the enumeration process,
// coordinating changes to its child entities (Checkpoint) and value objects (EnumerationStatus).
// It maintains configuration, checkpoints, and status to enable resumable scanning of large data sources
// while ensuring business rules and invariants are preserved.
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
