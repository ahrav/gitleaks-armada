package enumeration

import (
	"encoding/json"
	"time"
)

// Status represents the lifecycle states of an enumeration session.
// It is implemented as a value object using a string type to ensure type safety
// and domain invariants. The status transitions form a state machine that
// enforces valid lifecycle progression.
type Status string

const (
	// StatusInitialized indicates the session is configured but hasn't started scanning.
	// This is the initial valid state for new enumeration sessions.
	StatusInitialized Status = "initialized"
	// StatusInProgress indicates active scanning and task generation is underway.
	// The session can only transition to this state from StatusInitialized.
	StatusInProgress Status = "in_progress"
	// StatusCompleted indicates all targets were successfully enumerated.
	// This is a terminal state that can only be reached from StatusInProgress.
	StatusCompleted Status = "completed"
	// StatusFailed indicates the enumeration encountered an unrecoverable error.
	// This is a terminal state that can be reached from any non-terminal state.
	StatusFailed Status = "failed"
	// StatusStalled indicates the enumeration has not made progress within the configured threshold.
	// This state can transition back to StatusInProgress if progress resumes.
	StatusStalled Status = "stalled"
)

// Progress tracks metrics about an enumeration session's execution. It provides
// visibility into the session's timeline and processing status to enable monitoring
// and reporting of long-running enumerations.
type Progress struct {
	// Timeline.

	// StartedAt records when the enumeration session began.
	StartedAt time.Time `json:"started_at"`
	// LastUpdate tracks the most recent progress update timestamp.
	LastUpdate time.Time `json:"last_update"`

	// Metrics.

	// ItemsFound represents the total number of items discovered for processing.
	ItemsFound int `json:"items_found"`
	// ItemsProcessed tracks how many items have been successfully handled.
	ItemsProcessed int `json:"items_processed"`
}

// Checkpoint is an entity object that stores progress information for resumable target enumeration.
// It enables reliable scanning of large data sources by tracking the last successfully processed position.
// As an entity, it has a unique identity (ID) that persists across state changes and is mutable over time
// through its Data and UpdatedAt fields.
type Checkpoint struct {
	// Identity.
	ID       int64  `json:"id"`
	TargetID string `json:"target_id"`

	// State/Metadata.
	Data      map[string]any `json:"data"`
	UpdatedAt time.Time      `json:"updated_at"`
}

// State is an aggregate root that tracks the progress and status of a target enumeration session.
// As an aggregate, it encapsulates the lifecycle and consistency boundaries of the enumeration process,
// coordinating changes to its child entities (Checkpoint) and value objects (EnumerationStatus).
// It maintains configuration, checkpoints, and status to enable resumable scanning of large data sources
// while ensuring business rules and invariants are preserved.
type State struct {
	// Identity.
	SessionID  string `json:"session_id"`
	SourceType string `json:"source_type"`

	// Configuration.
	Config json.RawMessage `json:"config"`

	// Current state.
	Status        Status    `json:"status"`
	LastUpdated   time.Time `json:"last_updated"`
	FailureReason string    `json:"failure_reason,omitempty"`

	// Progress tracking.
	LastCheckpoint *Checkpoint `json:"last_checkpoint"`
	Progress       *Progress   `json:"progress,omitempty"`
}

// UpdateCheckpoint updates the checkpoint and last updated time.
func (s *State) UpdateCheckpoint(checkpoint *Checkpoint) {
	s.LastCheckpoint = checkpoint
	s.LastUpdated = time.Now()
}

// UpdateStatus changes the enumeration status and updates the timestamp.
func (s *State) UpdateStatus(status Status) {
	s.Status = status
	s.LastUpdated = time.Now()
}
