package enumeration

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
)

// EnumerationErrorKind identifies specific types of errors that can occur during enumeration.
// This enables error handling code to make decisions based on the type of error.
type EnumerationErrorKind int

// Error kinds for enumeration operations.
const (
	// ErrKindInvalidStateTransition indicates an attempt to transition to an invalid state.
	ErrKindInvalidStateTransition EnumerationErrorKind = iota

	// ErrKindInvalidProgress indicates invalid progress tracking updates.
	ErrKindInvalidProgress

	// ErrKindMissingCheckpoint indicates a missing required checkpoint.
	ErrKindMissingCheckpoint

	// ErrKindInvalidItemCount indicates an invalid count of processed items.
	ErrKindInvalidItemCount
)

// EnumerationError represents domain-specific errors that can occur during enumeration.
// It provides context about the type of error to enable appropriate error handling.
type EnumerationError struct {
	msg  string
	kind EnumerationErrorKind
}

// Error returns the error message. This implements the error interface.
func (e *EnumerationError) Error() string { return e.msg }

// Is enables error wrapping by comparing error kinds. This implements error wrapping
// introduced in Go 1.13.
func (e *EnumerationError) Is(target error) bool {
	t, ok := target.(*EnumerationError)
	if !ok {
		return false
	}
	return e.kind == t.kind
}

// newInvalidStateTransitionError creates an error for invalid state transitions.
// It includes the attempted transition details to aid in debugging.
func newInvalidStateTransitionError(from, to Status) error {
	return &EnumerationError{
		msg:  fmt.Sprintf("cannot transition from %s to %s", from, to),
		kind: ErrKindInvalidStateTransition,
	}
}

// newInvalidProgressError creates an error for invalid progress updates.
// The message parameter provides context about why the progress update was invalid.
func newInvalidProgressError(msg string) error {
	return &EnumerationError{
		msg:  fmt.Sprintf("invalid progress update: %s", msg),
		kind: ErrKindInvalidProgress,
	}
}

// newMissingCheckpointError creates an error when a required checkpoint is missing.
// This typically occurs when trying to update progress without a valid checkpoint.
func newMissingCheckpointError() error {
	return &EnumerationError{
		msg:  "checkpoint required for progress update",
		kind: ErrKindMissingCheckpoint,
	}
}

// newInvalidItemCountError creates an error when item counts are invalid.
// This occurs when processed item counts decrease or become negative.
func newInvalidItemCountError() error {
	return &EnumerationError{
		msg:  "invalid items processed count",
		kind: ErrKindInvalidItemCount,
	}
}

type TimeProvider interface {
	Now() time.Time
}

// Real implementation for production
type realTimeProvider struct{}

func (r *realTimeProvider) Now() time.Time {
	return time.Now()
}

// Status represents the lifecycle states of an enumeration session.
// It is implemented as a value object using a string type to ensure type safety
// and domain invariants.
// The status transitions form a state machine that enforces valid lifecycle progression.
type Status string

const (
	// StatusInitialized indicates the session is configured but hasn't started scanning.
	// This is the initial valid state for new enumeration sessions.
	StatusInitialized Status = "INITIALIZED"

	// StatusInProgress indicates active scanning and task generation is underway.
	// The session can only transition to this state from StatusInitialized.
	StatusInProgress Status = "IN_PROGRESS"

	// StatusCompleted indicates all targets were successfully enumerated.
	// This is a terminal state that can only be reached from StatusInProgress.
	StatusCompleted Status = "COMPLETED"

	// StatusFailed indicates the enumeration encountered an unrecoverable error.
	// This is a terminal state that can be reached from any non-terminal state.
	StatusFailed Status = "FAILED"

	// StatusStalled indicates the enumeration has not made progress within the configured threshold.
	// This state can transition back to StatusInProgress if progress resumes.
	StatusStalled Status = "STALED"

	// StatusPartiallyCompleted indicates the enumeration completed with some failed batches.
	StatusPartiallyCompleted Status = "PARTIALLY_COMPLETED"
)

// SessionState is an aggregate root that tracks the progress and status of a target enumeration session.
// As an aggregate, it encapsulates the lifecycle and consistency boundaries of the enumeration process,
// coordinating changes to its child entities (Checkpoint) and value objects (EnumerationStatus).
// It maintains configuration, checkpoints, and status to enable resumable scanning of large data sources
// while ensuring business rules and invariants are preserved.
type SessionState struct {
	// Identity.
	sessionID  string
	sourceType string

	// Configuration.
	config json.RawMessage

	// Current state.
	status        Status
	lastUpdated   time.Time
	failureReason string

	// Progress tracking.
	lastCheckpoint *Checkpoint
	progress       *Progress

	timeProvider TimeProvider
}

// NewState creates a new enumeration State aggregate root with the provided source type and configuration.
// It enforces domain invariants by generating a unique session ID and setting the initial status.
// The domain owns identity generation to maintain aggregate consistency.
func NewState(sourceType string, config json.RawMessage) *SessionState {
	return &SessionState{
		sessionID:    uuid.New().String(),
		sourceType:   sourceType,
		config:       config,
		status:       StatusInitialized,
		lastUpdated:  time.Now(),
		timeProvider: &realTimeProvider{},
	}
}

// ReconstructState creates a State instance from persisted data without generating
// new identities or enforcing creation-time invariants.
// This should only be used by repositories when reconstructing from storage.
func ReconstructState(
	sessionID string,
	sourceType string,
	config json.RawMessage,
	status Status,
	lastUpdated time.Time,
	failureReason string,
	lastCheckpoint *Checkpoint,
	progress *Progress,
) *SessionState {
	return &SessionState{
		sessionID:      sessionID,
		sourceType:     sourceType,
		config:         config,
		status:         status,
		lastUpdated:    lastUpdated,
		failureReason:  failureReason,
		lastCheckpoint: lastCheckpoint,
		progress:       progress,
	}
}

// Getters for SessionState.
func (s *SessionState) SessionID() string           { return s.sessionID }
func (s *SessionState) SourceType() string          { return s.sourceType }
func (s *SessionState) Status() Status              { return s.status }
func (s *SessionState) Progress() *Progress         { return s.progress }
func (s *SessionState) LastCheckpoint() *Checkpoint { return s.lastCheckpoint }
func (s *SessionState) FailureReason() string       { return s.failureReason }
func (s *SessionState) Config() json.RawMessage     { return s.config }
func (s *SessionState) LastUpdated() time.Time      { return s.lastUpdated }

// HasFailedBatches returns true if any batches failed during enumeration.
func (s *SessionState) HasFailedBatches() bool {
	return s.progress != nil && s.progress.failedBatches > 0
}

// CreateTask creates a new task for this session.
func (s *SessionState) CreateTask(resourceURI string, metadata map[string]string) *Task {
	return &Task{
		CoreTask: shared.CoreTask{
			TaskID:     uuid.New().String(),
			SourceType: shared.SourceType(s.sourceType),
		},
		sessionID:   s.sessionID,
		resourceURI: resourceURI,
		metadata:    metadata,
	}
}

// MarkInProgress transitions an enumeration to the in-progress state. It initializes
// progress tracking if not already present.
func (s *SessionState) MarkInProgress() error {
	if !s.CanTransitionTo(StatusInProgress) {
		return newInvalidStateTransitionError(s.Status(), StatusInProgress)
	}

	s.setStatus(StatusInProgress)
	s.updateLastUpdated()

	if s.Progress() == nil {
		s.initializeProgress()
	}
	return nil
}

// MarkCompleted transitions an enumeration to the completed state.
func (s *SessionState) MarkCompleted() error {
	if !s.CanTransitionTo(StatusCompleted) {
		return newInvalidStateTransitionError(s.Status(), StatusCompleted)
	}

	s.setStatus(StatusCompleted)
	s.updateLastUpdated()
	return nil
}

// MarkFailed transitions an enumeration to the failed state with a reason.
func (s *SessionState) MarkFailed(reason string) error {
	if !s.CanTransitionTo(StatusFailed) {
		return newInvalidStateTransitionError(s.Status(), StatusFailed)
	}

	s.setStatus(StatusFailed)
	s.setFailureReason(reason)
	s.updateLastUpdated()
	return nil
}

// TODO: Consider setting this on the session state.
// This could open up the ability to set different thresholds for different sessions.
const defaultStallThreshold = 10 * time.Second

// RecordBatchProgress updates the enumeration state with progress from a batch.
func (s *SessionState) RecordBatchProgress(batch BatchProgress) error {
	if s.Status() != StatusInProgress {
		return newInvalidProgressError("can only update progress when in progress")
	}

	if batch.Checkpoint() == nil {
		return newMissingCheckpointError()
	}

	if batch.ItemsProcessed() < 0 {
		return newInvalidItemCountError()
	}

	// Check for stall before updating progress.
	if s.IsStalled(defaultStallThreshold) {
		s.setStatus(StatusStalled)
		return nil
	}

	s.addBatchProgress(batch)
	s.attachCheckpoint(batch.Checkpoint())

	// Check for partial completion.
	if s.HasFailedBatches() && s.Progress().ItemsProcessed() > 0 {
		s.setStatus(StatusPartiallyCompleted)
	}

	return nil
}

// IsStalled determines if an enumeration has exceeded the staleness threshold.
func (s *SessionState) IsStalled(threshold time.Duration) bool {
	if s.Progress() == nil || s.Status() != StatusInProgress {
		return false
	}

	timeSinceLastUpdate := s.timeProvider.Now().Sub(s.Progress().LastUpdate())
	return timeSinceLastUpdate > threshold
}

// validTransitions defines the allowed state transitions for enumerations.
// Empty slices indicate terminal states with no allowed transitions.
// TODO: revist this.
var validTransitions = map[Status][]Status{
	StatusInitialized: {StatusInProgress, StatusFailed},
	StatusInProgress:  {StatusCompleted, StatusFailed, StatusStalled},
	StatusStalled:     {StatusInProgress, StatusFailed, StatusCompleted},
	StatusFailed:      {}, // Terminal state
	StatusCompleted:   {}, // Terminal state
}

// CanTransitionTo validates if a state transition is allowed.
func (s *SessionState) CanTransitionTo(targetStatus Status) bool {
	allowedTransitions, exists := validTransitions[s.Status()]
	if !exists {
		return false
	}

	for _, allowed := range allowedTransitions {
		if targetStatus == allowed {
			return true
		}
	}
	return false
}

// MarshalJSON serializes the State object into a JSON byte array.
func (s *SessionState) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		SessionID      string          `json:"session_id"`
		SourceType     string          `json:"source_type"`
		Config         json.RawMessage `json:"config"`
		Status         Status          `json:"status"`
		LastUpdated    time.Time       `json:"last_updated"`
		FailureReason  string          `json:"failure_reason,omitempty"`
		LastCheckpoint *Checkpoint     `json:"last_checkpoint"`
		Progress       *Progress       `json:"progress,omitempty"`
	}{
		SessionID:      s.sessionID,
		SourceType:     s.sourceType,
		Config:         s.config,
		Status:         s.status,
		LastUpdated:    s.lastUpdated,
		FailureReason:  s.failureReason,
		LastCheckpoint: s.lastCheckpoint,
		Progress:       s.progress,
	})
}

// UnmarshalJSON deserializes JSON data into a State object.
func (s *SessionState) UnmarshalJSON(data []byte) error {
	aux := &struct {
		SessionID      string          `json:"session_id"`
		SourceType     string          `json:"source_type"`
		Config         json.RawMessage `json:"config"`
		Status         Status          `json:"status"`
		LastUpdated    time.Time       `json:"last_updated"`
		FailureReason  string          `json:"failure_reason,omitempty"`
		LastCheckpoint *Checkpoint     `json:"last_checkpoint"`
		Progress       *Progress       `json:"progress,omitempty"`
	}{
		SessionID:      s.sessionID,
		SourceType:     s.sourceType,
		Config:         s.config,
		Status:         s.status,
		LastUpdated:    s.lastUpdated,
		FailureReason:  s.failureReason,
		LastCheckpoint: s.lastCheckpoint,
		Progress:       s.progress,
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	s.sessionID = aux.SessionID
	s.sourceType = aux.SourceType
	s.config = aux.Config
	s.status = aux.Status
	s.lastUpdated = aux.LastUpdated
	s.failureReason = aux.FailureReason
	s.lastCheckpoint = aux.LastCheckpoint
	s.progress = aux.Progress

	return nil
}

// SessionState methods for internal modifications.
func (s *SessionState) setStatus(status Status) {
	s.status = status
	s.updateLastUpdated()
}

func (s *SessionState) setFailureReason(reason string) { s.failureReason = reason }

func (s *SessionState) updateLastUpdated() { s.lastUpdated = s.timeProvider.Now() }

func (s *SessionState) initializeProgress() {
	now := s.timeProvider.Now()
	s.progress = &Progress{
		startedAt:    now,
		lastUpdate:   now,
		timeProvider: s.timeProvider,
	}
}

func (s *SessionState) attachCheckpoint(cp *Checkpoint) {
	s.lastCheckpoint = cp
	s.lastUpdated = time.Now()
}

// addBatchProgress updates the enumeration state with results from a completed batch.
// It maintains aggregate progress metrics and ensures the state reflects the latest
// batch outcomes for monitoring and resumption.
func (s *SessionState) addBatchProgress(batch BatchProgress) {
	if s.progress == nil {
		s.initializeProgress()
	}

	s.progress.batches = append(s.progress.batches, batch)
	s.progress.totalBatches++
	s.progress.lastUpdate = s.timeProvider.Now()

	if batch.status == BatchStatusFailed {
		s.progress.failedBatches++
	}

	s.progress.itemsProcessed += batch.itemsProcessed
}

func (s *SessionState) withTimeProvider(tp TimeProvider) *SessionState {
	s.timeProvider = tp
	return s
}
