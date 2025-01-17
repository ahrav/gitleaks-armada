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
// coordinating changes to its child entities (Checkpoint) and value objects (Timeline, SessionMetrics).
type SessionState struct {
	// Identity
	sessionID  uuid.UUID
	sourceType string

	// Configuration
	config json.RawMessage

	// State
	status        Status
	failureReason string

	// Domain objects
	timeline       *Timeline
	metrics        *SessionMetrics
	lastCheckpoint *Checkpoint
}

// StateOption defines functional options for configuring a new SessionState.
type StateOption func(*SessionState)

// WithSessionTimeProvider sets a custom time provider for the session.
func WithSessionTimeProvider(tp TimeProvider) StateOption {
	return func(s *SessionState) { s.timeline = NewTimeline(tp) }
}

// NewState creates a new enumeration State aggregate root with the provided source type and configuration.
// It enforces domain invariants by generating a unique session ID and setting the initial status.
func NewState(sourceType string, config json.RawMessage, opts ...StateOption) *SessionState {
	state := &SessionState{
		sessionID:  uuid.New(),
		sourceType: sourceType,
		config:     config,
		status:     StatusInitialized,
		timeline:   NewTimeline(new(realTimeProvider)),
		metrics:    NewSessionMetrics(),
	}

	for _, opt := range opts {
		opt(state)
	}

	return state
}

// ReconstructState creates a State instance from persisted data without generating
// new identities or enforcing creation-time invariants.
// This should only be used by repositories when reconstructing from storage.
func ReconstructState(
	sessionID uuid.UUID,
	sourceType string,
	config json.RawMessage,
	status Status,
	timeline *Timeline,
	failureReason string,
	lastCheckpoint *Checkpoint,
	metrics *SessionMetrics,
) *SessionState {
	return &SessionState{
		sessionID:      sessionID,
		sourceType:     sourceType,
		config:         config,
		status:         status,
		timeline:       timeline,
		failureReason:  failureReason,
		lastCheckpoint: lastCheckpoint,
		metrics:        metrics,
	}
}

// Getters for the SessionState.
func (s *SessionState) SessionID() uuid.UUID        { return s.sessionID }
func (s *SessionState) SourceType() string          { return s.sourceType }
func (s *SessionState) Status() Status              { return s.status }
func (s *SessionState) Timeline() *Timeline         { return s.timeline }
func (s *SessionState) LastCheckpoint() *Checkpoint { return s.lastCheckpoint }
func (s *SessionState) FailureReason() string       { return s.failureReason }
func (s *SessionState) Config() json.RawMessage     { return s.config }
func (s *SessionState) Metrics() *SessionMetrics    { return s.metrics }

// MarshalJSON serializes the State object into a JSON byte array.
func (s *SessionState) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		SessionID      string          `json:"session_id"`
		SourceType     string          `json:"source_type"`
		Config         json.RawMessage `json:"config"`
		Status         Status          `json:"status"`
		FailureReason  string          `json:"failure_reason,omitempty"`
		LastCheckpoint *Checkpoint     `json:"last_checkpoint"`
		Timeline       *Timeline       `json:"timeline"`
		Metrics        *SessionMetrics `json:"metrics"`
	}{
		SessionID:      s.sessionID.String(),
		SourceType:     s.sourceType,
		Config:         s.config,
		Status:         s.status,
		FailureReason:  s.failureReason,
		LastCheckpoint: s.lastCheckpoint,
		Timeline:       s.timeline,
		Metrics:        s.metrics,
	})
}

// UnmarshalJSON deserializes JSON data into a State object.
func (s *SessionState) UnmarshalJSON(data []byte) error {
	aux := &struct {
		SessionID      string          `json:"session_id"`
		SourceType     string          `json:"source_type"`
		Config         json.RawMessage `json:"config"`
		Status         Status          `json:"status"`
		FailureReason  string          `json:"failure_reason,omitempty"`
		LastCheckpoint *Checkpoint     `json:"last_checkpoint"`
		Timeline       *Timeline       `json:"timeline"`
		Metrics        *SessionMetrics `json:"metrics"`
	}{}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	s.sessionID = uuid.MustParse(aux.SessionID)
	s.sourceType = aux.SourceType
	s.config = aux.Config
	s.status = aux.Status
	s.failureReason = aux.FailureReason
	s.lastCheckpoint = aux.LastCheckpoint
	s.timeline = aux.Timeline
	s.metrics = aux.Metrics

	return nil
}

// CreateTask creates a new task for this session.
func (s *SessionState) CreateTask(resourceURI string, metadata map[string]string) *Task {
	return &Task{
		CoreTask: shared.CoreTask{
			ID:         uuid.New(),
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
	s.timeline.UpdateLastUpdate()
	return nil
}

// MarkCompleted transitions an enumeration to the completed state.
func (s *SessionState) MarkCompleted() error {
	if !s.CanTransitionTo(StatusCompleted) {
		return newInvalidStateTransitionError(s.Status(), StatusCompleted)
	}

	s.setStatus(StatusCompleted)
	s.timeline.MarkCompleted()
	return nil
}

// MarkFailed transitions an enumeration to the failed state with a reason.
func (s *SessionState) MarkFailed(reason string) error {
	if !s.CanTransitionTo(StatusFailed) {
		return newInvalidStateTransitionError(s.Status(), StatusFailed)
	}

	s.setStatus(StatusFailed)
	s.setFailureReason(reason)
	s.timeline.MarkCompleted()
	return nil
}

// TODO: Consider setting this on the session state.
// This could open up the ability to set different thresholds for different sessions.
const defaultStallThreshold = 10 * time.Second

// ProcessCompletedBatch updates the session state based on a completed batch's outcome.
// It maintains aggregate-level metrics and updates the session status based on batch results.
func (s *SessionState) ProcessCompletedBatch(batch *Batch) error {
	if s.Status() != StatusInProgress {
		return newInvalidProgressError("can only process batches when session is in progress")
	}

	if s.IsStalled(defaultStallThreshold) {
		s.setStatus(StatusStalled)
		return nil
	}

	// Update metrics
	s.metrics.IncrementTotalBatches()
	if err := s.metrics.AddProcessedItems(batch.Metrics().ItemsProcessed()); err != nil {
		return err
	}

	if batch.Status() == BatchStatusFailed {
		s.metrics.IncrementFailedBatches()
	}

	// Update session status if we have partial completion
	if s.metrics.HasFailedBatches() && s.metrics.ItemsProcessed() > 0 {
		s.setStatus(StatusPartiallyCompleted)
	}

	// Update checkpoint and timeline
	if batch.Checkpoint() != nil {
		s.attachCheckpoint(batch.Checkpoint())
	}
	s.timeline.UpdateLastUpdate()

	return nil
}

func (s *SessionState) attachCheckpoint(cp *Checkpoint) { s.lastCheckpoint = cp }

// IsStalled determines if an enumeration has exceeded the staleness threshold.
func (s *SessionState) IsStalled(threshold time.Duration) bool {
	if s.Status() != StatusInProgress {
		return false
	}

	return s.timeline.Since(s.timeline.LastUpdate()) > threshold
}

// validTransitions defines the allowed state transitions for enumerations.
// Empty slices indicate terminal states with no allowed transitions.
// TODO: revist this.
var validTransitions = map[Status][]Status{
	StatusInitialized:        {StatusInProgress, StatusFailed},
	StatusInProgress:         {StatusCompleted, StatusFailed, StatusStalled, StatusPartiallyCompleted},
	StatusStalled:            {StatusInProgress, StatusFailed, StatusCompleted},
	StatusFailed:             {}, // Terminal state
	StatusCompleted:          {}, // Terminal state
	StatusPartiallyCompleted: {},
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

// SessionState methods for internal modifications.
func (s *SessionState) setStatus(status Status) {
	s.status = status
	s.timeline.UpdateLastUpdate()
}

func (s *SessionState) setFailureReason(reason string) { s.failureReason = reason }
