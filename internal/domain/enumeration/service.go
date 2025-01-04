package enumeration

import (
	"fmt"
	"time"
)

// Service manages the lifecycle and state transitions of enumeration sessions.
// It encapsulates the core domain logic for tracking progress, validating state changes,
// and detecting stalled operations without dependencies on external services.
type Service interface {
	// State management.

	// MarkInProgress transitions an enumeration to the in-progress state.
	// Returns an error if the transition is invalid from the current state.
	MarkInProgress(state *SessionState) error
	// MarkCompleted transitions an enumeration to the completed state.
	// Returns an error if the transition is invalid from the current state.
	MarkCompleted(state *SessionState) error
	// MarkFailed transitions an enumeration to the failed state with a reason.
	// Returns an error if the transition is invalid from the current state.
	MarkFailed(state *SessionState, reason string) error

	// Progress tracking.

	// RecordBatchProgress records the progress of a batch and updates overall progress.
	RecordBatchProgress(state *SessionState, batch BatchProgress) error

	// Querying.

	// IsStalled determines if an enumeration has exceeded the staleness threshold.
	IsStalled(state *SessionState, threshold time.Duration) bool
	// CanTransitionTo validates if a state transition is allowed by the domain rules.
	CanTransitionTo(state *SessionState, targetStatus Status) bool
}

// Domain errors define the core failure modes of enumeration state management.
var (
	// ErrInvalidStateTransition indicates an attempt to make a disallowed state transition.
	ErrInvalidStateTransition = fmt.Errorf("invalid state transition")

	// ErrInvalidProgress indicates invalid progress tracking data.
	ErrInvalidProgress = fmt.Errorf("invalid progress update")

	// ErrMissingCheckpoint indicates a progress update without required checkpoint data.
	ErrMissingCheckpoint = fmt.Errorf("checkpoint required for progress update")
)

type service struct{ stallThreshold time.Duration }

// NewService creates a new domain service with default configuration.
func NewService() Service {
	const defaultStallThreshold = 30 * time.Minute
	return &service{
		stallThreshold: defaultStallThreshold, // TODO: Make this configurable.
	}
}

// MarkInProgress transitions an enumeration to the in-progress state. It initializes
// progress tracking if not already present. This transition is only allowed from
// specific states per domain rules.
func (ds *service) MarkInProgress(state *SessionState) error {
	if !ds.CanTransitionTo(state, StatusInProgress) {
		return fmt.Errorf("%w: cannot transition from %s to %s",
			ErrInvalidStateTransition, state.Status(), StatusInProgress)
	}

	state.setStatus(StatusInProgress)
	state.updateLastUpdated()

	if state.Progress() == nil {
		state.initializeProgress()
	}
	return nil
}

// MarkCompleted transitions an enumeration to the completed state, indicating all
// targets were successfully processed. This is a terminal state that can only be
// reached from in-progress or stalled states.
func (ds *service) MarkCompleted(state *SessionState) error {
	if !ds.CanTransitionTo(state, StatusCompleted) {
		return fmt.Errorf("%w: cannot transition from %s to %s",
			ErrInvalidStateTransition, state.Status(), StatusCompleted)
	}

	state.setStatus(StatusCompleted)
	state.updateLastUpdated()
	return nil
}

// MarkFailed transitions an enumeration to the failed state with a reason for the
// failure. This is a terminal state that captures unrecoverable errors during
// enumeration.
func (ds *service) MarkFailed(state *SessionState, reason string) error {
	if !ds.CanTransitionTo(state, StatusFailed) {
		return fmt.Errorf("%w: cannot transition from %s to %s",
			ErrInvalidStateTransition, state.Status(), StatusFailed)
	}

	state.setStatus(StatusFailed)
	state.setFailureReason(reason)
	state.updateLastUpdated()
	return nil
}

// RecordBatchProgress updates the enumeration state with progress from a batch of
// processed items. It enforces monotonically increasing progress and automatically
// transitions to stalled or partially completed states based on progress conditions.
func (ds *service) RecordBatchProgress(state *SessionState, batch BatchProgress) error {
	if state.Status() != StatusInProgress {
		return fmt.Errorf("%w: can only update progress when in progress", ErrInvalidProgress)
	}

	if batch.Checkpoint() == nil {
		return fmt.Errorf("%w: checkpoint required for progress update", ErrMissingCheckpoint)
	}

	// Ensure progress metrics remain monotonically increasing
	if batch.ItemsProcessed() < 0 ||
		(state.Progress() != nil &&
			batch.ItemsProcessed()+state.Progress().ItemsProcessed() < state.Progress().ItemsProcessed()) {
		return fmt.Errorf("%w: invalid items processed count", ErrInvalidProgress)
	}

	state.addBatchProgress(batch)
	state.attachCheckpoint(batch.Checkpoint())

	// Auto-transition based on progress conditions
	if ds.IsStalled(state, ds.stallThreshold) {
		state.setStatus(StatusStalled)
	} else if state.HasFailedBatches() && state.Progress().ItemsProcessed() > 0 {
		state.setStatus(StatusPartiallyCompleted)
	}

	return nil
}

// IsStalled determines if an enumeration has exceeded the staleness threshold by
// checking the time since the last progress update.
func (ds *service) IsStalled(state *SessionState, threshold time.Duration) bool {
	if state.Progress() == nil || state.Status() != StatusInProgress {
		return false
	}

	return time.Since(state.Progress().LastUpdate()) > threshold
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

// CanTransitionTo validates if a state transition is allowed by checking the
// transition rules defined in validTransitions.
func (ds *service) CanTransitionTo(state *SessionState, targetStatus Status) bool {
	allowedTransitions, exists := validTransitions[state.Status()]
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
