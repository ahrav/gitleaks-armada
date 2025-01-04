package enumeration

import (
	"fmt"
	"time"
)

// EnumerationDomainService manages the lifecycle and state transitions of enumeration sessions.
// It encapsulates the core domain logic for tracking progress, validating state changes,
// and detecting stalled operations without dependencies on external services.
type EnumerationDomainService interface {
	// MarkInProgress transitions an enumeration to the in-progress state.
	// Returns an error if the transition is invalid from the current state.
	MarkInProgress(state *State) error

	// MarkCompleted transitions an enumeration to the completed state.
	// Returns an error if the transition is invalid from the current state.
	MarkCompleted(state *State) error

	// MarkFailed transitions an enumeration to the failed state with a reason.
	// Returns an error if the transition is invalid from the current state.
	MarkFailed(state *State, reason string) error

	// UpdateProgress records enumeration progress and the latest checkpoint.
	// Returns an error if the update is invalid or missing required data.
	UpdateProgress(state *State, itemsProcessed int, checkpoint *Checkpoint) error

	// IsStalled determines if an enumeration has exceeded the staleness threshold.
	IsStalled(state *State, threshold time.Duration) bool

	// CanTransitionTo validates if a state transition is allowed by the domain rules.
	CanTransitionTo(state *State, targetStatus Status) bool
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

type enumerationDomainServiceImpl struct {
	// TODO: More configuration options here?
	stallThreshold time.Duration
}

// NewEnumerationDomainService creates a new domain service with default configuration.
func NewEnumerationDomainService() EnumerationDomainService {
	const defaultStallThreshold = 30 * time.Minute
	return &enumerationDomainServiceImpl{
		stallThreshold: defaultStallThreshold, // TODO: Make configurable
	}
}

func (ds *enumerationDomainServiceImpl) MarkInProgress(state *State) error {
	if !ds.CanTransitionTo(state, StatusInProgress) {
		return fmt.Errorf("%w: cannot transition from %s to %s",
			ErrInvalidStateTransition, state.Status, StatusInProgress)
	}

	state.Status = StatusInProgress
	state.LastUpdated = time.Now()

	// Initialize progress tracking if this is the first transition to in-progress.
	if state.Progress == nil {
		state.Progress = &Progress{
			StartedAt:  time.Now(),
			LastUpdate: time.Now(),
		}
	}
	return nil
}

func (ds *enumerationDomainServiceImpl) MarkCompleted(state *State) error {
	if !ds.CanTransitionTo(state, StatusCompleted) {
		return fmt.Errorf("%w: cannot transition from %s to %s",
			ErrInvalidStateTransition, state.Status, StatusCompleted)
	}

	state.Status = StatusCompleted
	state.LastUpdated = time.Now()
	return nil
}

func (ds *enumerationDomainServiceImpl) MarkFailed(state *State, reason string) error {
	if !ds.CanTransitionTo(state, StatusFailed) {
		return fmt.Errorf("%w: cannot transition from %s to %s",
			ErrInvalidStateTransition, state.Status, StatusFailed)
	}

	state.Status = StatusFailed
	state.LastUpdated = time.Now()
	state.FailureReason = reason
	return nil
}

func (ds *enumerationDomainServiceImpl) UpdateProgress(
	state *State,
	itemsProcessed int,
	checkpoint *Checkpoint,
) error {
	if state.Status != StatusInProgress {
		return fmt.Errorf("%w: can only update progress when in progress", ErrInvalidProgress)
	}

	if checkpoint == nil {
		return fmt.Errorf("%w: checkpoint required for progress update", ErrMissingCheckpoint)
	}

	// Ensure monotonically increasing progress.
	if itemsProcessed < 0 || (state.Progress != nil && itemsProcessed < state.Progress.ItemsProcessed) {
		return fmt.Errorf("%w: invalid items processed count", ErrInvalidProgress)
	}

	now := time.Now()

	// Initialize progress tracking if needed.
	if state.Progress == nil {
		state.Progress = &Progress{
			StartedAt: now,
		}
	}

	state.Progress.ItemsProcessed = itemsProcessed
	state.Progress.LastUpdate = now
	state.LastCheckpoint = checkpoint
	state.LastUpdated = now

	// Auto-transition to stalled if threshold exceeded.
	if ds.IsStalled(state, ds.stallThreshold) {
		state.Status = StatusStalled
	}

	return nil
}

func (ds *enumerationDomainServiceImpl) IsStalled(state *State, threshold time.Duration) bool {
	if state.Progress == nil || state.Status != StatusInProgress {
		return false
	}

	return time.Since(state.Progress.LastUpdate) > threshold
}

func (ds *enumerationDomainServiceImpl) CanTransitionTo(state *State, targetStatus Status) bool {
	// Define allowed state transitions based on domain rules.
	validTransitions := map[Status][]Status{
		StatusInitialized: {StatusInProgress, StatusFailed},
		StatusInProgress:  {StatusCompleted, StatusFailed, StatusStalled},
		StatusStalled:     {StatusInProgress, StatusFailed, StatusCompleted},
		StatusFailed:      {}, // Terminal state
		StatusCompleted:   {}, // Terminal state
	}

	allowedTransitions, exists := validTransitions[state.Status]
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
