package enumeration

// EnumerationStatus represents the lifecycle states of an enumeration session.
// It is implemented as a value object using a string type to ensure type safety
// and domain invariants. The status transitions form a state machine that
// enforces valid lifecycle progression.
type EnumerationStatus string

const (
	// StatusInitialized indicates the session is configured but hasn't started scanning.
	// This is the initial valid state for new enumeration sessions.
	StatusInitialized EnumerationStatus = "initialized"
	// StatusInProgress indicates active scanning and task generation is underway.
	// The session can only transition to this state from StatusInitialized.
	StatusInProgress EnumerationStatus = "in_progress"
	// StatusCompleted indicates all targets were successfully enumerated.
	// This is a terminal state that can only be reached from StatusInProgress.
	StatusCompleted EnumerationStatus = "completed"
	// StatusFailed indicates the enumeration encountered an unrecoverable error.
	// This is a terminal state that can be reached from any non-terminal state.
	StatusFailed EnumerationStatus = "failed"
)
