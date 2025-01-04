package enumeration

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Checkpoint is an entity object that stores progress information for resumable target enumeration.
// It enables reliable scanning of large data sources by tracking the last successfully processed position.
// As an entity, it has a unique identity (ID) that persists across state changes and is mutable over time
// through its Data and UpdatedAt fields.
type Checkpoint struct {
	// Identity.
	id       int64
	targetID string

	// State/Metadata.
	data      map[string]any
	updatedAt time.Time
}

// NewCheckpoint creates a new Checkpoint entity with a persistent ID. The ID is provided by the caller,
// typically from a persistence layer, to maintain entity identity across state changes. The checkpoint
// tracks enumeration progress for a specific target using arbitrary data.
func NewCheckpoint(id int64, targetID string, data map[string]any) *Checkpoint {
	return &Checkpoint{
		id:        id,
		targetID:  targetID,
		data:      data,
		updatedAt: time.Now(),
	}
}

// NewTemporaryCheckpoint creates a Checkpoint without a persistent ID for use in transient operations.
// This allows checkpoints to be created and manipulated in memory before being persisted. Once
// persisted, a proper entity ID should be assigned via NewCheckpoint.
func NewTemporaryCheckpoint(targetID string, data map[string]any) *Checkpoint {
	return &Checkpoint{
		targetID:  targetID,
		data:      data,
		updatedAt: time.Now(),
	}
}

// Getters for Checkpoint.
func (c *Checkpoint) ID() int64            { return c.id }
func (c *Checkpoint) TargetID() string     { return c.targetID }
func (c *Checkpoint) Data() map[string]any { return c.data }
func (c *Checkpoint) UpdatedAt() time.Time { return c.updatedAt }

// Setters for Checkpoint.

// SetID updates the checkpoint's ID after persistence. This should only be used
// to set the ID of a temporary checkpoint after it has been persisted.
// It will panic if called on an already-persisted checkpoint to prevent ID mutations.
func (c *Checkpoint) SetID(id int64) {
	if c.id != 0 {
		panic("attempting to modify ID of a persisted checkpoint")
	}
	c.id = id
}

// MarshalJSON serializes the Checkpoint object into a JSON byte array.
func (c *Checkpoint) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		ID        int64          `json:"id"`
		TargetID  string         `json:"target_id"`
		Data      map[string]any `json:"data"`
		UpdatedAt time.Time      `json:"updated_at"`
	}{
		ID:        c.id,
		TargetID:  c.targetID,
		Data:      c.data,
		UpdatedAt: c.updatedAt,
	})
}

// UnmarshalJSON deserializes JSON data into a Checkpoint object.
func (c *Checkpoint) UnmarshalJSON(data []byte) error {
	aux := &struct {
		ID        int64          `json:"id"`
		TargetID  string         `json:"target_id"`
		Data      map[string]any `json:"data"`
		UpdatedAt time.Time      `json:"updated_at"`
	}{
		ID:        c.id,
		TargetID:  c.targetID,
		Data:      c.data,
		UpdatedAt: c.updatedAt,
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	c.id = aux.ID
	c.targetID = aux.TargetID
	c.data = aux.Data
	c.updatedAt = aux.UpdatedAt

	return nil
}

// BatchStatus represents the lifecycle state of an enumeration batch as a value object.
// It enables tracking of batch-level outcomes to support partial failure handling
// and resumable processing.
type BatchStatus string

const (
	// BatchStatusSucceeded indicates the batch completed processing all items successfully.
	BatchStatusSucceeded BatchStatus = "succeeded"
	// BatchStatusFailed indicates the batch encountered an unrecoverable error.
	BatchStatusFailed BatchStatus = "failed"
	// BatchStatusPartial indicates the batch completed with some items failing.
	BatchStatusPartial BatchStatus = "partial"
)

// BatchProgress is a value object that captures the execution details and outcomes
// of a single enumeration batch. It provides granular visibility into batch-level
// processing to support monitoring and failure analysis.
type BatchProgress struct {
	// batchID uniquely identifies this batch within the enumeration.
	batchID string
	// status reflects the batch's processing outcome.
	status BatchStatus
	// startedAt records when batch processing began.
	startedAt time.Time
	// completedAt records when batch processing finished.
	completedAt time.Time
	// itemsProcessed tracks the number of successfully handled items.
	itemsProcessed int
	// errorDetails captures failure information when status is failed or partial.
	errorDetails string
	// state stores the state of the enumeration at the time of the batch.
	state map[string]any
}

// ReconstructBatchProgress creates a BatchProgress instance from persisted data
func ReconstructBatchProgress(
	batchID string,
	status BatchStatus,
	startedAt time.Time,
	completedAt time.Time,
	itemsProcessed int,
	errorDetails string,
	state map[string]any,
) BatchProgress {
	return BatchProgress{
		batchID:        batchID,
		status:         status,
		startedAt:      startedAt,
		completedAt:    completedAt,
		itemsProcessed: itemsProcessed,
		errorDetails:   errorDetails,
		state:          state,
	}
}

// Getters for BatchProgress.
func (bp BatchProgress) BatchID() string        { return bp.batchID }
func (bp BatchProgress) Status() BatchStatus    { return bp.status }
func (bp BatchProgress) ItemsProcessed() int    { return bp.itemsProcessed }
func (bp BatchProgress) State() map[string]any  { return bp.state }
func (bp BatchProgress) ErrorDetails() string   { return bp.errorDetails }
func (bp BatchProgress) StartedAt() time.Time   { return bp.startedAt }
func (bp BatchProgress) CompletedAt() time.Time { return bp.completedAt }

// MarshalJSON serializes the BatchProgress object into a JSON byte array.
func (bp *BatchProgress) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		BatchID        string         `json:"batch_id"`
		Status         BatchStatus    `json:"status"`
		StartedAt      time.Time      `json:"started_at"`
		CompletedAt    time.Time      `json:"completed_at"`
		ItemsProcessed int            `json:"items_processed"`
		ErrorDetails   string         `json:"error_details,omitempty"`
		State          map[string]any `json:"state"`
	}{
		BatchID:        bp.batchID,
		Status:         bp.status,
		StartedAt:      bp.startedAt,
		CompletedAt:    bp.completedAt,
		ItemsProcessed: bp.itemsProcessed,
		ErrorDetails:   bp.errorDetails,
		State:          bp.state,
	})
}

// UnmarshalJSON deserializes JSON data into a BatchProgress object.
func (bp *BatchProgress) UnmarshalJSON(data []byte) error {
	aux := &struct {
		BatchID        string         `json:"batch_id"`
		Status         BatchStatus    `json:"status"`
		StartedAt      time.Time      `json:"started_at"`
		CompletedAt    time.Time      `json:"completed_at"`
		ItemsProcessed int            `json:"items_processed"`
		ErrorDetails   string         `json:"error_details,omitempty"`
		State          map[string]any `json:"state"`
	}{
		BatchID:        bp.batchID,
		Status:         bp.status,
		StartedAt:      bp.startedAt,
		CompletedAt:    bp.completedAt,
		ItemsProcessed: bp.itemsProcessed,
		ErrorDetails:   bp.errorDetails,
		State:          bp.state,
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	bp.batchID = aux.BatchID
	bp.status = aux.Status
	bp.startedAt = aux.StartedAt
	bp.completedAt = aux.CompletedAt
	bp.itemsProcessed = aux.ItemsProcessed
	bp.errorDetails = aux.ErrorDetails
	bp.state = aux.State

	return nil
}

// Progress tracks metrics about an enumeration session's execution. It provides
// visibility into the session's timeline and processing status to enable monitoring
// and reporting of long-running enumerations.
type Progress struct {
	// Timeline
	startedAt  time.Time
	lastUpdate time.Time

	// Metrics
	itemsFound     int
	itemsProcessed int

	// Batch tracking
	batches       []BatchProgress
	failedBatches int
	totalBatches  int
}

// ReconstructProgress creates a Progress instance from persisted data.
func ReconstructProgress(
	startedAt time.Time,
	lastUpdate time.Time,
	itemsFound int,
	itemsProcessed int,
	failedBatches int,
	totalBatches int,
	batches []BatchProgress,
) *Progress {
	return &Progress{
		startedAt:      startedAt,
		lastUpdate:     lastUpdate,
		itemsFound:     itemsFound,
		itemsProcessed: itemsProcessed,
		failedBatches:  failedBatches,
		totalBatches:   totalBatches,
		batches:        batches,
	}
}

// Getters for Progress
func (p *Progress) StartedAt() time.Time     { return p.startedAt }
func (p *Progress) LastUpdate() time.Time    { return p.lastUpdate }
func (p *Progress) ItemsFound() int          { return p.itemsFound }
func (p *Progress) ItemsProcessed() int      { return p.itemsProcessed }
func (p *Progress) FailedBatches() int       { return p.failedBatches }
func (p *Progress) TotalBatches() int        { return p.totalBatches }
func (p *Progress) Batches() []BatchProgress { return p.batches }

// MarshalJSON serializes the Progress object into a JSON byte array.
func (p *Progress) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		StartedAt      time.Time       `json:"started_at"`
		LastUpdate     time.Time       `json:"last_update"`
		ItemsFound     int             `json:"items_found"`
		ItemsProcessed int             `json:"items_processed"`
		Batches        []BatchProgress `json:"batches,omitempty"`
		FailedBatches  int             `json:"failed_batches"`
		TotalBatches   int             `json:"total_batches"`
	}{
		StartedAt:      p.startedAt,
		LastUpdate:     p.lastUpdate,
		ItemsFound:     p.itemsFound,
		ItemsProcessed: p.itemsProcessed,
		Batches:        p.batches,
		FailedBatches:  p.failedBatches,
		TotalBatches:   p.totalBatches,
	})
}

// UnmarshalJSON deserializes JSON data into a Progress object.
func (p *Progress) UnmarshalJSON(data []byte) error {
	aux := &struct {
		StartedAt      time.Time       `json:"started_at"`
		LastUpdate     time.Time       `json:"last_update"`
		ItemsFound     int             `json:"items_found"`
		ItemsProcessed int             `json:"items_processed"`
		Batches        []BatchProgress `json:"batches,omitempty"`
		FailedBatches  int             `json:"failed_batches"`
		TotalBatches   int             `json:"total_batches"`
	}{
		StartedAt:      p.startedAt,
		LastUpdate:     p.lastUpdate,
		ItemsFound:     p.itemsFound,
		ItemsProcessed: p.itemsProcessed,
		Batches:        p.batches,
		FailedBatches:  p.failedBatches,
		TotalBatches:   p.totalBatches,
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	p.startedAt = aux.StartedAt
	p.lastUpdate = aux.LastUpdate
	p.itemsFound = aux.ItemsFound
	p.itemsProcessed = aux.ItemsProcessed
	p.batches = aux.Batches
	p.failedBatches = aux.FailedBatches
	p.totalBatches = aux.TotalBatches

	return nil
}

// Status represents the lifecycle states of an enumeration session.
// It is implemented as a value object using a string type to ensure type safety
// and domain invariants.
// The status transitions form a state machine that enforces valid lifecycle progression.
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
	// StatusPartiallyCompleted indicates the enumeration completed with some failed batches.
	StatusPartiallyCompleted Status = "partially_completed"
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
}

// NewState creates a new enumeration State aggregate root with the provided source type and configuration.
// It enforces domain invariants by generating a unique session ID and setting the initial status.
// The domain owns identity generation to maintain aggregate consistency.
func NewState(sourceType string, config json.RawMessage) *SessionState {
	return &SessionState{
		sessionID:   uuid.New().String(),
		sourceType:  sourceType,
		config:      config,
		status:      StatusInitialized,
		lastUpdated: time.Now(),
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

// Getters for State
func (s *SessionState) SessionID() string           { return s.sessionID }
func (s *SessionState) SourceType() string          { return s.sourceType }
func (s *SessionState) Status() Status              { return s.status }
func (s *SessionState) Progress() *Progress         { return s.progress }
func (s *SessionState) LastCheckpoint() *Checkpoint { return s.lastCheckpoint }
func (s *SessionState) FailureReason() string       { return s.failureReason }
func (s *SessionState) Config() json.RawMessage     { return s.config }
func (s *SessionState) LastUpdated() time.Time      { return s.lastUpdated }

// State methods for internal modifications
func (s *SessionState) setStatus(status Status) {
	s.status = status
	s.lastUpdated = time.Now()
}

func (s *SessionState) setFailureReason(reason string) { s.failureReason = reason }

func (s *SessionState) updateLastUpdated() { s.lastUpdated = time.Now() }

func (s *SessionState) initializeProgress() {
	s.progress = &Progress{
		startedAt:  time.Now(),
		lastUpdate: time.Now(),
	}
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

// NewSuccessfulBatchProgress creates a BatchProgress record for a successfully completed batch.
// It captures the number of items processed and the state of the enumeration at the time of the batch.
// This enables accurate progress monitoring and resumable processing of large datasets.
func NewSuccessfulBatchProgress(itemCount int, state map[string]any) BatchProgress {
	return BatchProgress{
		batchID:        uuid.New().String(),
		status:         BatchStatusSucceeded,
		startedAt:      time.Now(),
		completedAt:    time.Now(),
		itemsProcessed: itemCount,
		state:          state,
	}
}

// NewFailedBatchProgress creates a BatchProgress record for a failed batch execution.
// It preserves the error details and state of the enumeration at the time of the batch.
// This enables failure analysis and recovery.
func NewFailedBatchProgress(err error, state map[string]any) BatchProgress {
	return BatchProgress{
		batchID:      uuid.New().String(),
		status:       BatchStatusFailed,
		startedAt:    time.Now(),
		completedAt:  time.Now(),
		errorDetails: err.Error(),
		state:        state,
	}
}

// addBatchProgress updates the enumeration state with results from a completed batch.
// It maintains aggregate progress metrics and ensures the state reflects the latest
// batch outcomes for monitoring and resumption.
func (s *SessionState) addBatchProgress(batch BatchProgress) {
	// Initialize progress tracking if this is the first batch.
	if s.progress == nil {
		s.initializeProgress()
	}

	s.progress.batches = append(s.progress.batches, batch)
	s.progress.totalBatches++
	s.progress.lastUpdate = time.Now()

	if batch.status == BatchStatusFailed {
		s.progress.failedBatches++
	}

	s.progress.itemsProcessed += batch.itemsProcessed
}

// HasFailedBatches returns true if any batches failed during enumeration.
func (s *SessionState) HasFailedBatches() bool {
	return s.progress != nil && s.progress.failedBatches > 0
}
