package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ahrav/gitleaks-armada/internal/db"
	"github.com/ahrav/gitleaks-armada/pkg/storage"
)

// EnumerationStatus represents the lifecycle state of an enumeration session.
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
	LastCheckpoint *Checkpoint       `json:"last_checkpoint,omitempty"`
	LastUpdated    time.Time         `json:"last_updated"`
	Status         EnumerationStatus `json:"status"`
}

// PGEnumerationStateStorage provides persistent storage for enumeration session state
// using PostgreSQL. It enables resumable scanning across process restarts by maintaining
// both enumeration state and associated checkpoints.
type PGEnumerationStateStorage struct {
	q               *db.Queries
	checkpointStore storage.CheckpointStorage
}

// NewPGEnumerationStateStorage creates a new PostgreSQL-backed enumeration state storage
// using the provided database connection and checkpoint store.
func NewPGEnumerationStateStorage(dbConn *sql.DB, checkpointStore storage.CheckpointStorage) *PGEnumerationStateStorage {
	return &PGEnumerationStateStorage{q: db.New(dbConn), checkpointStore: checkpointStore}
}

// Save persists an enumeration state and its associated checkpoint (if any) to PostgreSQL.
// It ensures atomic updates by saving the checkpoint first, then updating the enumeration state
// with a reference to the checkpoint.
func (s *PGEnumerationStateStorage) Save(ctx context.Context, state *storage.EnumerationState) error {
	var lastCheckpointID sql.NullInt64
	if state.LastCheckpoint != nil {
		// Save checkpoint first to maintain referential integrity
		if err := s.checkpointStore.Save(ctx, state.LastCheckpoint); err != nil {
			return err
		}
		lastCheckpointID = sql.NullInt64{Int64: state.LastCheckpoint.ID, Valid: true}
	}

	err := s.q.CreateOrUpdateEnumerationState(ctx, db.CreateOrUpdateEnumerationStateParams{
		SessionID:        state.SessionID,
		SourceType:       state.SourceType,
		Config:           state.Config,
		LastCheckpointID: lastCheckpointID,
		Status:           db.EnumerationStatus(state.Status),
	})
	return err
}

// LoadBySessionID retrieves an enumeration state and its associated checkpoint by session ID.
// Returns nil if no state exists for the given session ID.
func (s *PGEnumerationStateStorage) LoadBySessionID(ctx context.Context, sessionID string) (*storage.EnumerationState, error) {
	dbState, err := s.q.GetEnumerationState(ctx, sessionID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return s.fromDBState(ctx, dbState)
}

// fromDBState converts a database enumeration state row into a domain EnumerationState object.
// It loads the associated checkpoint if one exists.
func (s *PGEnumerationStateStorage) fromDBState(ctx context.Context, state db.GetEnumerationStateRow) (*storage.EnumerationState, error) {
	var cp *storage.Checkpoint
	if state.LastCheckpointID.Valid {
		checkpoint, err := s.checkpointStore.LoadByID(ctx, state.LastCheckpointID.Int64)
		if err != nil {
			return nil, fmt.Errorf("failed to load checkpoint: %w", err)
		}
		cp = checkpoint
	}

	return &storage.EnumerationState{
		SessionID:      state.SessionID,
		SourceType:     state.SourceType,
		Config:         state.Config,
		LastCheckpoint: cp,
		LastUpdated:    state.UpdatedAt,
		Status:         storage.EnumerationStatus(state.Status),
	}, nil
}
