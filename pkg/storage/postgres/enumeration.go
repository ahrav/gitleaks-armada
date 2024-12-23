package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/ahrav/gitleaks-armada/internal/db"
	"github.com/ahrav/gitleaks-armada/pkg/storage"
)

// EnumerationStateStorage provides persistent storage for enumeration session state
// using PostgreSQL. It enables resumable scanning across process restarts by maintaining
// both enumeration state and associated checkpoints.
type EnumerationStateStorage struct {
	q               *db.Queries
	checkpointStore storage.CheckpointStorage
}

// NewEnumerationStateStorage creates a new PostgreSQL-backed enumeration state storage
// using the provided database connection and checkpoint store.
func NewEnumerationStateStorage(dbConn *sql.DB, checkpointStore storage.CheckpointStorage) *EnumerationStateStorage {
	return &EnumerationStateStorage{q: db.New(dbConn), checkpointStore: checkpointStore}
}

// Save persists an enumeration state and its associated checkpoint (if any) to PostgreSQL.
// It ensures atomic updates by saving the checkpoint first, then updating the enumeration state
// with a reference to the checkpoint.
func (s *EnumerationStateStorage) Save(ctx context.Context, state *storage.EnumerationState) error {
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

// Load retrieves the current enumeration state and its associated checkpoint.
// Returns nil if no state exists.
func (s *EnumerationStateStorage) Load(ctx context.Context) (*storage.EnumerationState, error) {
	dbState, err := s.q.GetEnumerationState(ctx)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	state := &storage.EnumerationState{
		SessionID:   dbState.SessionID,
		SourceType:  dbState.SourceType,
		Config:      dbState.Config,
		LastUpdated: dbState.UpdatedAt,
		Status:      storage.EnumerationStatus(dbState.Status),
	}

	// Only load checkpoint if explicitly requested
	if dbState.LastCheckpointID.Valid {
		checkpoint, err := s.checkpointStore.LoadByID(ctx, dbState.LastCheckpointID.Int64)
		if err != nil {
			return nil, fmt.Errorf("failed to load checkpoint: %w", err)
		}
		state.LastCheckpoint = checkpoint
	}

	return state, nil
}
