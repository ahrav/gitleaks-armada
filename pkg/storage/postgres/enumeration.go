package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/db"
	"github.com/ahrav/gitleaks-armada/pkg/storage"
)

var _ storage.EnumerationStateStorage = (*EnumerationStateStorage)(nil)

// EnumerationStateStorage provides persistent storage for enumeration session state
// using PostgreSQL. It enables resumable scanning across process restarts by maintaining
// both enumeration state and associated checkpoints.
type EnumerationStateStorage struct {
	q               *db.Queries
	checkpointStore storage.CheckpointStorage
	tracer          trace.Tracer
}

// NewEnumerationStateStorage creates a new PostgreSQL-backed enumeration state storage
// using the provided database connection and checkpoint store.
func NewEnumerationStateStorage(dbConn *pgxpool.Pool, checkpointStore storage.CheckpointStorage, tracer trace.Tracer) *EnumerationStateStorage {
	return &EnumerationStateStorage{
		q:               db.New(dbConn),
		checkpointStore: checkpointStore,
		tracer:          tracer,
	}
}

// Save persists an enumeration state and its associated checkpoint (if any) to PostgreSQL.
// It ensures atomic updates by saving the checkpoint first, then updating the enumeration state
// with a reference to the checkpoint.
func (s *EnumerationStateStorage) Save(ctx context.Context, state *storage.EnumerationState) error {
	return executeAndTrace(ctx, s.tracer, "postgres.save_enumeration_state", []attribute.KeyValue{
		attribute.String("session_id", state.SessionID),
		attribute.String("source_type", state.SourceType),
		attribute.String("status", string(state.Status)),
		attribute.Bool("has_checkpoint", state.LastCheckpoint != nil),
	}, func(ctx context.Context) error {
		var lastCheckpointID pgtype.Int8
		if state.LastCheckpoint != nil {
			if err := executeAndTrace(ctx, s.tracer, "postgres.save_checkpoint", nil, func(ctx context.Context) error {
				return s.checkpointStore.Save(ctx, state.LastCheckpoint)
			}); err != nil {
				return fmt.Errorf("failed to save checkpoint: %w", err)
			}
			lastCheckpointID = pgtype.Int8{Int64: state.LastCheckpoint.ID, Valid: true}
		}

		err := s.q.CreateOrUpdateEnumerationState(ctx, db.CreateOrUpdateEnumerationStateParams{
			SessionID:        state.SessionID,
			SourceType:       state.SourceType,
			Config:           state.Config,
			LastCheckpointID: lastCheckpointID,
			Status:           db.EnumerationStatus(state.Status),
		})
		if err != nil {
			return fmt.Errorf("failed to save enumeration state: %w", err)
		}
		return nil
	})
}

// Load retrieves the current enumeration state and its associated checkpoint.
// Returns nil if no state exists.
func (s *EnumerationStateStorage) Load(ctx context.Context, sessionID string) (*storage.EnumerationState, error) {
	var state *storage.EnumerationState
	err := executeAndTrace(ctx, s.tracer, "postgres.load_enumeration_state", []attribute.KeyValue{
		attribute.String("session_id", sessionID),
	}, func(ctx context.Context) error {
		dbState, err := s.q.GetEnumerationState(ctx, sessionID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			return fmt.Errorf("failed to load enumeration state: %w", err)
		}

		convertedState, err := s.convertDBStateToEnumState(ctx, dbState)
		if err != nil {
			return err
		}
		state = convertedState
		return nil
	})
	return state, err
}

func (s *EnumerationStateStorage) GetActiveStates(ctx context.Context) ([]*storage.EnumerationState, error) {
	var states []*storage.EnumerationState
	err := executeAndTrace(ctx, s.tracer, "postgres.get_active_enumeration_states", nil, func(ctx context.Context) error {
		dbStates, err := s.q.GetActiveEnumerationStates(ctx)
		if err != nil {
			return fmt.Errorf("failed to get active enumeration states: %w", err)
		}

		convertedStates, err := s.convertDBStatesToEnumStates(ctx, dbStates)
		if err != nil {
			return err
		}
		states = convertedStates
		return nil
	})
	return states, err
}

func (s *EnumerationStateStorage) List(ctx context.Context, limit int) ([]*storage.EnumerationState, error) {
	var states []*storage.EnumerationState
	err := executeAndTrace(ctx, s.tracer, "postgres.list_enumeration_states", []attribute.KeyValue{
		attribute.Int("limit", limit),
	}, func(ctx context.Context) error {
		dbStates, err := s.q.ListEnumerationStates(ctx, int32(limit))
		if err != nil {
			return fmt.Errorf("failed to list enumeration states: %w", err)
		}

		convertedStates, err := s.convertDBStatesToEnumStates(ctx, dbStates)
		if err != nil {
			return err
		}
		states = convertedStates
		return nil
	})
	return states, err
}

// Helper function to convert DB state to domain model.
func (s *EnumerationStateStorage) convertDBStateToEnumState(ctx context.Context, dbState db.EnumerationState) (*storage.EnumerationState, error) {
	var state *storage.EnumerationState
	err := executeAndTrace(ctx, s.tracer, "postgres.convert_db_state", []attribute.KeyValue{
		attribute.String("session_id", dbState.SessionID),
		attribute.Bool("has_checkpoint", dbState.LastCheckpointID.Valid),
	}, func(ctx context.Context) error {
		state = &storage.EnumerationState{
			SessionID:   dbState.SessionID,
			SourceType:  dbState.SourceType,
			Config:      dbState.Config,
			LastUpdated: dbState.UpdatedAt.Time,
			Status:      storage.EnumerationStatus(dbState.Status),
		}

		if dbState.LastCheckpointID.Valid {
			checkpoint, err := s.checkpointStore.LoadByID(ctx, dbState.LastCheckpointID.Int64)
			if err != nil {
				return fmt.Errorf("failed to load checkpoint: %w", err)
			}
			state.LastCheckpoint = checkpoint
		}
		return nil
	})
	return state, err
}

// Helper function to convert multiple DB states to domain model.
func (s *EnumerationStateStorage) convertDBStatesToEnumStates(ctx context.Context, dbStates []db.EnumerationState) ([]*storage.EnumerationState, error) {
	var states []*storage.EnumerationState
	err := executeAndTrace(ctx, s.tracer, "postgres.convert_db_states", []attribute.KeyValue{
		attribute.Int("state_count", len(dbStates)),
	}, func(ctx context.Context) error {
		states = make([]*storage.EnumerationState, len(dbStates))
		for i, dbState := range dbStates {
			state, err := s.convertDBStateToEnumState(ctx, dbState)
			if err != nil {
				return fmt.Errorf("failed to convert state %s: %w", dbState.SessionID, err)
			}
			states[i] = state
		}
		return nil
	})
	return states, err
}
