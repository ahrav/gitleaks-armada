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
	"github.com/ahrav/gitleaks-armada/internal/domain/enumeration"
	"github.com/ahrav/gitleaks-armada/internal/storage"
)

var _ enumeration.EnumerationStateRepository = (*enumerationStateStore)(nil)

// enumerationStateStore provides persistent storage for enumeration session state
// using PostgreSQL. It enables resumable scanning across process restarts by maintaining
// both enumeration state and associated checkpoints.
type enumerationStateStore struct {
	q               *db.Queries
	checkpointStore enumeration.CheckpointRepository
	tracer          trace.Tracer
}

// NewEnumerationStateStore creates a new PostgreSQL-backed enumeration state storage
// using the provided database connection and checkpoint store.
func NewEnumerationStateStore(dbConn *pgxpool.Pool, checkpointStore enumeration.CheckpointRepository, tracer trace.Tracer) *enumerationStateStore {
	return &enumerationStateStore{
		q:               db.New(dbConn),
		checkpointStore: checkpointStore,
		tracer:          tracer,
	}
}

// Save persists an enumeration state and its associated checkpoint (if any) to PostgreSQL.
// It ensures atomic updates by saving the checkpoint first, then updating the enumeration state
// with a reference to the checkpoint.
func (s *enumerationStateStore) Save(ctx context.Context, state *enumeration.State) error {
	return storage.ExecuteAndTrace(ctx, s.tracer, "postgres.save_enumeration_state", []attribute.KeyValue{
		attribute.String("session_id", state.SessionID),
		attribute.String("source_type", state.SourceType),
		attribute.String("status", string(state.Status)),
		attribute.Bool("has_checkpoint", state.LastCheckpoint != nil),
	}, func(ctx context.Context) error {
		var lastCheckpointID pgtype.Int8
		if state.LastCheckpoint != nil {
			if err := storage.ExecuteAndTrace(ctx, s.tracer, "postgres.save_checkpoint", nil, func(ctx context.Context) error {
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
func (s *enumerationStateStore) Load(ctx context.Context, sessionID string) (*enumeration.State, error) {
	var state *enumeration.State
	err := storage.ExecuteAndTrace(ctx, s.tracer, "postgres.load_enumeration_state", []attribute.KeyValue{
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

func (s *enumerationStateStore) GetActiveStates(ctx context.Context) ([]*enumeration.State, error) {
	var states []*enumeration.State
	err := storage.ExecuteAndTrace(ctx, s.tracer, "postgres.get_active_enumeration_states", nil, func(ctx context.Context) error {
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

func (s *enumerationStateStore) List(ctx context.Context, limit int) ([]*enumeration.State, error) {
	var states []*enumeration.State
	err := storage.ExecuteAndTrace(ctx, s.tracer, "postgres.list_enumeration_states", []attribute.KeyValue{
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
func (s *enumerationStateStore) convertDBStateToEnumState(ctx context.Context, dbState db.EnumerationState) (*enumeration.State, error) {
	var state *enumeration.State
	err := storage.ExecuteAndTrace(ctx, s.tracer, "postgres.convert_db_state", []attribute.KeyValue{
		attribute.String("session_id", dbState.SessionID),
		attribute.Bool("has_checkpoint", dbState.LastCheckpointID.Valid),
	}, func(ctx context.Context) error {
		state = &enumeration.State{
			SessionID:   dbState.SessionID,
			SourceType:  dbState.SourceType,
			Config:      dbState.Config,
			LastUpdated: dbState.UpdatedAt.Time,
			Status:      enumeration.Status(dbState.Status),
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
func (s *enumerationStateStore) convertDBStatesToEnumStates(ctx context.Context, dbStates []db.EnumerationState) ([]*enumeration.State, error) {
	var states []*enumeration.State
	err := storage.ExecuteAndTrace(ctx, s.tracer, "postgres.convert_db_states", []attribute.KeyValue{
		attribute.Int("state_count", len(dbStates)),
	}, func(ctx context.Context) error {
		states = make([]*enumeration.State, len(dbStates))
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
