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
	ctx, span := s.tracer.Start(ctx, "postgres.save_enumeration_state",
		trace.WithAttributes(
			attribute.String("session_id", state.SessionID),
			attribute.String("source_type", state.SourceType),
			attribute.String("status", string(state.Status)),
			attribute.Bool("has_checkpoint", state.LastCheckpoint != nil),
		))
	defer span.End()

	var lastCheckpointID pgtype.Int8
	if state.LastCheckpoint != nil {
		checkpointCtx, checkpointSpan := s.tracer.Start(ctx, "postgres.save_checkpoint")
		if err := s.checkpointStore.Save(checkpointCtx, state.LastCheckpoint); err != nil {
			checkpointSpan.RecordError(err)
			checkpointSpan.End()
			return fmt.Errorf("failed to save checkpoint: %w", err)
		}
		checkpointSpan.End()
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
		span.RecordError(err)
		return fmt.Errorf("failed to save enumeration state: %w", err)
	}

	return nil
}

// Load retrieves the current enumeration state and its associated checkpoint.
// Returns nil if no state exists.
func (s *EnumerationStateStorage) Load(ctx context.Context, sessionID string) (*storage.EnumerationState, error) {
	ctx, span := s.tracer.Start(ctx, "postgres.load_enumeration_state",
		trace.WithAttributes(
			attribute.String("session_id", sessionID),
		))
	defer span.End()

	dbState, err := s.q.GetEnumerationState(ctx, sessionID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		span.RecordError(err)
		return nil, fmt.Errorf("failed to load enumeration state: %w", err)
	}

	return s.convertDBStateToEnumState(ctx, dbState)
}

func (s *EnumerationStateStorage) GetActiveStates(ctx context.Context) ([]*storage.EnumerationState, error) {
	ctx, span := s.tracer.Start(ctx, "postgres.get_active_enumeration_states")
	defer span.End()

	dbStates, err := s.q.GetActiveEnumerationStates(ctx)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("failed to get active enumeration states: %w", err)
	}

	states, err := s.convertDBStatesToEnumStates(ctx, dbStates)
	if err != nil {
		span.RecordError(err)
		return nil, err
	}

	span.SetAttributes(attribute.Int("active_states_count", len(states)))
	return states, nil
}

func (s *EnumerationStateStorage) List(ctx context.Context, limit int) ([]*storage.EnumerationState, error) {
	ctx, span := s.tracer.Start(ctx, "postgres.list_enumeration_states",
		trace.WithAttributes(
			attribute.Int("limit", limit),
		))
	defer span.End()

	dbStates, err := s.q.ListEnumerationStates(ctx, int32(limit))
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("failed to list enumeration states: %w", err)
	}

	states, err := s.convertDBStatesToEnumStates(ctx, dbStates)
	if err != nil {
		span.RecordError(err)
		return nil, err
	}

	span.SetAttributes(attribute.Int("states_count", len(states)))
	return states, nil
}

// Helper function to convert DB state to domain model.
func (s *EnumerationStateStorage) convertDBStateToEnumState(ctx context.Context, dbState db.EnumerationState) (*storage.EnumerationState, error) {
	ctx, span := s.tracer.Start(ctx, "postgres.convert_db_state",
		trace.WithAttributes(
			attribute.String("session_id", dbState.SessionID),
			attribute.Bool("has_checkpoint", dbState.LastCheckpointID.Valid),
		))
	defer span.End()

	state := &storage.EnumerationState{
		SessionID:   dbState.SessionID,
		SourceType:  dbState.SourceType,
		Config:      dbState.Config,
		LastUpdated: dbState.UpdatedAt.Time,
		Status:      storage.EnumerationStatus(dbState.Status),
	}

	if dbState.LastCheckpointID.Valid {
		checkpointCtx, checkpointSpan := s.tracer.Start(ctx, "postgres.load_checkpoint")
		checkpoint, err := s.checkpointStore.LoadByID(checkpointCtx, dbState.LastCheckpointID.Int64)
		if err != nil {
			checkpointSpan.RecordError(err)
			checkpointSpan.End()
			return nil, fmt.Errorf("failed to load checkpoint: %w", err)
		}
		checkpointSpan.End()
		state.LastCheckpoint = checkpoint
	}

	return state, nil
}

// Helper function to convert multiple DB states to domain model.
func (s *EnumerationStateStorage) convertDBStatesToEnumStates(ctx context.Context, dbStates []db.EnumerationState) ([]*storage.EnumerationState, error) {
	ctx, span := s.tracer.Start(ctx, "postgres.convert_db_states",
		trace.WithAttributes(
			attribute.Int("state_count", len(dbStates)),
		))
	defer span.End()

	states := make([]*storage.EnumerationState, len(dbStates))
	for i, dbState := range dbStates {
		state, err := s.convertDBStateToEnumState(ctx, dbState)
		if err != nil {
			span.RecordError(err)
			return nil, fmt.Errorf("failed to convert state %s: %w", dbState.SessionID, err)
		}
		states[i] = state
	}
	return states, nil
}
