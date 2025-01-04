package postgres

import (
	"context"
	"encoding/json"
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

var _ enumeration.StateRepository = (*enumerationSessionStateStore)(nil)

// enumerationSessionStateStore provides persistent storage for enumeration session state
// using PostgreSQL. It enables resumable scanning across process restarts by maintaining
// both enumeration state and associated checkpoints.
type enumerationSessionStateStore struct {
	q               *db.Queries
	checkpointStore enumeration.CheckpointRepository
	tracer          trace.Tracer
}

// NewEnumerationSessionStateStore creates a new PostgreSQL-backed enumeration state storage
// using the provided database connection and checkpoint store.
func NewEnumerationSessionStateStore(dbConn *pgxpool.Pool, checkpointStore enumeration.CheckpointRepository, tracer trace.Tracer) *enumerationSessionStateStore {
	return &enumerationSessionStateStore{
		q:               db.New(dbConn),
		checkpointStore: checkpointStore,
		tracer:          tracer,
	}
}

// Save persists an enumeration state and its associated checkpoint (if any) to PostgreSQL.
// It ensures atomic updates by saving the checkpoint first, then updating the enumeration state
// with a reference to the checkpoint.
func (s *enumerationSessionStateStore) Save(ctx context.Context, state *enumeration.SessionState) error {
	return storage.ExecuteAndTrace(ctx, s.tracer, "postgres.save_enumeration_state", []attribute.KeyValue{
		attribute.String("session_id", state.SessionID()),
		attribute.String("source_type", state.SourceType()),
		attribute.String("status", string(state.Status())),
		attribute.Bool("has_checkpoint", state.LastCheckpoint() != nil),
	}, func(ctx context.Context) error {
		// Save checkpoint if present.
		var lastCheckpointID pgtype.Int8
		if state.LastCheckpoint() != nil {
			if err := storage.ExecuteAndTrace(ctx, s.tracer, "postgres.save_checkpoint", nil, func(ctx context.Context) error {
				return s.checkpointStore.Save(ctx, state.LastCheckpoint())
			}); err != nil {
				return fmt.Errorf("failed to save checkpoint: %w", err)
			}
			lastCheckpointID = pgtype.Int8{Int64: state.LastCheckpoint().ID(), Valid: true}
		}

		// Save the session state.
		err := s.q.CreateOrUpdateEnumerationSessionState(ctx, db.CreateOrUpdateEnumerationSessionStateParams{
			SessionID:        state.SessionID(),
			SourceType:       state.SourceType(),
			Config:           state.Config(),
			LastCheckpointID: lastCheckpointID,
			Status:           db.EnumerationStatus(state.Status()),
			FailureReason:    pgtype.Text{String: state.FailureReason(), Valid: state.FailureReason() != ""},
		})
		if err != nil {
			return fmt.Errorf("failed to save enumeration state: %w", err)
		}

		if state.Progress() != nil {
			// Save progress.
			err = s.q.CreateEnumerationProgress(ctx, db.CreateEnumerationProgressParams{
				SessionID:  state.SessionID(),
				StartedAt:  pgtype.Timestamptz{Time: state.Progress().StartedAt(), Valid: true},
				LastUpdate: pgtype.Timestamptz{Time: state.Progress().LastUpdate(), Valid: true},
			})
			if err != nil {
				return fmt.Errorf("failed to create progress: %w", err)
			}

			err = s.q.UpdateEnumerationProgress(ctx, db.UpdateEnumerationProgressParams{
				SessionID:      state.SessionID(),
				ItemsFound:     int32(state.Progress().ItemsFound()),
				ItemsProcessed: int32(state.Progress().ItemsProcessed()),
				FailedBatches:  int32(state.Progress().FailedBatches()),
				TotalBatches:   int32(state.Progress().TotalBatches()),
			})
			if err != nil {
				return fmt.Errorf("failed to update progress: %w", err)
			}

			// Save batch progress with state as JSONB.
			for _, batch := range state.Progress().Batches() {
				stateJSON, err := json.Marshal(batch.State())
				if err != nil {
					return fmt.Errorf("failed to marshal batch state: %w", err)
				}

				_, err = s.q.CreateEnumerationBatchProgress(ctx, db.CreateEnumerationBatchProgressParams{
					BatchID:        batch.BatchID(),
					SessionID:      state.SessionID(),
					Status:         db.BatchStatus(batch.Status()),
					StartedAt:      pgtype.Timestamptz{Time: batch.StartedAt(), Valid: true},
					CompletedAt:    pgtype.Timestamptz{Time: batch.CompletedAt(), Valid: true},
					ItemsProcessed: int32(batch.ItemsProcessed()),
					ErrorDetails:   pgtype.Text{String: batch.ErrorDetails(), Valid: true},
					State:          stateJSON,
				})
				if err != nil {
					return fmt.Errorf("failed to create batch progress: %w", err)
				}
			}
		}

		return nil
	})
}

// Load retrieves the current enumeration state and its associated checkpoint.
// Returns nil if no state exists.
func (s *enumerationSessionStateStore) Load(ctx context.Context, sessionID string) (*enumeration.SessionState, error) {
	var state *enumeration.SessionState
	err := storage.ExecuteAndTrace(ctx, s.tracer, "postgres.load_enumeration_state", []attribute.KeyValue{
		attribute.String("session_id", sessionID),
	}, func(ctx context.Context) error {
		dbState, err := s.q.GetEnumerationSessionState(ctx, sessionID)
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

func (s *enumerationSessionStateStore) GetActiveStates(ctx context.Context) ([]*enumeration.SessionState, error) {
	var states []*enumeration.SessionState
	err := storage.ExecuteAndTrace(ctx, s.tracer, "postgres.get_active_enumeration_states", nil, func(ctx context.Context) error {
		dbStates, err := s.q.GetActiveEnumerationSessionStates(ctx)
		if err != nil {
			return fmt.Errorf("failed to get active enumeration states: %w", err)
		}

		states, err = s.convertDBStatesToEnumStates(ctx, dbStates)
		if err != nil {
			return fmt.Errorf("failed to convert states: %w", err)
		}
		return nil
	})
	return states, err
}

func (s *enumerationSessionStateStore) List(ctx context.Context, limit int) ([]*enumeration.SessionState, error) {
	var states []*enumeration.SessionState
	err := storage.ExecuteAndTrace(ctx, s.tracer, "postgres.list_enumeration_states", []attribute.KeyValue{
		attribute.Int("limit", limit),
	}, func(ctx context.Context) error {
		dbStates, err := s.q.ListEnumerationSessionStates(ctx, int32(limit))
		if err != nil {
			return fmt.Errorf("failed to list enumeration states: %w", err)
		}

		states, err = s.convertDBStatesToEnumStates(ctx, dbStates)
		if err != nil {
			return fmt.Errorf("failed to convert states: %w", err)
		}
		return nil
	})
	return states, err
}

// Helper function to convert different DB row types to domain model
func (s *enumerationSessionStateStore) convertDBStatesToEnumStates(ctx context.Context, dbStates interface{}) ([]*enumeration.SessionState, error) {
	var states []*enumeration.SessionState

	switch rows := dbStates.(type) {
	case []db.GetActiveEnumerationSessionStatesRow:
		for _, row := range rows {
			state, err := s.convertDBStateToEnumState(ctx, db.EnumerationSessionState{
				ID:               row.ID,
				SessionID:        row.SessionID,
				SourceType:       row.SourceType,
				Config:           row.Config,
				LastCheckpointID: row.LastCheckpointID,
				Status:           row.Status,
				FailureReason:    row.FailureReason,
				CreatedAt:        row.CreatedAt,
				UpdatedAt:        row.UpdatedAt,
			})
			if err != nil {
				return nil, fmt.Errorf("failed to convert state %s: %w", row.SessionID, err)
			}
			states = append(states, state)
		}
	case []db.ListEnumerationSessionStatesRow:
		for _, row := range rows {
			state, err := s.convertDBStateToEnumState(ctx, db.EnumerationSessionState{
				ID:               row.ID,
				SessionID:        row.SessionID,
				SourceType:       row.SourceType,
				Config:           row.Config,
				LastCheckpointID: row.LastCheckpointID,
				Status:           row.Status,
				FailureReason:    row.FailureReason,
				CreatedAt:        row.CreatedAt,
				UpdatedAt:        row.UpdatedAt,
			})
			if err != nil {
				return nil, fmt.Errorf("failed to convert state %s: %w", row.SessionID, err)
			}
			states = append(states, state)
		}
	default:
		return nil, fmt.Errorf("unsupported DB row type: %T", dbStates)
	}

	return states, nil
}

// Helper function to convert DB state to domain model.
func (s *enumerationSessionStateStore) convertDBStateToEnumState(ctx context.Context, dbState db.EnumerationSessionState) (*enumeration.SessionState, error) {
	var state *enumeration.SessionState
	err := storage.ExecuteAndTrace(ctx, s.tracer, "postgres.convert_db_state", []attribute.KeyValue{
		attribute.String("session_id", dbState.SessionID),
		attribute.Bool("has_checkpoint", dbState.LastCheckpointID.Valid),
	}, func(ctx context.Context) error {
		// Load checkpoint if present.
		var checkpoint *enumeration.Checkpoint
		if dbState.LastCheckpointID.Valid {
			var err error
			checkpoint, err = s.checkpointStore.LoadByID(ctx, dbState.LastCheckpointID.Int64)
			if err != nil {
				return fmt.Errorf("failed to load checkpoint: %w", err)
			}
		}

		// Load progress data.
		progress, err := s.q.GetEnumerationProgressForSession(ctx, dbState.SessionID)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("failed to load progress: %w", err)
		}

		// Load batch progress.
		batches, err := s.q.GetEnumerationBatchProgressForSession(ctx, dbState.SessionID)
		if err != nil {
			return fmt.Errorf("failed to load batch progress: %w", err)
		}

		batchProgresses := make([]enumeration.BatchProgress, len(batches))
		for i, batch := range batches {
			var state map[string]any
			if batch.State != nil {
				if err := json.Unmarshal(batch.State, &state); err != nil {
					return fmt.Errorf("failed to unmarshal batch state: %w", err)
				}
			}

			batchProgresses[i] = enumeration.ReconstructBatchProgress(
				batch.BatchID,
				enumeration.BatchStatus(batch.Status),
				batch.StartedAt.Time,
				batch.CompletedAt.Time,
				int(batch.ItemsProcessed),
				batch.ErrorDetails.String,
				state,
			)
		}

		domainProgress := enumeration.ReconstructProgress(
			progress.StartedAt.Time,
			progress.LastUpdate.Time,
			int(progress.ItemsFound),
			int(progress.ItemsProcessed),
			int(progress.FailedBatches),
			int(progress.TotalBatches),
			batchProgresses,
		)

		state = enumeration.ReconstructState(
			dbState.SessionID,
			dbState.SourceType,
			dbState.Config,
			enumeration.Status(dbState.Status),
			dbState.UpdatedAt.Time,
			dbState.FailureReason.String,
			checkpoint,
			domainProgress,
		)
		return nil
	})
	return state, err
}
