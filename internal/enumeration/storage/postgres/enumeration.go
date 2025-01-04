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

		// 3) Save progress + batch progress
		if state.Progress() != nil {
			if err := s.saveProgress(ctx, state); err != nil {
				return err
			}
			for _, batch := range state.Progress().Batches() {
				if err := s.saveBatchProgress(ctx, state.SessionID(), batch); err != nil {
					return err
				}
			}
		}

		return nil
	})
}

func (s *enumerationSessionStateStore) saveProgress(ctx context.Context, state *enumeration.SessionState) error {
	// Upsert enumeration_progress row
	err := s.q.CreateEnumerationProgress(ctx, db.CreateEnumerationProgressParams{
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
	return nil
}

func (s *enumerationSessionStateStore) saveBatchProgress(ctx context.Context, sessionID string, batch enumeration.BatchProgress) error {
	// 1) Save the batch's checkpoint if present
	var checkpointID pgtype.Int8
	if cp := batch.Checkpoint(); cp != nil {
		if err := s.checkpointStore.Save(ctx, cp); err != nil {
			return fmt.Errorf("failed to save batch checkpoint: %w", err)
		}
		checkpointID = pgtype.Int8{Int64: cp.ID(), Valid: true}
	} else {
		checkpointID = pgtype.Int8{Valid: false} // no checkpoint
	}

	// 2) Insert or update the enumeration_batch_progress row
	//    (Assuming your SQL code has a param for checkpoint_id)
	_, err := s.q.CreateEnumerationBatchProgress(ctx, db.CreateEnumerationBatchProgressParams{
		BatchID:        batch.BatchID(),
		SessionID:      sessionID,
		Status:         db.BatchStatus(batch.Status()),
		StartedAt:      pgtype.Timestamptz{Time: batch.StartedAt(), Valid: true},
		CompletedAt:    pgtype.Timestamptz{Time: batch.CompletedAt(), Valid: true},
		ItemsProcessed: int32(batch.ItemsProcessed()),
		ErrorDetails:   pgtype.Text{String: batch.ErrorDetails(), Valid: batch.ErrorDetails() != ""},
		CheckpointID:   checkpointID, // new column
	})
	if err != nil {
		return fmt.Errorf("failed to create batch progress: %w", err)
	}

	return nil
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

// convertDBStateToEnumState loads all relevant data (session row, progress row, batch progress rows)
// and re-hydrates a domain SessionState object with typed Checkpoint entities.
func (s *enumerationSessionStateStore) convertDBStateToEnumState(
	ctx context.Context,
	dbState db.EnumerationSessionState,
) (*enumeration.SessionState, error) {
	var state *enumeration.SessionState

	err := storage.ExecuteAndTrace(ctx, s.tracer, "postgres.convert_db_state", []attribute.KeyValue{
		attribute.String("session_id", dbState.SessionID),
		attribute.Bool("has_checkpoint", dbState.LastCheckpointID.Valid),
	}, func(ctx context.Context) error {

		// 1) Load the session's "last checkpoint" if the ID is valid
		var sessionCheckpoint *enumeration.Checkpoint
		if dbState.LastCheckpointID.Valid {
			cp, err := s.checkpointStore.LoadByID(ctx, dbState.LastCheckpointID.Int64)
			if err != nil {
				return fmt.Errorf("failed to load session checkpoint: %w", err)
			}
			sessionCheckpoint = cp
		}

		// 2) Load the top-level enumeration progress (if it exists)
		progressRow, err := s.q.GetEnumerationProgressForSession(ctx, dbState.SessionID)
		// If there's truly no progress row, that's not necessarily an error;
		// check for pgx.ErrNoRows or handle as you wish:
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("failed to load progress for session %s: %w", dbState.SessionID, err)
		}

		// 3) Load all batch progress rows for this session
		dbBatches, err := s.q.GetEnumerationBatchProgressForSession(ctx, dbState.SessionID)
		if err != nil {
			return fmt.Errorf("failed to load batch progress for session %s: %w", dbState.SessionID, err)
		}

		// 4) Reconstruct domain BatchProgress objects, each referencing its own checkpoint if checkpoint_id is set
		batchProgresses := make([]enumeration.BatchProgress, len(dbBatches))
		for i, row := range dbBatches {
			// If row.CheckpointID is valid, load that checkpoint
			var batchCheckpoint *enumeration.Checkpoint
			if row.CheckpointID.Valid {
				cp, err := s.checkpointStore.LoadByID(ctx, row.CheckpointID.Int64)
				if err != nil {
					return fmt.Errorf("failed to load batch checkpoint (batch_id=%s): %w", row.BatchID, err)
				}
				batchCheckpoint = cp
			}

			// Reconstruct the batch progress domain object
			batchProgresses[i] = enumeration.ReconstructBatchProgress(
				row.BatchID,
				enumeration.BatchStatus(row.Status),
				row.StartedAt.Time,
				row.CompletedAt.Time,
				int(row.ItemsProcessed),
				row.ErrorDetails.String,
				batchCheckpoint,
			)
		}

		// 5) Construct a domain Progress object if the progress row exists
		//    (If none existed, progressRow might be zeroed out or an invalid reference).
		var domainProgress *enumeration.Progress
		// Typically, you'll check for a valid row:
		if progressRow.SessionID != "" {
			domainProgress = enumeration.ReconstructProgress(
				progressRow.StartedAt.Time,
				progressRow.LastUpdate.Time,
				int(progressRow.ItemsFound),
				int(progressRow.ItemsProcessed),
				int(progressRow.FailedBatches),
				int(progressRow.TotalBatches),
				batchProgresses,
			)
		}

		// 6) Finally reconstruct the SessionState aggregate
		state = enumeration.ReconstructState(
			dbState.SessionID,
			dbState.SourceType,
			dbState.Config,
			enumeration.Status(dbState.Status),
			dbState.UpdatedAt.Time,
			dbState.FailureReason.String,
			sessionCheckpoint,
			domainProgress,
		)

		return nil
	})

	return state, err
}
