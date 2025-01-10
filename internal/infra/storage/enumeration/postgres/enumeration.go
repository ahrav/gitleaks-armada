package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/db"
	"github.com/ahrav/gitleaks-armada/internal/domain/enumeration"
	"github.com/ahrav/gitleaks-armada/internal/infra/storage"
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

var defaultDBAttributes = []attribute.KeyValue{
	attribute.String("db.system", "postgresql"),
}

// Save persists an enumeration state and its associated checkpoint (if any) to PostgreSQL.
// It ensures atomic updates by saving the checkpoint first, then updating the enumeration state
// with a reference to the checkpoint.
func (s *enumerationSessionStateStore) Save(ctx context.Context, state *enumeration.SessionState) error {
	dbAttrs := append(
		defaultDBAttributes,
		attribute.String("session_id", state.SessionID()),
		attribute.String("source_type", state.SourceType()),
		attribute.String("status", string(state.Status())),
		attribute.Bool("has_checkpoint", state.LastCheckpoint() != nil),
	)

	return storage.ExecuteAndTrace(ctx, s.tracer, "postgres.enumeration.save_state", dbAttrs, func(ctx context.Context) error {
		// Save checkpoint if present.
		var lastCheckpointID pgtype.Int8
		if state.LastCheckpoint() != nil {
			if err := storage.ExecuteAndTrace(ctx, s.tracer, "postgres.enumeration.save_checkpoint", dbAttrs, func(ctx context.Context) error {
				return s.checkpointStore.Save(ctx, state.LastCheckpoint())
			}); err != nil {
				return fmt.Errorf("failed to save checkpoint: %w", err)
			}
			lastCheckpointID = pgtype.Int8{Int64: state.LastCheckpoint().ID(), Valid: true}
		}

		// Save session state with timeline.
		err := s.q.UpsertSessionState(ctx, db.UpsertSessionStateParams{
			SessionID:        state.SessionID(),
			SourceType:       state.SourceType(),
			Config:           state.Config(),
			Status:           db.EnumerationStatus(state.Status()),
			FailureReason:    pgtype.Text{String: state.FailureReason(), Valid: state.FailureReason() != ""},
			LastCheckpointID: lastCheckpointID,
			StartedAt:        pgtype.Timestamptz{Time: state.Timeline().StartedAt(), Valid: true},
			CompletedAt:      pgtype.Timestamptz{Time: state.Timeline().CompletedAt(), Valid: !state.Timeline().CompletedAt().IsZero()},
			LastUpdate:       pgtype.Timestamptz{Time: state.Timeline().LastUpdate(), Valid: true},
		})
		if err != nil {
			return fmt.Errorf("failed to save session state: %w", err)
		}

		// Save session metrics.
		err = s.q.UpsertSessionMetrics(ctx, db.UpsertSessionMetricsParams{
			SessionID:      state.SessionID(),
			TotalBatches:   int32(state.Metrics().TotalBatches()),
			FailedBatches:  int32(state.Metrics().FailedBatches()),
			ItemsFound:     int32(state.Metrics().ItemsFound()),
			ItemsProcessed: int32(state.Metrics().ItemsProcessed()),
		})
		if err != nil {
			return fmt.Errorf("failed to save session metrics: %w", err)
		}

		return nil
	})
}

// func (s *enumerationSessionStateStore) Save(ctx context.Context, state *enumeration.SessionState) error {
// 	dbAttrs := append(
// 		defaultDBAttributes,
// 		attribute.String("session_id", state.SessionID()),
// 		attribute.String("source_type", state.SourceType()),
// 		attribute.String("status", string(state.Status())),
// 		attribute.Bool("has_checkpoint", state.LastCheckpoint() != nil),
// 	)
// 	return storage.ExecuteAndTrace(ctx, s.tracer, "postgres.enumeration.save_state", dbAttrs, func(ctx context.Context) error {
// 		// Save checkpoint if present.
// 		var lastCheckpointID pgtype.Int8
// 		if state.LastCheckpoint() != nil {
// 			if err := storage.ExecuteAndTrace(ctx, s.tracer, "postgres.enumeration.save_checkpoint", dbAttrs, func(ctx context.Context) error {
// 				return s.checkpointStore.Save(ctx, state.LastCheckpoint())
// 			}); err != nil {
// 				return fmt.Errorf("failed to save checkpoint: %w", err)
// 			}
// 			lastCheckpointID = pgtype.Int8{Int64: state.LastCheckpoint().ID(), Valid: true}
// 		}

// 		// Save the session state.
// 		err := s.q.UpsertEnumerationSessionState(ctx, db.UpsertEnumerationSessionStateParams{
// 			SessionID:        state.SessionID(),
// 			SourceType:       state.SourceType(),
// 			Config:           state.Config(),
// 			LastCheckpointID: lastCheckpointID,
// 			Status:           db.EnumerationStatus(state.Status()),
// 			FailureReason:    pgtype.Text{String: state.FailureReason(), Valid: state.FailureReason() != ""},
// 		})
// 		if err != nil {
// 			return fmt.Errorf("failed to save enumeration state: %w", err)
// 		}

// 		// Save progress if exists
// 		if progress := state.Progress(); progress != nil {
// 			if err := s.saveProgress(ctx, state); err != nil {
// 				return err
// 			}

// 			// Save the current batch if it exists
// 			if batch := state.LastBatch(); batch != nil {
// 				if err := s.saveBatch(ctx, state.SessionID(), batch); err != nil {
// 					return err
// 				}
// 			}
// 		}

// 		return nil
// 	})
// }

// func (s *enumerationSessionStateStore) saveProgress(ctx context.Context, state *enumeration.SessionState) error {
// 	dbAttrs := append(
// 		defaultDBAttributes,
// 		attribute.String("session_id", state.SessionID()),
// 	)
// 	return storage.ExecuteAndTrace(ctx, s.tracer, "postgres.enumeration.save_progress", dbAttrs, func(ctx context.Context) error {
// 		err := s.q.UpsertSessionProgress(ctx, db.UpsertSessionProgressParams{
// 			SessionID:      state.SessionID(),
// 			StartedAt:      pgtype.Timestamptz{Time: state.Progress().StartedAt(), Valid: true},
// 			ItemsFound:     int32(state.Progress().ItemsFound()),
// 			ItemsProcessed: int32(state.Progress().ItemsProcessed()),
// 			FailedBatches:  int32(state.FailedBatches()),
// 			TotalBatches:   int32(state.TotalBatches()),
// 		})
// 		if err != nil {
// 			return fmt.Errorf("failed to upsert progress: %w", err)
// 		}
// 		return nil
// 	})
// }

// func (s *enumerationSessionStateStore) saveBatch(ctx context.Context, sessionID string, batch *enumeration.Batch) error {
// 	dbAttrs := append(
// 		defaultDBAttributes,
// 		attribute.String("session_id", sessionID),
// 		attribute.String("batch_id", batch.BatchID()),
// 		attribute.Bool("has_checkpoint", batch.Checkpoint() != nil),
// 	)
// 	return storage.ExecuteAndTrace(ctx, s.tracer, "postgres.enumeration.save_batch", dbAttrs, func(ctx context.Context) error {
// 		// Save batch checkpoint if exists
// 		var checkpointID pgtype.Int8
// 		if cp := batch.Checkpoint(); cp != nil {
// 			if err := s.checkpointStore.Save(ctx, cp); err != nil {
// 				return fmt.Errorf("failed to save batch checkpoint: %w", err)
// 			}
// 			checkpointID = pgtype.Int8{Int64: cp.ID(), Valid: true}
// 		}

// 		// Create batch entity
// 		if _, err := s.q.CreateBatch(ctx, db.CreateBatchParams{
// 			BatchID:      batch.BatchID(),
// 			SessionID:    sessionID,
// 			Status:       db.BatchStatus(batch.Status()),
// 			CheckpointID: checkpointID,
// 		}); err != nil {
// 			return fmt.Errorf("failed to create batch: %w", err)
// 		}

// 		// Save batch progress
// 		progress := batch.Progress()
// 		if err := s.q.UpsertBatchProgress(ctx, db.UpsertBatchProgressParams{
// 			BatchID:        batch.BatchID(),
// 			StartedAt:      pgtype.Timestamptz{Time: progress.StartedAt(), Valid: true},
// 			CompletedAt:    pgtype.Timestamptz{Time: progress.CompletedAt(), Valid: !progress.CompletedAt().IsZero()},
// 			ItemsProcessed: int32(progress.ItemsProcessed()),
// 			ExpectedItems:  int32(progress.ExpectedItems()),
// 			ErrorDetails:   pgtype.Text{String: progress.ErrorDetails(), Valid: progress.ErrorDetails() != ""},
// 		}); err != nil {
// 			return fmt.Errorf("failed to upsert batch progress: %w", err)
// 		}

// 		return nil
// 	})
// }

// Load retrieves the current enumeration state and its associated checkpoint.
// Returns nil if no state exists.
func (s *enumerationSessionStateStore) Load(ctx context.Context, sessionID string) (*enumeration.SessionState, error) {
	dbAttrs := append(
		defaultDBAttributes,
		attribute.String("session_id", sessionID),
	)
	var state *enumeration.SessionState
	err := storage.ExecuteAndTrace(ctx, s.tracer, "postgres.enumeration.load_state", dbAttrs, func(ctx context.Context) error {
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
	err := storage.ExecuteAndTrace(
		ctx, s.tracer, "postgres.enumeration.get_active_states", defaultDBAttributes, func(ctx context.Context) error {
			dbStates, err := s.q.GetActiveEnumerationSessionStates(ctx)
			if err != nil {
				return fmt.Errorf("failed to get active enumeration states: %w", err)
			}

			for _, dbState := range dbStates {
				state, err := s.convertDBStateToEnumState(ctx, dbState)
				if err != nil {
					return fmt.Errorf("failed to convert state: %w", err)
				}
				states = append(states, state)
			}
			return nil
		})
	return states, err
}

func (s *enumerationSessionStateStore) List(ctx context.Context, limit int) ([]*enumeration.SessionState, error) {
	dbAttrs := append(
		defaultDBAttributes,
		attribute.Int("limit", limit),
	)
	var states []*enumeration.SessionState
	err := storage.ExecuteAndTrace(ctx, s.tracer, "postgres.enumeration.list_states", dbAttrs, func(ctx context.Context) error {
		dbStates, err := s.q.ListEnumerationSessionStates(ctx, int32(limit))
		if err != nil {
			return fmt.Errorf("failed to list enumeration states: %w", err)
		}

		for _, dbState := range dbStates {
			state, err := s.convertDBStateToEnumState(ctx, dbState)
			if err != nil {
				return fmt.Errorf("failed to convert state: %w", err)
			}
			states = append(states, state)
		}
		return nil
	})
	return states, err
}

// convertDBStateToEnumState loads the session state, metrics, and checkpoint data
// and reconstructs a domain SessionState object.
func (s *enumerationSessionStateStore) convertDBStateToEnumState(
	ctx context.Context,
	dbState any,
) (*enumeration.SessionState, error) {
	var sessionID string
	var sourceType string
	var config json.RawMessage
	var status db.EnumerationStatus
	var failureReason pgtype.Text
	var lastCheckpointID pgtype.Int8
	var startedAt time.Time
	var completedAt pgtype.Timestamptz
	var lastUpdate time.Time

	switch v := dbState.(type) {
	case db.EnumerationSessionState:
		sessionID = v.SessionID
		sourceType = v.SourceType
		config = v.Config
		status = v.Status
		failureReason = v.FailureReason
		lastCheckpointID = v.LastCheckpointID
		startedAt = v.StartedAt.Time
		completedAt = v.CompletedAt
		lastUpdate = v.LastUpdate.Time
	case db.GetActiveEnumerationSessionStatesRow:
		sessionID = v.SessionID
		sourceType = v.SourceType
		config = v.Config
		status = v.Status
		failureReason = v.FailureReason
		lastCheckpointID = v.LastCheckpointID
	case db.ListEnumerationSessionStatesRow:
		sessionID = v.SessionID
		sourceType = v.SourceType
		config = v.Config
		status = v.Status
		failureReason = v.FailureReason
		lastCheckpointID = v.LastCheckpointID
	default:
		return nil, fmt.Errorf("unknown state type: %T", dbState)
	}

	var state *enumeration.SessionState
	err := storage.ExecuteAndTrace(ctx, s.tracer, "postgres.enumeration.convert_state", []attribute.KeyValue{
		attribute.String("session_id", sessionID),
		attribute.Bool("has_checkpoint", lastCheckpointID.Valid),
	}, func(ctx context.Context) error {
		// Load the session's checkpoint if present
		var sessionCheckpoint *enumeration.Checkpoint
		if lastCheckpointID.Valid {
			cp, err := s.checkpointStore.LoadByID(ctx, lastCheckpointID.Int64)
			if err != nil {
				return fmt.Errorf("failed to load session checkpoint: %w", err)
			}
			sessionCheckpoint = cp
		}

		// Load the session metrics
		metricsRow, err := s.q.GetSessionMetrics(ctx, sessionID)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("failed to load metrics for session %s: %w", sessionID, err)
		}

		// Reconstruct Timeline
		timeline := enumeration.ReconstructTimeline(
			startedAt,
			completedAt.Time,
			lastUpdate,
		)

		// Reconstruct SessionMetrics
		metrics := enumeration.ReconstructSessionMetrics(
			int(metricsRow.TotalBatches),
			int(metricsRow.FailedBatches),
			int(metricsRow.ItemsFound),
			int(metricsRow.ItemsProcessed),
		)

		state = enumeration.ReconstructState(
			sessionID,
			sourceType,
			config,
			enumeration.Status(status),
			timeline,
			failureReason.String,
			sessionCheckpoint,
			metrics,
		)
		return nil
	})
	return state, err
}
