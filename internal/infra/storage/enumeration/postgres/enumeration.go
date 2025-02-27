package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ahrav/gitleaks-armada/pkg/common/uuid"
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
		attribute.String("session_id", state.SessionID().String()),
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
			SessionID:        pgtype.UUID{Bytes: state.SessionID(), Valid: true},
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
			SessionID:      pgtype.UUID{Bytes: state.SessionID(), Valid: true},
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

// Load retrieves the current enumeration state and its associated checkpoint.
// Returns nil if no state exists.
func (s *enumerationSessionStateStore) Load(ctx context.Context, sessionID uuid.UUID) (*enumeration.SessionState, error) {
	dbAttrs := append(
		defaultDBAttributes,
		attribute.String("session_id", sessionID.String()),
	)
	var state *enumeration.SessionState
	err := storage.ExecuteAndTrace(ctx, s.tracer, "postgres.enumeration.load_state", dbAttrs, func(ctx context.Context) error {
		dbState, err := s.q.GetEnumerationSessionState(ctx, pgtype.UUID{Bytes: sessionID, Valid: true})
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
	var sessionID uuid.UUID
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
		sessionID = v.SessionID.Bytes
		sourceType = v.SourceType
		config = v.Config
		status = v.Status
		failureReason = v.FailureReason
		lastCheckpointID = v.LastCheckpointID
		startedAt = v.StartedAt.Time
		completedAt = v.CompletedAt
		lastUpdate = v.LastUpdate.Time
	case db.GetActiveEnumerationSessionStatesRow:
		sessionID = v.SessionID.Bytes
		sourceType = v.SourceType
		config = v.Config
		status = v.Status
		failureReason = v.FailureReason
		lastCheckpointID = v.LastCheckpointID
	case db.ListEnumerationSessionStatesRow:
		sessionID = v.SessionID.Bytes
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
		attribute.String("session_id", sessionID.String()),
		attribute.Bool("has_checkpoint", lastCheckpointID.Valid),
	}, func(ctx context.Context) error {
		var sessionCheckpoint *enumeration.Checkpoint
		if lastCheckpointID.Valid {
			cp, err := s.checkpointStore.LoadByID(ctx, lastCheckpointID.Int64)
			if err != nil {
				return fmt.Errorf("failed to load session checkpoint: %w", err)
			}
			sessionCheckpoint = cp
		}

		metricsRow, err := s.q.GetSessionMetrics(ctx, pgtype.UUID{Bytes: sessionID, Valid: true})
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("failed to load metrics for session %s: %w", sessionID, err)
		}

		timeline := enumeration.ReconstructTimeline(
			startedAt,
			completedAt.Time,
			lastUpdate,
		)

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
