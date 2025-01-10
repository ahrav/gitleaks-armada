package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/db"
	"github.com/ahrav/gitleaks-armada/internal/domain/enumeration"
	"github.com/ahrav/gitleaks-armada/internal/infra/storage"
)

// Ensure batchStore implements BatchRepository at compile time.
var _ enumeration.BatchRepository = (*batchStore)(nil)

// batchStore provides a PostgreSQL-backed BatchRepository.
type batchStore struct {
	q               *db.Queries
	checkpointStore enumeration.CheckpointRepository
	tracer          trace.Tracer
}

// NewBatchStore creates a new PostgreSQL-backed store that implements BatchRepository.
func NewBatchStore(
	dbConn *pgxpool.Pool,
	checkpointStore enumeration.CheckpointRepository,
	tracer trace.Tracer,
) *batchStore {
	return &batchStore{
		q:               db.New(dbConn),
		checkpointStore: checkpointStore,
		tracer:          tracer,
	}
}

// Save persists a Batch (and its checkpoint, if present) to PostgreSQL.
// It uses an upsert pattern to update existing rows or insert new ones.
func (s *batchStore) Save(ctx context.Context, batch *enumeration.Batch) error {
	dbAttrs := append(
		defaultDBAttributes,
		attribute.String("batch_id", batch.BatchID()),
		attribute.String("session_id", batch.SessionID()),
		attribute.String("status", string(batch.Status())),
		attribute.Bool("has_checkpoint", batch.Checkpoint() != nil),
	)

	return storage.ExecuteAndTrace(ctx, s.tracer, "postgres.enumeration.save_batch", dbAttrs, func(ctx context.Context) error {
		var checkpointID int64
		if batch.Checkpoint() != nil {
			// Persist the checkpoint first; if it's new, it will get an ID.
			if err := storage.ExecuteAndTrace(ctx, s.tracer, "postgres.enumeration.save_checkpoint", dbAttrs, func(ctx context.Context) error {
				return s.checkpointStore.Save(ctx, batch.Checkpoint())
			}); err != nil {
				return fmt.Errorf("failed to save batch checkpoint: %w", err)
			}
			checkpointID = batch.Checkpoint().ID()
		}

		startedAt := batch.Timeline().StartedAt()
		completedAt := batch.Timeline().CompletedAt()
		lastUpdate := batch.Timeline().LastUpdate()

		expectedItems := batch.Metrics().ExpectedItems()
		itemsProcessed := batch.Metrics().ItemsProcessed()
		errorDetails := batch.Metrics().ErrorDetails()

		err := s.q.UpsertBatch(ctx, db.UpsertBatchParams{
			BatchID:        batch.BatchID(),
			SessionID:      batch.SessionID(),
			Status:         db.BatchStatus(batch.Status()), // Convert domain to DB enum
			CheckpointID:   pgtype.Int8{Int64: checkpointID, Valid: checkpointID != 0},
			StartedAt:      pgtype.Timestamptz{Time: startedAt, Valid: true},
			CompletedAt:    pgtype.Timestamptz{Time: completedAt, Valid: completedAt != time.Time{}},
			LastUpdate:     pgtype.Timestamptz{Time: lastUpdate, Valid: true},
			ItemsProcessed: int32(itemsProcessed),
			ExpectedItems:  int32(expectedItems),
			ErrorDetails:   pgtype.Text{String: errorDetails, Valid: errorDetails != ""},
		})
		if err != nil {
			return fmt.Errorf("failed to upsert batch: %w", err)
		}

		return nil
	})
}

// FindBySessionID returns all batches for a given session, ordered by started_at ASC.
func (s *batchStore) FindBySessionID(ctx context.Context, sessionID string) ([]*enumeration.Batch, error) {
	dbAttrs := append(
		defaultDBAttributes,
		attribute.String("session_id", sessionID),
	)

	var batches []*enumeration.Batch
	err := storage.ExecuteAndTrace(ctx, s.tracer, "postgres.enumeration.get_batches_for_session", dbAttrs, func(ctx context.Context) error {
		rows, err := s.q.GetBatchesForSession(ctx, sessionID)
		if err != nil {
			return fmt.Errorf("failed to get batches for session %s: %w", sessionID, err)
		}

		for _, r := range rows {
			b, err := s.toDomainBatch(ctx, &r)
			if err != nil {
				return err
			}
			batches = append(batches, b)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return batches, nil
}

// FindLastBySessionID returns the most recently started batch for a given session.
// Since the "GetBatchesForSession" query orders by started_at ASC, we can simply
// fetch all and return the last element (if any exist). Alternatively, you could
// add a dedicated "GetLastBatchForSession" query sorted DESC LIMIT 1.
func (s *batchStore) FindLastBySessionID(ctx context.Context, sessionID string) (*enumeration.Batch, error) {
	batches, err := s.FindBySessionID(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	if len(batches) == 0 {
		return nil, nil // or an error if you prefer
	}
	return batches[len(batches)-1], nil
}

// FindByID retrieves a batch by its unique batchID.
func (s *batchStore) FindByID(ctx context.Context, batchID string) (*enumeration.Batch, error) {
	dbAttrs := append(
		defaultDBAttributes,
		attribute.String("batch_id", batchID),
	)

	var batchEntity *enumeration.Batch
	err := storage.ExecuteAndTrace(
		ctx,
		s.tracer,
		"postgres.enumeration.get_batch_by_id",
		dbAttrs,
		func(ctx context.Context) error {
			r, err := s.q.GetBatch(ctx, batchID)
			if err != nil {
				return fmt.Errorf("failed to get batch %s: %w", batchID, err)
			}

			batchEntity, err = s.toDomainBatch(ctx, &r)
			if err != nil {
				return err
			}
			return nil
		})
	if err != nil {
		return nil, err
	}

	return batchEntity, nil
}

// toDomainBatch reconstructs a Batch entity from a DB row and fetches the associated checkpoint if present.
func (s *batchStore) toDomainBatch(ctx context.Context, row *db.EnumerationBatch) (*enumeration.Batch, error) {
	timeline := enumeration.ReconstructTimeline(
		row.StartedAt.Time,
		row.CompletedAt.Time,
		row.LastUpdate.Time,
	)

	metrics := enumeration.ReconstructBatchMetrics(
		int(row.ExpectedItems),
		int(row.ItemsProcessed),
		row.ErrorDetails.String,
	)

	var cp *enumeration.Checkpoint
	if row.CheckpointID.Valid {
		checkpoint, err := s.checkpointStore.LoadByID(ctx, row.CheckpointID.Int64)
		if err != nil {
			return nil, fmt.Errorf("failed to load checkpoint %d: %w", row.CheckpointID.Int64, err)
		}
		cp = checkpoint
	}

	return enumeration.ReconstructBatch(
		row.BatchID,
		row.SessionID,
		enumeration.BatchStatus(row.Status),
		timeline,
		metrics,
		cp,
	), nil
}
