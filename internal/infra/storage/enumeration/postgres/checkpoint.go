package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/db"
	"github.com/ahrav/gitleaks-armada/internal/domain/enumeration"
	"github.com/ahrav/gitleaks-armada/internal/infra/storage"
)

var _ enumeration.CheckpointRepository = (*checkpointStore)(nil)

// checkpointStore provides a PostgreSQL implementation of checkpointStore.
// It uses sqlc-generated queries to manage checkpoint persistence, enabling
// resumable scanning across process restarts.
type checkpointStore struct {
	q      *db.Queries
	tracer trace.Tracer
}

// NewCheckpointStore creates a new PostgreSQL-backed checkpoint storage using
// the provided database connection. It initializes the underlying sqlc queries
// used for checkpoint operations.
func NewCheckpointStore(dbConn *pgxpool.Pool, tracer trace.Tracer) *checkpointStore {
	return &checkpointStore{q: db.New(dbConn), tracer: tracer}
}

// Save persists a checkpoint to PostgreSQL. The checkpoint's Data field is
// serialized to JSON before storage to allow for flexible schema evolution.
func (p *checkpointStore) Save(ctx context.Context, cp *enumeration.Checkpoint) error {
	dbAttrs := append(
		defaultDBAttributes,
		attribute.String("target_id", cp.TargetID()),
		attribute.Int("data_size", len(cp.Data())),
	)
	return storage.ExecuteAndTrace(ctx, p.tracer, "postgres.save_checkpoint", dbAttrs, func(ctx context.Context) error {
		dataBytes, err := json.Marshal(cp.Data())
		if err != nil {
			return fmt.Errorf("failed to marshal checkpoint data: %w", err)
		}

		id, err := p.q.UpsertCheckpoint(ctx, db.UpsertCheckpointParams{
			TargetID: cp.TargetID(),
			Data:     dataBytes,
		})
		if err != nil {
			return fmt.Errorf("failed to save checkpoint: %w", err)
		}
		if cp.IsTemporary() {
			cp.SetID(id)
		}
		return nil
	})
}

// Load retrieves a checkpoint by target ID. Returns nil if no checkpoint exists
// for the given target. The stored JSON data is deserialized into the checkpoint's
// Data field.
func (p *checkpointStore) Load(ctx context.Context, targetID string) (*enumeration.Checkpoint, error) {
	var checkpoint *enumeration.Checkpoint
	dbAttrs := append(
		defaultDBAttributes,
		attribute.String("target_id", targetID),
	)
	err := storage.ExecuteAndTrace(ctx, p.tracer, "postgres.load_checkpoint", dbAttrs, func(ctx context.Context) error {
		dbCp, err := p.q.GetCheckpoint(ctx, targetID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			return fmt.Errorf("failed to load checkpoint: %w", err)
		}

		var data map[string]any
		if err := json.Unmarshal(dbCp.Data, &data); err != nil {
			return fmt.Errorf("failed to unmarshal checkpoint data: %w", err)
		}
		checkpoint = enumeration.NewCheckpoint(dbCp.ID, dbCp.TargetID, data)

		return nil
	})
	return checkpoint, err
}

// LoadByID retrieves a checkpoint by its unique database ID.
func (p *checkpointStore) LoadByID(ctx context.Context, id int64) (*enumeration.Checkpoint, error) {
	var checkpoint *enumeration.Checkpoint
	dbAttrs := append(
		defaultDBAttributes,
		attribute.Int64("checkpoint_id", id),
	)
	err := storage.ExecuteAndTrace(ctx, p.tracer, "postgres.load_checkpoint_by_id", dbAttrs, func(ctx context.Context) error {
		dbCp, err := p.q.GetCheckpointByID(ctx, id)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			return fmt.Errorf("failed to load checkpoint by ID: %w", err)
		}

		var data map[string]any
		if err := json.Unmarshal(dbCp.Data, &data); err != nil {
			return fmt.Errorf("failed to unmarshal checkpoint data: %w", err)
		}
		checkpoint = enumeration.NewCheckpoint(dbCp.ID, dbCp.TargetID, data)

		return nil
	})
	return checkpoint, err
}

// Delete removes a checkpoint for the given target ID. It is not an error if
// the checkpoint does not exist.
func (p *checkpointStore) Delete(ctx context.Context, targetID string) error {
	dbAttrs := append(
		defaultDBAttributes,
		attribute.String("target_id", targetID),
	)
	return storage.ExecuteAndTrace(ctx, p.tracer, "postgres.delete_checkpoint", dbAttrs, func(ctx context.Context) error {
		if err := p.q.DeleteCheckpoint(ctx, targetID); err != nil {
			return fmt.Errorf("failed to delete checkpoint: %w", err)
		}
		return nil
	})
}
