package postgres

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/ahrav/gitleaks-armada/internal/db"
	"github.com/ahrav/gitleaks-armada/pkg/storage"
)

// PGCheckpointStorage provides a PostgreSQL implementation of CheckpointStorage.
// It uses sqlc-generated queries to manage checkpoint persistence, enabling
// resumable scanning across process restarts.
type PGCheckpointStorage struct{ q *db.Queries }

// NewPGCheckpointStorage creates a new PostgreSQL-backed checkpoint storage using
// the provided database connection. It initializes the underlying sqlc queries
// used for checkpoint operations.
func NewPGCheckpointStorage(dbConn *sql.DB) *PGCheckpointStorage {
	return &PGCheckpointStorage{q: db.New(dbConn)}
}

// Save persists a checkpoint to PostgreSQL. The checkpoint's Data field is
// serialized to JSON before storage to allow for flexible schema evolution.
func (p *PGCheckpointStorage) Save(ctx context.Context, cp *storage.Checkpoint) error {
	dataBytes, err := json.Marshal(cp.Data)
	if err != nil {
		return err
	}

	err = p.q.CreateOrUpdateCheckpoint(ctx, db.CreateOrUpdateCheckpointParams{
		TargetID: cp.TargetID,
		Data:     dataBytes,
	})
	return err
}

// Load retrieves a checkpoint by target ID. Returns nil if no checkpoint exists
// for the given target. The stored JSON data is deserialized into the checkpoint's
// Data field.
func (p *PGCheckpointStorage) Load(ctx context.Context, targetID string) (*storage.Checkpoint, error) {
	dbCp, err := p.q.GetCheckpoint(ctx, targetID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	var data map[string]any
	if err := json.Unmarshal(dbCp.Data, &data); err != nil {
		return nil, err
	}
	return &storage.Checkpoint{
		ID:        dbCp.ID,
		TargetID:  dbCp.TargetID,
		Data:      data,
		UpdatedAt: dbCp.UpdatedAt,
	}, nil
}

// LoadByID retrieves a checkpoint by its unique database ID.
func (p *PGCheckpointStorage) LoadByID(ctx context.Context, id int64) (*storage.Checkpoint, error) {
	dbCp, err := p.q.GetCheckpointByID(ctx, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	var data map[string]any
	if err := json.Unmarshal(dbCp.Data, &data); err != nil {
		return nil, err
	}
	return &storage.Checkpoint{
		ID:        dbCp.ID,
		TargetID:  dbCp.TargetID,
		Data:      data,
		UpdatedAt: dbCp.UpdatedAt,
	}, nil
}

// Delete removes a checkpoint for the given target ID. It is not an error if
// the checkpoint does not exist.
func (p *PGCheckpointStorage) Delete(ctx context.Context, targetID string) error {
	return p.q.DeleteCheckpoint(ctx, targetID)
}