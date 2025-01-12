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

// scanTargetRepository implements enumeration.ScanTargetRepository to provide
// persistent storage of scan targets in PostgreSQL. This enables tracking of
// scan targets across multiple scan sessions.
var _ enumeration.ScanTargetRepository = (*scanTargetRepository)(nil)

// scanTargetRepository manages scan target persistence in PostgreSQL.
type scanTargetRepository struct {
	q      *db.Queries // Provides type-safe database queries
	tracer trace.Tracer
}

// NewScanTargetRepository creates a new PostgreSQL-backed scan target repository.
// It requires a connection pool and tracer for observability. The repository
// provides CRUD operations for scan targets with automatic tracing.
func NewScanTargetRepository(pool *pgxpool.Pool, tracer trace.Tracer) *scanTargetRepository {
	return &scanTargetRepository{
		q:      db.New(pool),
		tracer: tracer,
	}
}

// Create persists a new scan target to the database. It automatically sets
// created_at and updated_at timestamps. Returns an error if the target cannot
// be created or if metadata serialization fails.
func (r *scanTargetRepository) Create(ctx context.Context, target *enumeration.ScanTarget) (int64, error) {
	dbAttrs := []attribute.KeyValue{
		attribute.String("repository", "ScanTargetRepository"),
		attribute.String("method", "Create"),
		attribute.String("target_name", target.Name()),
		attribute.String("target_type", target.TargetType()),
	}

	var id int64
	err := storage.ExecuteAndTrace(ctx, r.tracer, "postgres.scantarget.create", dbAttrs, func(ctx context.Context) error {
		// Metadata must be JSON serialized for storage
		metadataBytes, err := json.Marshal(target.Metadata())
		if err != nil {
			return fmt.Errorf("failed to marshal metadata: %w", err)
		}

		var createErr error
		id, createErr = r.q.CreateScanTarget(ctx, db.CreateScanTargetParams{
			Name:       target.Name(),
			TargetType: target.TargetType(),
			TargetID:   target.TargetID(),
			Metadata:   metadataBytes,
		})
		if createErr != nil {
			return fmt.Errorf("insert error: %w", createErr)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}

	return id, nil
}

// Update modifies an existing scan target's scan time and metadata.
// Returns an error if the target doesn't exist or if updates fail.
func (r *scanTargetRepository) Update(ctx context.Context, target *enumeration.ScanTarget) error {
	dbAttrs := []attribute.KeyValue{
		attribute.String("repository", "ScanTargetRepository"),
		attribute.String("method", "Update"),
		attribute.Int64("scan_target_id", target.ID()),
	}

	return storage.ExecuteAndTrace(ctx, r.tracer, "postgres.scantarget.update", dbAttrs, func(ctx context.Context) error {
		metadataBytes, err := json.Marshal(target.Metadata())
		if err != nil {
			return fmt.Errorf("failed to marshal metadata: %w", err)
		}

		var lastScan pgtype.Timestamptz
		if lst := target.LastScanTime(); lst != nil {
			lastScan = pgtype.Timestamptz{Time: *lst, Valid: true}
		} else {
			lastScan = pgtype.Timestamptz{Valid: false}
		}

		rowsAffected, err := r.q.UpdateScanTargetScanTime(ctx, db.UpdateScanTargetScanTimeParams{
			ID:           target.ID(),
			LastScanTime: lastScan,
			Metadata:     metadataBytes,
		})
		if err != nil {
			return fmt.Errorf("update error: %w", err)
		}
		if rowsAffected == 0 {
			return fmt.Errorf("no rows affected for ID=%d", target.ID())
		}
		return nil
	})
}

// GetByID retrieves a scan target by its primary key. Returns nil if no target
// is found with the given ID. The returned target includes all fields including
// metadata and timestamps.
func (r *scanTargetRepository) GetByID(ctx context.Context, id int64) (*enumeration.ScanTarget, error) {
	dbAttrs := []attribute.KeyValue{
		attribute.String("repository", "ScanTargetRepository"),
		attribute.String("method", "GetByID"),
		attribute.Int64("scan_target_id", id),
	}

	var foundTarget *enumeration.ScanTarget
	err := storage.ExecuteAndTrace(ctx, r.tracer, "postgres.scantarget.get_by_id", dbAttrs, func(ctx context.Context) error {
		row, err := r.q.GetScanTargetByID(ctx, id)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			return fmt.Errorf("select error: %w", err)
		}

		var metadata map[string]any
		if err := json.Unmarshal(row.Metadata, &metadata); err != nil {
			return fmt.Errorf("failed to unmarshal metadata: %w", err)
		}

		var lst *time.Time
		if row.LastScanTime.Valid {
			lst = &row.LastScanTime.Time
		}

		foundTarget = enumeration.ReconstructScanTarget(
			row.ID,
			row.Name,
			row.TargetType,
			row.TargetID,
			lst,
			metadata,
			enumeration.ReconstructTimeline(row.CreatedAt.Time, row.UpdatedAt.Time, row.LastScanTime.Time),
		)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("scanTargetRepository.GetByID: %w", err)
	}
	return foundTarget, nil
}

// Find looks up a scan target by its type and ID combination. This allows finding
// targets by their logical identity rather than database ID. Returns nil if no
// matching target exists.
func (r *scanTargetRepository) Find(ctx context.Context, targetType string, targetID int64) (*enumeration.ScanTarget, error) {
	dbAttrs := []attribute.KeyValue{
		attribute.String("repository", "ScanTargetRepository"),
		attribute.String("method", "Find"),
		attribute.String("target_type", targetType),
		attribute.Int64("target_id", targetID),
	}

	var foundTarget *enumeration.ScanTarget
	err := storage.ExecuteAndTrace(ctx, r.tracer, "postgres.scantarget.find", dbAttrs, func(ctx context.Context) error {
		row, err := r.q.FindScanTarget(ctx, db.FindScanTargetParams{
			TargetType: targetType,
			TargetID:   targetID,
		})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			return fmt.Errorf("select error: %w", err)
		}

		var metadata map[string]any
		if err := json.Unmarshal(row.Metadata, &metadata); err != nil {
			return fmt.Errorf("failed to unmarshal metadata: %w", err)
		}

		var lst *time.Time
		if row.LastScanTime.Valid {
			lst = &row.LastScanTime.Time
		}

		foundTarget = enumeration.ReconstructScanTarget(
			row.ID,
			row.Name,
			row.TargetType,
			row.TargetID,
			lst,
			metadata,
			enumeration.ReconstructTimeline(row.CreatedAt.Time, row.UpdatedAt.Time, row.LastScanTime.Time),
		)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("scanTargetRepository.Find: %w", err)
	}
	return foundTarget, nil
}

// List returns a paginated list of scan targets ordered by creation time.
// The limit and offset parameters control pagination. Results include all
// target fields including metadata and timestamps.
func (r *scanTargetRepository) List(ctx context.Context, limit, offset int32) ([]*enumeration.ScanTarget, error) {
	dbAttrs := []attribute.KeyValue{
		attribute.String("repository", "ScanTargetRepository"),
		attribute.String("method", "List"),
		attribute.Int64("limit", int64(limit)),
		attribute.Int64("offset", int64(offset)),
	}

	var results []*enumeration.ScanTarget
	err := storage.ExecuteAndTrace(ctx, r.tracer, "postgres.scantarget.list", dbAttrs, func(ctx context.Context) error {
		rows, err := r.q.ListScanTargets(ctx, db.ListScanTargetsParams{
			Limit:  limit,
			Offset: offset,
		})
		if err != nil {
			return fmt.Errorf("list error: %w", err)
		}

		tmp := make([]*enumeration.ScanTarget, 0, len(rows))
		for _, row := range rows {
			var metadata map[string]any
			if err := json.Unmarshal(row.Metadata, &metadata); err != nil {
				return fmt.Errorf("failed to unmarshal metadata: %w", err)
			}
			var lst *time.Time
			if row.LastScanTime.Valid {
				lst = &row.LastScanTime.Time
			}

			tmp = append(tmp, enumeration.ReconstructScanTarget(
				row.ID,
				row.Name,
				row.TargetType,
				row.TargetID,
				lst,
				metadata,
				enumeration.ReconstructTimeline(row.CreatedAt.Time, row.UpdatedAt.Time, row.LastScanTime.Time),
			))
		}
		results = tmp
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("scanTargetRepository.List: %w", err)
	}
	return results, nil
}
