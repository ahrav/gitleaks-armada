package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/db"
	"github.com/ahrav/gitleaks-armada/internal/domain/enumeration"
	"github.com/ahrav/gitleaks-armada/internal/infra/storage"
)

// Ensure urlTargetStore satisfies enumeration.URLRepository.
var _ enumeration.URLRepository = (*urlTargetStore)(nil)

// urlTargetStore implements enumeration.URLRepository using PostgreSQL.
type urlTargetStore struct {
	q      *db.Queries
	tracer trace.Tracer
}

// NewURLTargetStore creates a PostgreSQL-backed store for URLTarget aggregates.
func NewURLTargetStore(pool *pgxpool.Pool, tracer trace.Tracer) *urlTargetStore {
	return &urlTargetStore{
		q:      db.New(pool),
		tracer: tracer,
	}
}

// Create inserts a new URLTarget and returns its ID.
func (s *urlTargetStore) Create(ctx context.Context, target *enumeration.URLTarget) (int64, error) {
	dbAttrs := append(
		defaultDBAttributes,
		attribute.String("db.method", "CreateURLTarget"),
		attribute.String("url", target.URL()),
	)

	var newID int64
	err := storage.ExecuteAndTrace(ctx, s.tracer, "postgres.urltarget.create", dbAttrs, func(ctx context.Context) error {
		span := trace.SpanFromContext(ctx)

		metadataBytes, err := json.Marshal(target.Metadata())
		if err != nil {
			return fmt.Errorf("failed to marshal metadata: %w", err)
		}

		params := db.CreateURLTargetParams{
			Url:      target.URL(),
			Metadata: metadataBytes,
		}
		newID, err = s.q.CreateURLTarget(ctx, params)
		if err != nil {
			return fmt.Errorf("urlTargetStore.Create: insert error: %w", err)
		}
		span.SetAttributes(attribute.Int64("db.id", newID))
		target.SetID(newID)

		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("urlTargetStore.Create: %w", err)
	}

	return newID, nil
}

// Update modifies an existing URLTarget. Returns an error if the record doesn't exist or fails to update.
func (s *urlTargetStore) Update(ctx context.Context, target *enumeration.URLTarget) error {
	dbAttrs := append(
		defaultDBAttributes,
		attribute.String("db.method", "UpdateURLTarget"),
		attribute.Int64("url_target_id", target.ID()),
		attribute.String("url", target.URL()),
	)

	err := storage.ExecuteAndTrace(ctx, s.tracer, "postgres.urltarget.update", dbAttrs, func(ctx context.Context) error {
		span := trace.SpanFromContext(ctx)

		metadataBytes, err := json.Marshal(target.Metadata())
		if err != nil {
			return fmt.Errorf("failed to marshal metadata: %w", err)
		}

		params := db.UpdateURLTargetParams{
			ID:       target.ID(),
			Url:      target.URL(),
			Metadata: metadataBytes,
		}

		rowsAff, err := s.q.UpdateURLTarget(ctx, params)
		if err != nil {
			return fmt.Errorf("urlTargetStore.Update: update error: %w", err)
		}
		if rowsAff == 0 {
			span.SetAttributes(attribute.Bool("db.no_rows", true))
			span.RecordError(errors.New("no rows affected"))
			return fmt.Errorf("urlTargetStore.Update: no rows affected")
		}
		span.SetAttributes(attribute.Int64("db.rows_affected", rowsAff))

		return nil
	})
	if err != nil {
		return fmt.Errorf("urlTargetStore.Update: %w", err)
	}

	return nil
}

// GetByURL looks up a URLTarget by its URL. Returns (nil, nil) if no matching record exists.
func (s *urlTargetStore) GetByURL(ctx context.Context, urlStr string) (*enumeration.URLTarget, error) {
	dbAttrs := append(
		defaultDBAttributes,
		attribute.String("db.method", "GetByURLTarget"),
		attribute.String("url", urlStr),
	)

	var domainTarget *enumeration.URLTarget
	err := storage.ExecuteAndTrace(ctx, s.tracer, "postgres.urltarget.get_by_url", dbAttrs, func(ctx context.Context) error {
		span := trace.SpanFromContext(ctx)

		dbRow, err := s.q.GetURLTargetByURL(ctx, urlStr)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				span.SetAttributes(attribute.Bool("db.no_rows", true))
				return nil
			}
			return fmt.Errorf("select error: %w", err)
		}

		var meta map[string]any
		if err := json.Unmarshal(dbRow.Metadata, &meta); err != nil {
			return fmt.Errorf("failed to unmarshal metadata: %w", err)
		}
		span.SetAttributes(attribute.Int64("db.id", dbRow.ID))

		domainTarget = enumeration.ReconstructURLTarget(
			dbRow.ID,
			dbRow.Url,
			meta,
			enumeration.ReconstructTimeline(time.Time{}, dbRow.UpdatedAt.Time, time.Time{}),
		)

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("urlTargetStore.GetByURL: %w", err)
	}

	return domainTarget, nil
}
