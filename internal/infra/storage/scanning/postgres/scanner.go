package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/db"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/internal/infra/storage"
)

var _ scanning.ScannerRepository = (*scannerStore)(nil)

// scannerStore implements the scanning.ScannerRepository interface using PostgreSQL.
type scannerStore struct {
	q      *db.Queries
	db     *pgxpool.Pool
	tracer trace.Tracer
}

// NewScannerStore creates a new PostgreSQL-backed scanner repository with tracing.
func NewScannerStore(pool *pgxpool.Pool, tracer trace.Tracer) *scannerStore {
	return &scannerStore{q: db.New(pool), db: pool, tracer: tracer}
}

// CreateScannerGroup persists a new scanner group to the database.
func (r *scannerStore) CreateScannerGroup(ctx context.Context, group *scanning.ScannerGroup) error {
	dbAttrs := append(
		defaultDBAttributes,
		attribute.String("group_id", group.ID().String()),
		attribute.String("group_name", group.Name()),
	)

	return storage.ExecuteAndTrace(ctx, r.tracer, "postgres.create_scanner_group", dbAttrs, func(ctx context.Context) error {
		rowsAffected, err := r.q.CreateScannerGroup(ctx, db.CreateScannerGroupParams{
			ID:          pgtype.UUID{Bytes: group.ID(), Valid: true},
			Name:        group.Name(),
			Description: pgtype.Text{String: group.Description(), Valid: true},
		})

		if err != nil {
			return fmt.Errorf("failed to create scanner group: %w", err)
		}

		// If no rows were affected, the group already exists (due to ON CONFLICT DO NOTHING).
		if rowsAffected == 0 {
			return scanning.ErrScannerGroupAlreadyExists
		}

		return nil
	})
}

// CreateScanner persists a new scanner to the database.
func (r *scannerStore) CreateScanner(ctx context.Context, scanner *scanning.Scanner) error {
	dbAttrs := append(
		defaultDBAttributes,
		attribute.String("scanner_id", scanner.ID().String()),
		attribute.String("group_id", scanner.GroupID().String()),
	)

	return storage.ExecuteAndTrace(ctx, r.tracer, "postgres.create_scanner", dbAttrs, func(ctx context.Context) error {
		metadataJSON, err := json.Marshal(scanner.Metadata())
		if err != nil {
			return fmt.Errorf("failed to marshal scanner metadata: %w", err)
		}

		err = r.q.CreateScanner(ctx, db.CreateScannerParams{
			ID:            pgtype.UUID{Bytes: scanner.ID(), Valid: true},
			GroupID:       pgtype.UUID{Bytes: scanner.GroupID(), Valid: true},
			Name:          scanner.Name(),
			Version:       scanner.Version(),
			LastHeartbeat: pgtype.Timestamptz{Time: scanner.LastHeartbeat(), Valid: true},
			Status:        db.ScannerStatus(scanner.Status()),
			IpAddress:     scanner.IPAddress(),
			Hostname:      pgtype.Text{String: scanner.Hostname(), Valid: true},
			Metadata:      metadataJSON,
		})

		if err != nil {
			return fmt.Errorf("failed to create scanner: %w", err)
		}

		return nil
	})
}
