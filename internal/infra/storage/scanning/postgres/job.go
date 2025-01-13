package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/db"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/internal/infra/storage"
)

// jobStore implements scanning.JobRepository using PostgreSQL as the backing store.
// It provides persistent storage for scan jobs and their associated targets, enabling
// tracking of job status, timing, and relationships across the scanning domain.
var _ scanning.JobRepository = (*jobStore)(nil)

type jobStore struct {
	q      *db.Queries
	tracer trace.Tracer
}

// NewJobStore creates a new PostgreSQL-backed job repository with tracing capabilities.
// It encapsulates database operations and telemetry for scan job management.
func NewJobStore(pool *pgxpool.Pool, tracer trace.Tracer) *jobStore {
	return &jobStore{
		q:      db.New(pool),
		tracer: tracer,
	}
}

// defaultDBAttributes defines standard OpenTelemetry attributes for database operations.
var defaultDBAttributes = []attribute.KeyValue{
	attribute.String("db.system", "postgresql"),
}

// CreateJob persists a new scan job to the database. It captures the job's initial state
// including status, timing information, and sets appropriate end time for completed or
// failed jobs.
func (r *jobStore) CreateJob(ctx context.Context, job *scanning.ScanJob) error {
	dbAttrs := append(
		defaultDBAttributes,
		attribute.String("job_id", job.GetJobID().String()),
		attribute.String("status", string(job.GetStatus())),
	)

	return storage.ExecuteAndTrace(ctx, r.tracer, "postgres.create_job", dbAttrs, func(ctx context.Context) error {
		startTime := job.GetStartTime()
		var endTime *time.Time
		// Set end time only for terminal states
		if job.GetStatus() == scanning.JobStatusCompleted || job.GetStatus() == scanning.JobStatusFailed {
			e := job.GetLastUpdateTime()
			endTime = &e
		}

		err := r.q.CreateJob(ctx, db.CreateJobParams{
			JobID:     pgtype.UUID{Bytes: job.GetJobID(), Valid: true},
			Status:    db.ScanJobStatus(job.GetStatus()),
			StartTime: pgtype.Timestamptz{Time: startTime, Valid: true},
			EndTime:   pgtype.Timestamptz{Time: *endTime, Valid: endTime != nil},
		})
		if err != nil {
			return fmt.Errorf("CreateJob insert error: %w", err)
		}
		return nil
	})
}

// UpdateJob modifies an existing job's state in the database. It handles status transitions
// and updates timing information, particularly for jobs reaching terminal states.
func (r *jobStore) UpdateJob(ctx context.Context, job *scanning.ScanJob) error {
	dbAttrs := append(
		defaultDBAttributes,
		attribute.String("job_id", job.GetJobID().String()),
		attribute.String("status", string(job.GetStatus())),
	)

	return storage.ExecuteAndTrace(ctx, r.tracer, "postgres.update_job", dbAttrs, func(ctx context.Context) error {
		startTime := job.GetStartTime()
		var endTime *time.Time
		if job.GetStatus() == scanning.JobStatusCompleted || job.GetStatus() == scanning.JobStatusFailed {
			e := job.GetLastUpdateTime()
			endTime = &e
		}

		err := r.q.UpdateJob(ctx, db.UpdateJobParams{
			JobID:     pgtype.UUID{Bytes: job.GetJobID(), Valid: true},
			Status:    db.ScanJobStatus(job.GetStatus()),
			StartTime: pgtype.Timestamptz{Time: startTime, Valid: true},
			EndTime:   pgtype.Timestamptz{Time: *endTime, Valid: endTime != nil},
		})
		if err != nil {
			return fmt.Errorf("UpdateJob query error: %w", err)
		}
		return nil
	})
}

// AssociateTargets creates relationships between a scan job and its target repositories.
// It efficiently handles bulk insertions using PostgreSQL's COPY protocol for better performance
// when dealing with multiple targets.
func (r *jobStore) AssociateTargets(ctx context.Context, jobID uuid.UUID, targetIDs []uuid.UUID) error {
	dbAttrs := append(
		defaultDBAttributes,
		attribute.String("job_id", jobID.String()),
		attribute.Int("num_targets", len(targetIDs)),
	)

	return storage.ExecuteAndTrace(ctx, r.tracer, "postgres.associate_targets", dbAttrs, func(ctx context.Context) error {
		if len(targetIDs) == 0 {
			return nil
		}
		span := trace.SpanFromContext(ctx)

		rows := make([]db.BulkAssociateTargetsParams, len(targetIDs))
		for i, targetID := range targetIDs {
			rows[i] = db.BulkAssociateTargetsParams{
				JobID:        pgtype.UUID{Bytes: jobID, Valid: true},
				ScanTargetID: pgtype.UUID{Bytes: targetID, Valid: true},
			}
		}

		res, err := r.q.BulkAssociateTargets(ctx, rows)
		if err != nil {
			return fmt.Errorf("bulk associate targets error: %w", err)
		}
		if res != int64(len(targetIDs)) {
			return fmt.Errorf("bulk associate targets returned %d rows, expected %d", res, len(targetIDs))
		}
		span.SetAttributes(attribute.Int64("num_targets_inserted", res))

		return nil
	})
}

// GetJob retrieves a scan job and its associated targets from the database. It reconstructs
// the domain model from the stored data, handling the one-to-many relationship between
// jobs and targets.
func (r *jobStore) GetJob(ctx context.Context, jobID uuid.UUID) (*scanning.ScanJob, error) {
	dbAttrs := append(
		defaultDBAttributes,
		attribute.String("job_id", jobID.String()),
	)

	var job *scanning.ScanJob
	err := storage.ExecuteAndTrace(ctx, r.tracer, "postgres.get_job", dbAttrs, func(ctx context.Context) error {
		rows, err := r.q.GetJob(ctx, pgtype.UUID{Bytes: jobID, Valid: true})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			return fmt.Errorf("GetJob query error: %w", err)
		}
		if len(rows) == 0 {
			return nil
		}

		var targetIDs []uuid.UUID
		firstRow := rows[0] // Use first row for job details

		for _, row := range rows {
			if row.ScanTargetID.Valid {
				targetIDs = append(targetIDs, row.ScanTargetID.Bytes)
			}
		}

		job = scanning.ReconstructJob(
			firstRow.JobID.Bytes,
			scanning.JobStatus(firstRow.Status),
			firstRow.StartTime.Time,
			firstRow.EndTime.Time,
			firstRow.UpdatedAt.Time,
			targetIDs,
		)
		return nil
	})

	if err != nil {
		return nil, err
	}
	return job, nil
}
