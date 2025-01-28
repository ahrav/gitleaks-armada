package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
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
	db     *pgxpool.Pool
	tracer trace.Tracer
}

// NewJobStore creates a new PostgreSQL-backed job repository with tracing capabilities.
// It encapsulates database operations and telemetry for scan job management.
func NewJobStore(pool *pgxpool.Pool, tracer trace.Tracer) *jobStore {
	return &jobStore{
		q:      db.New(pool),
		db:     pool,
		tracer: tracer,
	}
}

// defaultDBAttributes defines standard OpenTelemetry attributes for database operations.
var defaultDBAttributes = []attribute.KeyValue{
	attribute.String("db.system", "postgresql"),
}

// CreateJob persists a new scan job to the database.
func (r *jobStore) CreateJob(ctx context.Context, job *scanning.Job) error {
	dbAttrs := append(
		defaultDBAttributes,
		attribute.String("job_id", job.JobID().String()),
		attribute.String("status", string(job.Status())),
		attribute.String("start_time", job.StartTime().String()),
	)

	return storage.ExecuteAndTrace(ctx, r.tracer, "postgres.create_job", dbAttrs, func(ctx context.Context) error {
		err := r.q.CreateJob(ctx, db.CreateJobParams{
			JobID:  pgtype.UUID{Bytes: job.JobID(), Valid: true},
			Status: db.ScanJobStatus(job.Status()),
		})
		if err != nil {
			return fmt.Errorf("CreateJob insert error: %w", err)
		}
		return nil
	})
}

// UpdateJob modifies an existing job's state in the database.
func (r *jobStore) UpdateJob(ctx context.Context, job *scanning.Job) error {
	dbAttrs := append(
		defaultDBAttributes,
		attribute.String("job_id", job.JobID().String()),
		attribute.String("status", string(job.Status())),
	)

	return storage.ExecuteAndTrace(ctx, r.tracer, "postgres.update_job", dbAttrs, func(ctx context.Context) error {
		span := trace.SpanFromContext(ctx)

		endTime, hasEndTime := job.EndTime()
		dbEndTime := pgtype.Timestamptz{
			Time:  endTime,
			Valid: hasEndTime,
		}

		rowsAffected, err := r.q.UpdateJob(ctx, db.UpdateJobParams{
			JobID:     pgtype.UUID{Bytes: job.JobID(), Valid: true},
			Status:    db.ScanJobStatus(job.Status()),
			StartTime: pgtype.Timestamptz{Time: job.StartTime(), Valid: true},
			EndTime:   dbEndTime,
		})
		if err != nil {
			return fmt.Errorf("UpdateJob query error: %w", err)
		}

		if rowsAffected == 0 {
			span.SetAttributes(attribute.Bool("job_not_found", true))
			span.RecordError(errors.New("job not found"))
			return fmt.Errorf("job not found: %s", job.JobID())
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
func (r *jobStore) GetJob(ctx context.Context, jobID uuid.UUID) (*scanning.Job, error) {
	dbAttrs := append(
		defaultDBAttributes,
		attribute.String("job_id", jobID.String()),
	)

	var job *scanning.Job
	err := storage.ExecuteAndTrace(ctx, r.tracer, "postgres.get_job", dbAttrs, func(ctx context.Context) error {
		rows, err := r.q.GetJob(ctx, pgtype.UUID{Bytes: jobID, Valid: true})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			return fmt.Errorf("GetJob query error: %w", err)
		}
		if len(rows) == 0 {
			return scanning.ErrJobNotFound
		}

		var targetIDs []uuid.UUID
		firstRow := rows[0] // Use first row for job details

		for _, row := range rows {
			if row.ScanTargetID.Valid {
				targetIDs = append(targetIDs, row.ScanTargetID.Bytes)
			}
		}

		timeline := scanning.ReconstructTimeline(
			firstRow.StartTime.Time,
			firstRow.EndTime.Time,
			firstRow.UpdatedAt.Time,
		)

		job = scanning.ReconstructJob(
			firstRow.JobID.Bytes,
			scanning.JobStatus(firstRow.Status),
			timeline,
			targetIDs,
			nil, // TODO: I don't think we need metrics for only the job.
		)
		return nil
	})
	if err != nil {
		return nil, err
	}

	return job, nil
}

// BulkUpdateJobMetrics updates metrics for multiple jobs in a single operation.
func (r *jobStore) BulkUpdateJobMetrics(ctx context.Context, updates map[uuid.UUID]*scanning.JobMetrics) (int64, error) {
	dbAttrs := append(
		defaultDBAttributes,
		attribute.Int("num_jobs", len(updates)),
	)

	values := make([]string, 0, len(updates))
	args := make([]any, 0, len(updates)*7) // jobID + 4 metrics fields + 2 timestamps
	i := 1
	now := time.Now().UTC()

	for jobID, metrics := range updates {
		values = append(values, fmt.Sprintf("($%d::uuid, $%d::int, $%d::int, $%d::int, $%d::int, $%d::timestamptz, $%d::timestamptz)",
			i, i+1, i+2, i+3, i+4, i+5, i+6))
		args = append(args,
			jobID,
			metrics.TotalTasks(),
			metrics.CompletedTasks(),
			metrics.FailedTasks(),
			metrics.StaleTasks(),
			now, // created_at
			now, // updated_at
		)
		i += 7
	}

	if len(values) == 0 {
		return 0, scanning.ErrNoJobMetricsUpdated
	}

	query := fmt.Sprintf(`
		INSERT INTO scan_job_metrics (
			job_id,
			total_tasks,
			completed_tasks,
			failed_tasks,
			stale_tasks,
			created_at,
			updated_at
		) VALUES %s
		ON CONFLICT (job_id) DO UPDATE SET
			total_tasks = EXCLUDED.total_tasks,
			completed_tasks = EXCLUDED.completed_tasks,
			failed_tasks = EXCLUDED.failed_tasks,
			stale_tasks = EXCLUDED.stale_tasks,
			updated_at = NOW()
	`, strings.Join(values, ","))

	var rowsAffected int64
	err := storage.ExecuteAndTrace(ctx, r.tracer, "postgres.bulk_update_job_metrics", dbAttrs, func(ctx context.Context) error {
		result, err := r.db.Exec(ctx, query, args...)
		if err != nil {
			return fmt.Errorf("bulk update job metrics query error: %w", err)
		}
		rowsAffected = result.RowsAffected()
		if rowsAffected == 0 {
			return scanning.ErrNoJobMetricsUpdated
		}

		return nil
	})

	return rowsAffected, err
}

// GetJobMetrics retrieves metrics for a specific job.
func (r *jobStore) GetJobMetrics(ctx context.Context, jobID uuid.UUID) (*scanning.JobMetrics, error) {
	dbAttrs := append(
		defaultDBAttributes,
		attribute.String("job_id", jobID.String()),
	)

	var jobMetrics *scanning.JobMetrics
	err := storage.ExecuteAndTrace(ctx, r.tracer, "postgres.get_job_metrics", dbAttrs, func(ctx context.Context) error {
		metrics, err := r.q.GetJobMetrics(ctx, pgtype.UUID{Bytes: jobID, Valid: true})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return scanning.ErrNoJobMetricsFound
			}
			return fmt.Errorf("get job metrics query error: %w", err)
		}

		jobMetrics = scanning.ReconstructJobMetrics(
			int(metrics.TotalTasks),
			int(metrics.CompletedTasks),
			int(metrics.FailedTasks),
			int(metrics.StaleTasks),
		)
		return nil
	})
	if err != nil {
		return nil, err
	}

	return jobMetrics, nil
}
