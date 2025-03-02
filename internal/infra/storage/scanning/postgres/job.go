package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/db"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/internal/infra/storage"
	"github.com/ahrav/gitleaks-armada/pkg/common/uuid"
)

// jobStore implements scanning.JobRepository using PostgreSQL as the backing store.
// It provides persistent storage for scan jobs and their associated targets, enabling
// tracking of job status, timing, and relationships across the scanning domain.
var _ scanning.JobRepository = (*jobStore)(nil)

// Ensure jobStore implements the ScanJobQueryRepository interface
var _ scanning.ScanJobQueryRepository = (*jobStore)(nil)

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

// CreateJob persists a new scan job and initializes its metrics record.
func (r *jobStore) CreateJob(ctx context.Context, job *scanning.Job) error {
	dbAttrs := append(
		defaultDBAttributes,
		attribute.String("job_id", job.JobID().String()),
		attribute.String("status", string(job.Status())),
		attribute.String("source_type", job.SourceType()),
		attribute.String("start_time", job.StartTime().String()),
	)

	return storage.ExecuteAndTrace(ctx, r.tracer, "postgres.create_job", dbAttrs, func(ctx context.Context) error {
		// Initial job metrics should get created alongisde the job.
		ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()

		tx, err := r.db.Begin(ctx)
		if err != nil {
			return fmt.Errorf("begin transaction error: %w", err)
		}
		defer tx.Rollback(ctx)

		qtx := r.q.WithTx(tx)

		err = qtx.CreateJob(ctx, db.CreateJobParams{
			JobID:      pgtype.UUID{Bytes: job.JobID(), Valid: true},
			Status:     db.ScanJobStatus(job.Status()),
			SourceType: job.SourceType(),
			Config:     job.Config(),
		})
		if err != nil {
			return fmt.Errorf("CreateJob insert error: %w", err)
		}

		err = qtx.CreateJobMetrics(ctx, pgtype.UUID{Bytes: job.JobID(), Valid: true})
		if err != nil {
			return fmt.Errorf("CreateJobMetrics insert error: %w", err)
		}

		return tx.Commit(ctx)
	})
}

// IncrementTotalTasks atomically increments the total tasks count for a job.
// It returns an error if the job metrics record doesn't exist or if the update fails.
func (r *jobStore) IncrementTotalTasks(ctx context.Context, jobID uuid.UUID, amount int) error {
	dbAttrs := append(
		defaultDBAttributes,
		attribute.String("job_id", jobID.String()),
		attribute.Int("amount", amount),
	)

	return storage.ExecuteAndTrace(ctx, r.tracer, "postgres.increment_total_tasks", dbAttrs, func(ctx context.Context) error {
		rowsAffected, err := r.q.IncrementTotalTasks(ctx, db.IncrementTotalTasksParams{
			JobID:      pgtype.UUID{Bytes: jobID, Valid: true},
			TotalTasks: int32(amount),
		})
		if err != nil {
			return fmt.Errorf("increment total tasks error: %w", err)
		}
		if rowsAffected == 0 {
			return scanning.ErrNoJobMetricsFound
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
		rowsAffected, err := r.q.UpdateJob(ctx, db.UpdateJobParams{
			JobID:     pgtype.UUID{Bytes: job.JobID(), Valid: true},
			Status:    db.ScanJobStatus(job.Status()),
			StartTime: pgtype.Timestamptz{Time: job.StartTime(), Valid: true},
			EndTime:   pgtype.Timestamptz{Time: endTime, Valid: hasEndTime},
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
		row, err := r.q.GetJob(ctx, pgtype.UUID{Bytes: jobID, Valid: true})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return scanning.ErrJobNotFound
			}
			return fmt.Errorf("GetJob query error: %w", err)
		}

		timeline := scanning.ReconstructTimeline(row.StartTime.Time, row.EndTime.Time, row.UpdatedAt.Time)
		job = scanning.ReconstructJob(
			row.JobID.Bytes,
			row.SourceType,
			row.Config,
			scanning.JobStatus(row.Status),
			timeline,
		)
		return nil
	})
	if err != nil {
		return nil, err
	}

	return job, nil
}

// GetJobConfigInfo retrieves just the source type and configuration for a job.
// This is useful for lightweight access to job configuration without loading the full job.
func (r *jobStore) GetJobConfigInfo(ctx context.Context, jobID uuid.UUID) (*scanning.JobConfigInfo, error) {
	dbAttrs := append(
		defaultDBAttributes,
		attribute.String("job_id", jobID.String()),
	)

	var configInfo *scanning.JobConfigInfo
	err := storage.ExecuteAndTrace(ctx, r.tracer, "postgres.get_job_config_info", dbAttrs, func(ctx context.Context) error {
		row, err := r.q.GetJobSourceTypeConfig(ctx, pgtype.UUID{Bytes: jobID, Valid: true})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return scanning.ErrJobNotFound
			}
			return fmt.Errorf("GetJobSourceTypeConfig query error: %w", err)
		}

		configInfo = scanning.NewJobConfigInfo(jobID, row.SourceType, row.Config)
		return nil
	})
	if err != nil {
		return nil, err
	}

	return configInfo, nil
}

const (
	maxBatchSize  = 1000
	numWorkers    = 2
	batchChanSize = 2
)

// jobEntry holds a reference to a single update item.
type jobEntry struct {
	jobID   uuid.UUID
	metrics *scanning.JobMetrics
}

type batchResult struct {
	rows int64
	err  error
}

type batchJob struct {
	batch  []jobEntry
	result chan batchResult
}

// BulkUpdateJobMetrics updates metrics for multiple jobs using a pool of workers
// to process batches concurrently.
func (r *jobStore) BulkUpdateJobMetrics(ctx context.Context, updates map[uuid.UUID]*scanning.JobMetrics) (int64, error) {
	if len(updates) == 0 {
		return 0, scanning.ErrNoJobMetricsUpdated
	}

	// Channels for distributing work and receiving completion signals.
	batchChan := make(chan batchJob, batchChanSize)
	done := make(chan struct{})

	for i := 0; i < numWorkers; i++ {
		go r.batchWorker(ctx, batchChan, done)
	}

	var totalRowsAffected int64
	var errs []error
	var currentBatch []jobEntry
	currentBatch = make([]jobEntry, 0, maxBatchSize)

	// Helper to queue a slice of job entries to workers.
	for jobID, metrics := range updates {
		currentBatch = append(currentBatch, jobEntry{jobID, metrics})
		if len(currentBatch) == maxBatchSize {
			job := batchJob{
				batch:  currentBatch,
				result: make(chan batchResult, 1),
			}

			select {
			case batchChan <- job:
				result := <-job.result
				if result.err != nil {
					errs = append(errs, result.err)
				}
				totalRowsAffected += result.rows
			case <-ctx.Done():
				close(batchChan)
				return 0, ctx.Err()
			}

			currentBatch = make([]jobEntry, 0, maxBatchSize)
		}
	}

	// Flush any trailing batch if it has leftover entries.
	if len(currentBatch) > 0 {
		job := batchJob{
			batch:  currentBatch,
			result: make(chan batchResult, 1),
		}

		select {
		case batchChan <- job:
			result := <-job.result
			if result.err != nil {
				errs = append(errs, result.err)
			}
			totalRowsAffected += result.rows
		case <-ctx.Done():
			close(batchChan)
			return 0, ctx.Err()
		}
	}

	// No more batches will be queued.
	close(batchChan)

	// Wait for all workers to finish.
	for i := 0; i < numWorkers; i++ {
		select {
		case <-done:
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}

	if len(errs) > 0 {
		return totalRowsAffected, fmt.Errorf("batch update errors: %v", errs)
	}
	if totalRowsAffected == 0 {
		return 0, scanning.ErrNoJobMetricsUpdated
	}
	return totalRowsAffected, nil
}

// batchWorker consumes batchJob messages from batchChan.
func (r *jobStore) batchWorker(ctx context.Context, batchChan <-chan batchJob, done chan<- struct{}) {
	defer func() {
		select {
		case done <- struct{}{}:
		case <-ctx.Done():
		}
	}()

	for job := range batchChan {
		rows, err := r.executeBatchUpdate(ctx, job.batch)
		job.result <- batchResult{rows: rows, err: err}
	}
}

func (r *jobStore) executeBatchUpdate(ctx context.Context, entries []jobEntry) (int64, error) {
	if len(entries) == 0 {
		return 0, nil
	}

	dbAttrs := append(
		defaultDBAttributes,
		attribute.Int("batch_size", len(entries)),
	)

	now := time.Now().UTC()
	// For each row, we have:
	//   job_id + total_tasks + pending_tasks + in_progress_tasks + completed_tasks + failed_tasks + stale_tasks + cancelled_tasks + paused_tasks + created_at + updated_at
	//
	// We'll build a VALUES string with placeholders like:
	//   ($1::uuid, $2::int, $3::int, $4::int, $5::int, $6::int, $7::int, $8::int, $9::int, $10::timestamptz, $11::timestamptz), ...
	values := make([]string, 0, len(entries))
	args := make([]any, 0, len(entries)*11) // jobID + 8 metrics fields + 2 timestamps
	i := 1

	for _, e := range entries {
		values = append(values, fmt.Sprintf("($%d::uuid, $%d::int, $%d::int, $%d::int, $%d::int, $%d::int, $%d::int, $%d::int, $%d::int, $%d::timestamptz, $%d::timestamptz)",
			i, i+1, i+2, i+3, i+4, i+5, i+6, i+7, i+8, i+9, i+10))
		args = append(args,
			e.jobID,
			e.metrics.TotalTasks(),
			e.metrics.PendingTasks(),
			e.metrics.InProgressTasks(),
			e.metrics.CompletedTasks(),
			e.metrics.FailedTasks(),
			e.metrics.StaleTasks(),
			e.metrics.CancelledTasks(),
			e.metrics.PausedTasks(),
			now, // created_at
			now, // updated_at
		)
		i += 11
	}

	query := fmt.Sprintf(`
			INSERT INTO scan_job_metrics (
					job_id,
					total_tasks,
					pending_tasks,
					in_progress_tasks,
					completed_tasks,
					failed_tasks,
					stale_tasks,
					cancelled_tasks,
					paused_tasks,
					created_at,
					updated_at
			) VALUES %s
			ON CONFLICT (job_id) DO UPDATE SET
					total_tasks = EXCLUDED.total_tasks,
					pending_tasks = EXCLUDED.pending_tasks,
					in_progress_tasks = EXCLUDED.in_progress_tasks,
					completed_tasks = EXCLUDED.completed_tasks,
					failed_tasks = EXCLUDED.failed_tasks,
					stale_tasks = EXCLUDED.stale_tasks,
					cancelled_tasks = EXCLUDED.cancelled_tasks,
					paused_tasks = EXCLUDED.paused_tasks,
					updated_at = NOW()
	`, strings.Join(values, ","))

	var rowsAffected int64
	err := storage.ExecuteAndTrace(ctx, r.tracer, "postgres.bulk_update_job_metrics", dbAttrs, func(ctx context.Context) error {
		result, err := r.db.Exec(ctx, query, args...)
		if err != nil {
			return fmt.Errorf("bulk update job metrics query error: %w", err)
		}
		rowsAffected = result.RowsAffected()
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
			int(metrics.PendingTasks),
			int(metrics.InProgressTasks),
			int(metrics.CompletedTasks),
			int(metrics.FailedTasks),
			int(metrics.StaleTasks),
			int(metrics.CancelledTasks),
			int(metrics.PausedTasks),
		)
		return nil
	})
	if err != nil {
		return nil, err
	}

	return jobMetrics, nil
}

// GetCheckpoints retrieves all checkpoints for a job's metrics
func (r *jobStore) GetCheckpoints(ctx context.Context, jobID uuid.UUID) (map[int32]int64, error) {
	dbAttrs := append(
		defaultDBAttributes,
		attribute.String("job_id", jobID.String()),
	)

	var checkpoints map[int32]int64
	err := storage.ExecuteAndTrace(ctx, r.tracer, "postgres.get_checkpoints", dbAttrs, func(ctx context.Context) error {
		rows, err := r.q.GetJobCheckpoints(ctx, pgtype.UUID{Bytes: jobID, Valid: true})
		if err != nil {
			return fmt.Errorf("get checkpoints error: %w", err)
		}

		if len(rows) == 0 {
			return scanning.ErrNoCheckpointsFound
		}

		checkpoints = make(map[int32]int64, len(rows))
		for _, row := range rows {
			checkpoints[row.PartitionID] = row.PartitionOffset
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return checkpoints, nil
}

// UpdateMetricsAndCheckpoint atomically updates both job metrics and checkpoint.
func (r *jobStore) UpdateMetricsAndCheckpoint(
	ctx context.Context,
	jobID uuid.UUID,
	metrics *scanning.JobMetrics,
	partitionID int32,
	offset int64,
) error {
	dbAttrs := append(
		defaultDBAttributes,
		attribute.String("job_id", jobID.String()),
		attribute.Int("partition_id", int(partitionID)),
		attribute.Int64("offset", offset),
	)

	return storage.ExecuteAndTrace(ctx, r.tracer, "postgres.update_metrics_and_checkpoint", dbAttrs, func(ctx context.Context) error {
		err := r.q.UpdateJobMetricsAndCheckpoint(ctx, db.UpdateJobMetricsAndCheckpointParams{
			JobID:           pgtype.UUID{Bytes: jobID, Valid: true},
			PartitionID:     partitionID,
			PartitionOffset: offset,
			PendingTasks:    int32(metrics.PendingTasks()),
			InProgressTasks: int32(metrics.InProgressTasks()),
			CompletedTasks:  int32(metrics.CompletedTasks()),
			FailedTasks:     int32(metrics.FailedTasks()),
			StaleTasks:      int32(metrics.StaleTasks()),
			CancelledTasks:  int32(metrics.CancelledTasks()),
			PausedTasks:     int32(metrics.PausedTasks()),
		})
		if err != nil {
			return fmt.Errorf("update metrics and checkpoint error: %w", err)
		}
		return nil
	})
}

// GetJobByID retrieves a job detail by its ID, implementing the ScanJobQueryRepository interface.
// It retrieves all job and metrics information in a single query for better performance.
func (r *jobStore) GetJobByID(ctx context.Context, jobID uuid.UUID) (*scanning.JobDetail, error) {
	dbAttrs := append(
		defaultDBAttributes,
		attribute.String("job_id", jobID.String()),
	)

	var jobDetail *scanning.JobDetail
	err := storage.ExecuteAndTrace(ctx, r.tracer, "postgres.get_job_detail", dbAttrs, func(ctx context.Context) error {
		row, err := r.q.GetJobWithMetrics(ctx, pgtype.UUID{Bytes: jobID, Valid: true})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return scanning.ErrJobNotFound
			}
			return fmt.Errorf("getting job with metrics: %w", err)
		}

		var endTime *time.Time
		if row.EndTime.Valid {
			t := row.EndTime.Time
			endTime = &t
		}

		metrics := &scanning.JobDetailMetrics{
			TotalTasks:           int(row.TotalTasks.Int32),
			PendingTasks:         int(row.PendingTasks.Int32),
			InProgressTasks:      int(row.InProgressTasks.Int32),
			CompletedTasks:       int(row.CompletedTasks.Int32),
			FailedTasks:          int(row.FailedTasks.Int32),
			StaleTasks:           int(row.StaleTasks.Int32),
			CancelledTasks:       int(row.CancelledTasks.Int32),
			PausedTasks:          int(row.PausedTasks.Int32),
			CompletionPercentage: row.CompletionPercentage,
		}

		jobDetail = &scanning.JobDetail{
			ID:         jobID,
			Status:     scanning.JobStatus(row.Status),
			SourceType: row.SourceType,
			StartTime:  row.StartTime.Time,
			EndTime:    endTime,
			CreatedAt:  row.CreatedAt.Time,
			UpdatedAt:  row.UpdatedAt.Time,
			Metrics:    metrics,
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return jobDetail, nil
}
