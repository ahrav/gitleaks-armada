package postgres

import (
	"context"
	"encoding/json"
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

// Ensure taskStore implements scanning.TaskRepository at compile time.
var _ scanning.TaskRepository = (*taskStore)(nil)

// taskStore implements scanning.TaskRepository using Postgres + sqlc queries.
// It provides persistent storage and retrieval of scan task state, enabling
// tracking of task progress and recovery from failures.
type taskStore struct {
	q      *db.Queries
	tracer trace.Tracer
}

// NewTaskStore creates a TaskRepository backed by PostgreSQL. It encapsulates database
// operations and telemetry for scan task management.
func NewTaskStore(pool *pgxpool.Pool, tracer trace.Tracer) *taskStore {
	return &taskStore{
		q:      db.New(pool),
		tracer: tracer,
	}
}

// CreateTask persists a new task's initial state in the database. It establishes
// the task's relationship to its parent job and initializes monitoring state.
func (s *taskStore) CreateTask(ctx context.Context, task *scanning.Task) error {
	dbAttrs := append(
		defaultDBAttributes,
		attribute.String("task_id", task.GetTaskID().String()),
		attribute.String("job_id", task.GetJobID().String()),
		attribute.String("status", string(task.GetStatus())),
	)

	return storage.ExecuteAndTrace(ctx, s.tracer, "postgres.create_task", dbAttrs, func(ctx context.Context) error {
		span := trace.SpanFromContext(ctx)
		// Only store lastUpdateTime if non-zero to preserve NULL semantics.
		var lastUpdateTime pgtype.Timestamptz
		if !task.GetLastUpdateTime().IsZero() {
			lastUpdateTime = pgtype.Timestamptz{Time: task.GetLastUpdateTime(), Valid: true}
		} else {
			lastUpdateTime = pgtype.Timestamptz{Valid: false}
		}
		span.SetAttributes(attribute.String("last_update_time", lastUpdateTime.Time.String()))

		var checkpointJSON []byte
		if task.LastCheckpoint() != nil {
			var err error
			checkpointJSON, err = json.Marshal(task.LastCheckpoint())
			if err != nil {
				span.SetAttributes(attribute.String("checkpoint_error", err.Error()))
				return fmt.Errorf("failed to marshal checkpoint: %w", err)
			}
		}

		params := db.CreateScanTaskParams{
			TaskID:          pgtype.UUID{Bytes: task.GetTaskID(), Valid: true},
			JobID:           pgtype.UUID{Bytes: task.GetJobID(), Valid: true},
			Status:          db.ScanTaskStatus(task.GetStatus()),
			LastSequenceNum: task.GetLastSequenceNum(),
			StartTime:       pgtype.Timestamptz{Time: task.StartTime(), Valid: true},
			LastUpdateTime:  lastUpdateTime,
			ItemsProcessed:  task.GetItemsProcessed(),
			ProgressDetails: task.ProgressDetails(),
			LastCheckpoint:  checkpointJSON,
		}

		err := s.q.CreateScanTask(ctx, params)
		if err != nil {
			return fmt.Errorf("CreateScanTask insert error: %w", err)
		}
		return nil
	})
}

// GetTask retrieves a task's current state from the database. It reconstructs the domain
// Task object from stored data, including checkpoint information for recovery.
func (s *taskStore) GetTask(ctx context.Context, taskID uuid.UUID) (*scanning.Task, error) {
	dbAttrs := append(
		defaultDBAttributes,
		attribute.String("task_id", taskID.String()),
	)

	var domainTask *scanning.Task

	err := storage.ExecuteAndTrace(ctx, s.tracer, "postgres.get_task", dbAttrs, func(ctx context.Context) error {
		row, err := s.q.GetScanTask(ctx, pgtype.UUID{Bytes: taskID, Valid: true})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			return fmt.Errorf("GetScanTask query error: %w", err)
		}

		lastUpdateTime := time.Time{}
		if row.LastUpdateTime.Valid {
			lastUpdateTime = row.LastUpdateTime.Time
		}

		var checkpoint *scanning.Checkpoint
		if len(row.LastCheckpoint) > 0 {
			var cp scanning.Checkpoint
			if jerr := json.Unmarshal(row.LastCheckpoint, &cp); jerr == nil {
				checkpoint = &cp
			}
		}

		domainTask = scanning.ReconstructTask(
			row.TaskID.Bytes,
			row.JobID.Bytes,
			scanning.TaskStatus(row.Status),
			row.LastSequenceNum,
			row.StartTime.Time,
			lastUpdateTime,
			row.ItemsProcessed,
			row.ProgressDetails,
			checkpoint,
		)
		return nil
	})

	if err != nil {
		return nil, err
	}
	if domainTask == nil {
		return nil, pgx.ErrNoRows
	}
	return domainTask, nil
}

// UpdateTask persists changes to an existing task's state. It updates monitoring metrics
// and preserves checkpoint data for potential recovery scenarios.
func (s *taskStore) UpdateTask(ctx context.Context, task *scanning.Task) error {
	dbAttrs := append(
		defaultDBAttributes,
		attribute.String("task_id", task.GetTaskID().String()),
		attribute.String("status", string(task.GetStatus())),
	)

	return storage.ExecuteAndTrace(ctx, s.tracer, "postgres.update_task", dbAttrs, func(ctx context.Context) error {
		span := trace.SpanFromContext(ctx)

		var lastUpdateTime pgtype.Timestamptz
		if !task.GetLastUpdateTime().IsZero() {
			lastUpdateTime = pgtype.Timestamptz{Time: task.GetLastUpdateTime(), Valid: true}
			span.SetAttributes(attribute.String("last_update_time", lastUpdateTime.Time.String()))
		}

		var checkpointJSON []byte
		if task.LastCheckpoint() != nil {
			checkpointJSON, _ = json.Marshal(task.LastCheckpoint())
			span.SetAttributes(attribute.Bool("has_checkpoint", true))
		}

		sqlcStatus := db.ScanTaskStatus(task.GetStatus())

		params := db.UpdateScanTaskParams{
			TaskID:          pgtype.UUID{Bytes: task.GetTaskID(), Valid: true},
			Status:          sqlcStatus,
			LastSequenceNum: task.GetLastSequenceNum(),
			LastUpdateTime:  lastUpdateTime,
			ItemsProcessed:  task.GetItemsProcessed(),
			ProgressDetails: task.ProgressDetails(),
			LastCheckpoint:  checkpointJSON,
		}

		rowsAff, err := s.q.UpdateScanTask(ctx, params)
		if err != nil {
			return fmt.Errorf("UpdateScanTask error: %w", err)
		}
		if rowsAff == 0 {
			span.SetAttributes(attribute.Bool("update_task_no_rows_affected", true))
			span.RecordError(errors.New("task not found"))
			return fmt.Errorf("UpdateScanTask no rows affected")
		}

		return nil
	})
}

// ListTasksByJobAndStatus retrieves tasks associated with a job and matching a specific status.
// This enables monitoring of task groups and coordination of multi-task operations.
func (s *taskStore) ListTasksByJobAndStatus(
	ctx context.Context,
	jobID uuid.UUID,
	status scanning.TaskStatus,
) ([]*scanning.Task, error) {
	dbAttrs := append(
		defaultDBAttributes,
		attribute.String("job_id", jobID.String()),
		attribute.String("status", string(status)),
	)

	var results []*scanning.Task

	err := storage.ExecuteAndTrace(ctx, s.tracer, "postgres.list_tasks_by_job_and_status", dbAttrs, func(ctx context.Context) error {
		sqlcStatus := db.ScanTaskStatus(status)
		rows, err := s.q.ListScanTasksByJobAndStatus(ctx, db.ListScanTasksByJobAndStatusParams{
			JobID:  pgtype.UUID{Bytes: jobID, Valid: true},
			Status: sqlcStatus,
		})
		if err != nil {
			return fmt.Errorf("ListScanTasksByJobAndStatus error: %w", err)
		}

		for _, row := range rows {
			lastUpdateTime := time.Time{}
			if row.LastUpdateTime.Valid {
				lastUpdateTime = row.LastUpdateTime.Time
			}

			var checkpoint *scanning.Checkpoint
			if len(row.LastCheckpoint) > 0 {
				var cp scanning.Checkpoint
				if jerr := json.Unmarshal(row.LastCheckpoint, &cp); jerr == nil {
					checkpoint = &cp
				}
			}

			t := scanning.ReconstructTask(
				row.TaskID.Bytes,
				row.JobID.Bytes,
				scanning.TaskStatus(row.Status),
				row.LastSequenceNum,
				row.StartTime.Time,
				lastUpdateTime,
				row.ItemsProcessed,
				row.ProgressDetails,
				checkpoint,
			)
			results = append(results, t)
		}
		return nil
	})

	if err != nil {
		return nil, err
	}
	return results, nil
}
