package postgres

import (
	"context"
	"encoding/json"
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
	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
	"github.com/ahrav/gitleaks-armada/internal/infra/storage"
	"github.com/ahrav/gitleaks-armada/pkg/common/uuid"
)

// Ensure taskStore implements scanning.TaskRepository at compile time.
var _ scanning.TaskRepository = (*taskStore)(nil)

// taskStore implements scanning.TaskRepository using Postgres + sqlc queries.
// It provides persistent storage and retrieval of scan task state, enabling
// tracking of task progress and recovery from failures.
type taskStore struct {
	q      *db.Queries
	db     *pgxpool.Pool
	tracer trace.Tracer
}

// NewTaskStore creates a TaskRepository backed by PostgreSQL. It encapsulates database
// operations and telemetry for scan task management.
func NewTaskStore(pool *pgxpool.Pool, tracer trace.Tracer) *taskStore {
	return &taskStore{
		q:      db.New(pool),
		db:     pool,
		tracer: tracer,
	}
}

// CreateTask persists a new task's initial state in the database. It establishes
// the task's relationship to its parent job and initializes monitoring state.
func (s *taskStore) CreateTask(ctx context.Context, task *scanning.Task, controllerID string) error {
	dbAttrs := append(
		defaultDBAttributes,
		attribute.String("task_id", task.TaskID().String()),
		attribute.String("job_id", task.JobID().String()),
		attribute.String("resource_uri", task.ResourceURI()),
		attribute.String("status", string(task.Status())),
		attribute.String("controller_id", controllerID),
	)

	return storage.ExecuteAndTrace(ctx, s.tracer, "postgres.create_task", dbAttrs, func(ctx context.Context) error {
		params := db.CreateScanTaskParams{
			TaskID:            pgtype.UUID{Bytes: task.TaskID(), Valid: true},
			JobID:             pgtype.UUID{Bytes: task.JobID(), Valid: true},
			ResourceUri:       task.ResourceURI(),
			Status:            db.ScanTaskStatus(task.Status()),
			LastSequenceNum:   task.LastSequenceNum(),
			OwnerControllerID: controllerID,
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
				return scanning.ErrTaskNotFound
			}
			return fmt.Errorf("GetScanTask query error: %w", err)
		}

		var checkpoint *scanning.Checkpoint
		if len(row.LastCheckpoint) > 0 {
			var cp scanning.Checkpoint
			if jerr := json.Unmarshal(row.LastCheckpoint, &cp); jerr == nil {
				checkpoint = &cp
			}
		}

		var stallReason *scanning.StallReason
		if row.StallReason.Valid {
			r := scanning.StallReason(row.StallReason.ScanTaskStallReason)
			stallReason = &r
		}

		var pausedAt pgtype.Timestamptz
		if row.PausedAt.Valid {
			pausedAt = pgtype.Timestamptz{Time: row.PausedAt.Time, Valid: true}
		}

		var scannerID *uuid.UUID
		if row.ScannerID.Valid {
			scannerUUID := uuid.UUID(row.ScannerID.Bytes)
			scannerID = &scannerUUID
		}

		domainTask = scanning.ReconstructTask(
			row.TaskID.Bytes,
			row.JobID.Bytes,
			row.ResourceUri,
			scanning.TaskStatus(row.Status),
			row.LastSequenceNum,
			row.LastHeartbeatAt.Time,
			row.StartTime.Time,
			row.EndTime.Time,
			row.ItemsProcessed,
			row.ProgressDetails,
			checkpoint,
			stallReason,
			row.StalledAt.Time,
			pausedAt.Time,
			int(row.RecoveryAttempts),
			scannerID,
		)
		return nil
	})
	if err != nil {
		return nil, err
	}

	return domainTask, nil
}

// UpdateTask persists changes to an existing task's state. It updates monitoring metrics
// and preserves checkpoint data for potential recovery scenarios.
func (s *taskStore) UpdateTask(ctx context.Context, task *scanning.Task) error {
	dbAttrs := append(
		defaultDBAttributes,
		attribute.String("task_id", task.TaskID().String()),
		attribute.String("status", string(task.Status())),
		attribute.String("last_sequence_num", fmt.Sprintf("%d", task.LastSequenceNum())),
		attribute.String("items_processed", fmt.Sprintf("%d", task.ItemsProcessed())),
		attribute.String("stalled_at", task.StalledAt().String()),
		attribute.Int("recovery_attempts", task.RecoveryAttempts()),
	)

	return storage.ExecuteAndTrace(ctx, s.tracer, "postgres.update_task", dbAttrs, func(ctx context.Context) error {
		span := trace.SpanFromContext(ctx)

		var endTime pgtype.Timestamptz
		if !task.EndTime().IsZero() {
			endTime = pgtype.Timestamptz{Time: task.EndTime(), Valid: true}
			span.SetAttributes(attribute.String("end_time", endTime.Time.String()))
		}

		// TODO: I don't like this. We shouldn't have to set the start time on every update.
		var startTime pgtype.Timestamptz
		if !task.StartTime().IsZero() {
			startTime = pgtype.Timestamptz{Time: task.StartTime(), Valid: true}
			span.SetAttributes(attribute.String("start_time", startTime.Time.String()))
		}

		var checkpointJSON []byte
		if task.LastCheckpoint() != nil {
			checkpointJSON, _ = json.Marshal(task.LastCheckpoint())
			span.SetAttributes(attribute.Bool("has_checkpoint", true))
		}

		var stallReason db.NullScanTaskStallReason
		if task.StallReason() != nil {
			stallReason.Valid = true
			stallReason.ScanTaskStallReason = db.ScanTaskStallReason(*task.StallReason())
		}

		var scannerIDParam pgtype.UUID
		if task.ScannerID() != nil {
			scannerIDParam = pgtype.UUID{Bytes: *task.ScannerID(), Valid: true}
		} else {
			scannerIDParam = pgtype.UUID{Valid: false}
		}

		params := db.UpdateScanTaskParams{
			TaskID:           pgtype.UUID{Bytes: task.TaskID(), Valid: true},
			Status:           db.ScanTaskStatus(task.Status()),
			LastSequenceNum:  task.LastSequenceNum(),
			StartTime:        startTime,
			EndTime:          endTime,
			ItemsProcessed:   task.ItemsProcessed(),
			ProgressDetails:  task.ProgressDetails(),
			LastCheckpoint:   checkpointJSON,
			StallReason:      stallReason,
			StalledAt:        pgtype.Timestamptz{Time: task.StalledAt(), Valid: !task.StalledAt().IsZero()},
			PausedAt:         pgtype.Timestamptz{Time: task.PausedAt(), Valid: !task.PausedAt().IsZero()},
			RecoveryAttempts: int32(task.RecoveryAttempts()),
			ScannerID:        scannerIDParam,
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

// UpdateTaskScanner updates just the scanner_id for a task.
// This is used when a task is reassigned to a different scanner.
// TODO: Use this...
func (s *taskStore) UpdateTaskScanner(ctx context.Context, taskID uuid.UUID, scannerID *uuid.UUID) error {
	dbAttrs := append(
		defaultDBAttributes,
		attribute.String("task_id", taskID.String()),
	)

	if scannerID != nil {
		dbAttrs = append(dbAttrs, attribute.String("scanner_id", scannerID.String()))
	}

	return storage.ExecuteAndTrace(ctx, s.tracer, "postgres.update_task_scanner", dbAttrs, func(ctx context.Context) error {
		var scannerIDParam pgtype.UUID
		if scannerID != nil {
			scannerIDParam = pgtype.UUID{Bytes: *scannerID, Valid: true}
		} else {
			scannerIDParam = pgtype.UUID{Valid: false}
		}

		query := `
			UPDATE scan_tasks
			SET scanner_id = $1, updated_at = NOW()
			WHERE task_id = $2
		`
		result, err := s.db.Exec(ctx, query,
			scannerIDParam,
			pgtype.UUID{Bytes: taskID, Valid: true},
		)
		if err != nil {
			return fmt.Errorf("update task scanner error: %w", err)
		}

		if result.RowsAffected() == 0 {
			return scanning.ErrTaskNotFound
		}

		return nil
	})
}

// FindStaleTasks retrieves tasks that have not sent a heartbeat since the given cutoff time.
func (s *taskStore) FindStaleTasks(ctx context.Context, controllerID string, cutoff time.Time) ([]scanning.StaleTaskInfo, error) {
	dbAttrs := append(
		defaultDBAttributes,
		attribute.String("cutoff", cutoff.String()),
	)

	var tasks []scanning.StaleTaskInfo

	err := storage.ExecuteAndTrace(ctx, s.tracer, "postgres.find_stale_tasks", dbAttrs, func(ctx context.Context) error {
		span := trace.SpanFromContext(ctx)

		rows, err := s.q.FindStaleTasks(ctx, db.FindStaleTasksParams{
			OwnerControllerID: controllerID,
			LastHeartbeatAt:   pgtype.Timestamptz{Time: cutoff, Valid: true},
		})
		if err != nil {
			return fmt.Errorf("FindStaleTasks query error: %w", err)
		}
		span.SetAttributes(attribute.Int("num_tasks", len(rows)))

		for _, row := range rows {
			tasks = append(tasks, scanning.NewStaleTaskInfo(row.TaskID.Bytes, row.JobID.Bytes, controllerID))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return tasks, nil
}

// BatchUpdateHeartbeats updates the last_heartbeat_at and updated_at for a list of tasks.
func (s *taskStore) BatchUpdateHeartbeats(ctx context.Context, heartbeats map[uuid.UUID]time.Time) (int64, error) {
	dbAttrs := append(
		defaultDBAttributes,
		attribute.Int("num_tasks", len(heartbeats)),
	)

	values := make([]string, 0, len(heartbeats))
	args := make([]any, 0, len(heartbeats)*3)
	i := 1
	for taskID, heartbeatTime := range heartbeats {
		values = append(values, fmt.Sprintf("($%d::uuid, $%d::timestamptz, $%d::timestamptz)", i, i+1, i+2))
		args = append(args, taskID, heartbeatTime, time.Now().UTC())
		i += 3
	}

	if len(values) == 0 {
		return 0, nil
	}

	query := fmt.Sprintf(`
		UPDATE scan_tasks AS t
		SET
			last_heartbeat_at = v.heartbeat_at,
			updated_at = v.updated_at
		FROM (VALUES %s) AS v(task_id, heartbeat_at, updated_at)
		WHERE t.task_id = v.task_id
		  AND t.status = 'IN_PROGRESS'
	`, strings.Join(values, ","))

	var rowsAffected int64
	err := storage.ExecuteAndTrace(ctx, s.tracer, "postgres.batch_update_heartbeats", dbAttrs, func(ctx context.Context) error {
		result, err := s.db.Exec(ctx, query, args...)
		if err != nil {
			return fmt.Errorf("batch update heartbeats query error: %w", err)
		}
		rowsAffected = result.RowsAffected()
		return nil
	})

	return rowsAffected, err
}

// GetTasksToResume efficiently retrieves the minimal data needed for resuming tasks
// from a PAUSED job in a single database query. It joins scan_tasks with scan_jobs
// to get the source_type directly, eliminating the need for separate GetTaskSourceType queries.
func (s *taskStore) GetTasksToResume(ctx context.Context, jobID uuid.UUID) ([]scanning.ResumeTaskInfo, error) {
	dbAttrs := append(
		defaultDBAttributes,
		attribute.String("job_id", jobID.String()),
	)

	var results []scanning.ResumeTaskInfo

	err := storage.ExecuteAndTrace(ctx, s.tracer, "postgres.get_tasks_to_resume", dbAttrs, func(ctx context.Context) error {
		rows, err := s.q.GetTasksToResume(ctx, pgtype.UUID{Bytes: jobID, Valid: true})
		if err != nil {
			return fmt.Errorf("GetTasksToResume error: %w", err)
		}

		for _, row := range rows {
			var checkpoint *scanning.Checkpoint
			if len(row.LastCheckpoint) > 0 {
				var cp scanning.Checkpoint
				if jerr := json.Unmarshal(row.LastCheckpoint, &cp); jerr == nil {
					checkpoint = &cp
				}
			}

			sourceType := shared.ParseSourceType(row.SourceType)

			info := scanning.NewResumeTaskInfo(
				row.TaskID.Bytes,
				row.JobID.Bytes,
				sourceType,
				row.ResourceUri,
				row.LastSequenceNum,
				checkpoint,
			)
			results = append(results, info)
		}
		return nil
	})

	if err != nil {
		return nil, err
	}
	return results, nil
}
