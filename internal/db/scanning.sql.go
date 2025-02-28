// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.27.0
// source: scanning.sql

package db

import (
	"context"

	"github.com/jackc/pgx/v5/pgtype"
)

const associateTarget = `-- name: AssociateTarget :exec
INSERT INTO scan_job_targets (
    job_id,
    scan_target_id
) VALUES (
    $1, -- job_id UUID
    $2  -- scan_target_id UUID
)
`

type AssociateTargetParams struct {
	JobID        pgtype.UUID
	ScanTargetID pgtype.UUID
}

func (q *Queries) AssociateTarget(ctx context.Context, arg AssociateTargetParams) error {
	_, err := q.db.Exec(ctx, associateTarget, arg.JobID, arg.ScanTargetID)
	return err
}

type BulkAssociateTargetsParams struct {
	JobID        pgtype.UUID
	ScanTargetID pgtype.UUID
}

const createBaseTask = `-- name: CreateBaseTask :exec
INSERT INTO tasks (task_id, source_type)
VALUES ($1, $2)
`

type CreateBaseTaskParams struct {
	TaskID     pgtype.UUID
	SourceType string
}

func (q *Queries) CreateBaseTask(ctx context.Context, arg CreateBaseTaskParams) error {
	_, err := q.db.Exec(ctx, createBaseTask, arg.TaskID, arg.SourceType)
	return err
}

const createJob = `-- name: CreateJob :exec

INSERT INTO scan_jobs (
    job_id,
    status,
    source_type,
    config
) VALUES (
    $1, -- job_id UUID
    $2, -- status scan_job_status
    $3, -- source_type VARCHAR
    $4  -- config JSONB
)
`

type CreateJobParams struct {
	JobID      pgtype.UUID
	Status     ScanJobStatus
	SourceType string
	Config     []byte
}

// Scanning Domain Queries
func (q *Queries) CreateJob(ctx context.Context, arg CreateJobParams) error {
	_, err := q.db.Exec(ctx, createJob,
		arg.JobID,
		arg.Status,
		arg.SourceType,
		arg.Config,
	)
	return err
}

const createJobMetrics = `-- name: CreateJobMetrics :exec
INSERT INTO scan_job_metrics (
    job_id,
    created_at,
    updated_at
) VALUES (
    $1,
    NOW(),
    NOW()
)
`

func (q *Queries) CreateJobMetrics(ctx context.Context, jobID pgtype.UUID) error {
	_, err := q.db.Exec(ctx, createJobMetrics, jobID)
	return err
}

const createScanTask = `-- name: CreateScanTask :exec
INSERT INTO scan_tasks (
    task_id,
    job_id,
    owner_controller_id,
    status,
    resource_uri,
    last_sequence_num
) VALUES (
    $1, -- task_id UUID
    $2, -- job_id UUID
    $3, -- owner_controller_id VARCHAR(255)
    $4, -- status TEXT (TaskStatus)
    $5, -- resource_uri VARCHAR(1024)
    $6  -- last_sequence_num BIGINT
)
`

type CreateScanTaskParams struct {
	TaskID            pgtype.UUID
	JobID             pgtype.UUID
	OwnerControllerID string
	Status            ScanTaskStatus
	ResourceUri       string
	LastSequenceNum   int64
}

func (q *Queries) CreateScanTask(ctx context.Context, arg CreateScanTaskParams) error {
	_, err := q.db.Exec(ctx, createScanTask,
		arg.TaskID,
		arg.JobID,
		arg.OwnerControllerID,
		arg.Status,
		arg.ResourceUri,
		arg.LastSequenceNum,
	)
	return err
}

const findStaleTasks = `-- name: FindStaleTasks :many
SELECT
    t.task_id,
    t.job_id,
    t.owner_controller_id,
    t.status,
    t.resource_uri,
    t.last_sequence_num,
    t.start_time,
    t.end_time,
    t.items_processed,
    t.progress_details,
    t.last_checkpoint,
    t.stall_reason,
    t.stalled_at,
    t.paused_at,
    t.recovery_attempts,
    t.last_heartbeat_at,
    t.created_at,
    t.updated_at
FROM scan_tasks t
JOIN scan_jobs j ON t.job_id = j.job_id
WHERE t.owner_controller_id = $1
  AND t.status = 'IN_PROGRESS'
  AND t.last_heartbeat_at < $2
  AND j.status NOT IN ('PAUSED', 'PAUSING', 'CANCELLING', 'CANCELLED')
`

type FindStaleTasksParams struct {
	OwnerControllerID string
	LastHeartbeatAt   pgtype.Timestamptz
}

type FindStaleTasksRow struct {
	TaskID            pgtype.UUID
	JobID             pgtype.UUID
	OwnerControllerID string
	Status            ScanTaskStatus
	ResourceUri       string
	LastSequenceNum   int64
	StartTime         pgtype.Timestamptz
	EndTime           pgtype.Timestamptz
	ItemsProcessed    int64
	ProgressDetails   []byte
	LastCheckpoint    []byte
	StallReason       NullScanTaskStallReason
	StalledAt         pgtype.Timestamptz
	PausedAt          pgtype.Timestamptz
	RecoveryAttempts  int32
	LastHeartbeatAt   pgtype.Timestamptz
	CreatedAt         pgtype.Timestamptz
	UpdatedAt         pgtype.Timestamptz
}

func (q *Queries) FindStaleTasks(ctx context.Context, arg FindStaleTasksParams) ([]FindStaleTasksRow, error) {
	rows, err := q.db.Query(ctx, findStaleTasks, arg.OwnerControllerID, arg.LastHeartbeatAt)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []FindStaleTasksRow
	for rows.Next() {
		var i FindStaleTasksRow
		if err := rows.Scan(
			&i.TaskID,
			&i.JobID,
			&i.OwnerControllerID,
			&i.Status,
			&i.ResourceUri,
			&i.LastSequenceNum,
			&i.StartTime,
			&i.EndTime,
			&i.ItemsProcessed,
			&i.ProgressDetails,
			&i.LastCheckpoint,
			&i.StallReason,
			&i.StalledAt,
			&i.PausedAt,
			&i.RecoveryAttempts,
			&i.LastHeartbeatAt,
			&i.CreatedAt,
			&i.UpdatedAt,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const getJob = `-- name: GetJob :many
SELECT
    j.job_id,
    j.status,
    j.source_type,
    j.config,
    j.start_time,
    j.end_time,
    j.updated_at,
    t.scan_target_id
FROM scan_jobs j
LEFT JOIN scan_job_targets t ON j.job_id = t.job_id
WHERE j.job_id = $1
`

type GetJobRow struct {
	JobID        pgtype.UUID
	Status       ScanJobStatus
	SourceType   string
	Config       []byte
	StartTime    pgtype.Timestamptz
	EndTime      pgtype.Timestamptz
	UpdatedAt    pgtype.Timestamptz
	ScanTargetID pgtype.UUID
}

func (q *Queries) GetJob(ctx context.Context, jobID pgtype.UUID) ([]GetJobRow, error) {
	rows, err := q.db.Query(ctx, getJob, jobID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []GetJobRow
	for rows.Next() {
		var i GetJobRow
		if err := rows.Scan(
			&i.JobID,
			&i.Status,
			&i.SourceType,
			&i.Config,
			&i.StartTime,
			&i.EndTime,
			&i.UpdatedAt,
			&i.ScanTargetID,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const getJobCheckpoints = `-- name: GetJobCheckpoints :many
SELECT partition_id, partition_offset
FROM job_metrics_checkpoints
WHERE job_id = $1
`

type GetJobCheckpointsRow struct {
	PartitionID     int32
	PartitionOffset int64
}

func (q *Queries) GetJobCheckpoints(ctx context.Context, jobID pgtype.UUID) ([]GetJobCheckpointsRow, error) {
	rows, err := q.db.Query(ctx, getJobCheckpoints, jobID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []GetJobCheckpointsRow
	for rows.Next() {
		var i GetJobCheckpointsRow
		if err := rows.Scan(&i.PartitionID, &i.PartitionOffset); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const getJobMetrics = `-- name: GetJobMetrics :one
SELECT
    total_tasks,
    pending_tasks,
    in_progress_tasks,
    completed_tasks,
    failed_tasks,
    stale_tasks,
    cancelled_tasks,
    paused_tasks
FROM scan_job_metrics
WHERE job_id = $1
`

type GetJobMetricsRow struct {
	TotalTasks      int32
	PendingTasks    int32
	InProgressTasks int32
	CompletedTasks  int32
	FailedTasks     int32
	StaleTasks      int32
	CancelledTasks  int32
	PausedTasks     int32
}

func (q *Queries) GetJobMetrics(ctx context.Context, jobID pgtype.UUID) (GetJobMetricsRow, error) {
	row := q.db.QueryRow(ctx, getJobMetrics, jobID)
	var i GetJobMetricsRow
	err := row.Scan(
		&i.TotalTasks,
		&i.PendingTasks,
		&i.InProgressTasks,
		&i.CompletedTasks,
		&i.FailedTasks,
		&i.StaleTasks,
		&i.CancelledTasks,
		&i.PausedTasks,
	)
	return i, err
}

const getScanTask = `-- name: GetScanTask :one
SELECT
    task_id,
    job_id,
    status,
    resource_uri,
    last_sequence_num,
    start_time,
    end_time,
    items_processed,
    progress_details,
    last_checkpoint,
    stall_reason,
    last_heartbeat_at,
    stalled_at,
    paused_at,
    recovery_attempts,
    created_at,
    updated_at
FROM scan_tasks
WHERE task_id = $1
`

type GetScanTaskRow struct {
	TaskID           pgtype.UUID
	JobID            pgtype.UUID
	Status           ScanTaskStatus
	ResourceUri      string
	LastSequenceNum  int64
	StartTime        pgtype.Timestamptz
	EndTime          pgtype.Timestamptz
	ItemsProcessed   int64
	ProgressDetails  []byte
	LastCheckpoint   []byte
	StallReason      NullScanTaskStallReason
	LastHeartbeatAt  pgtype.Timestamptz
	StalledAt        pgtype.Timestamptz
	PausedAt         pgtype.Timestamptz
	RecoveryAttempts int32
	CreatedAt        pgtype.Timestamptz
	UpdatedAt        pgtype.Timestamptz
}

func (q *Queries) GetScanTask(ctx context.Context, taskID pgtype.UUID) (GetScanTaskRow, error) {
	row := q.db.QueryRow(ctx, getScanTask, taskID)
	var i GetScanTaskRow
	err := row.Scan(
		&i.TaskID,
		&i.JobID,
		&i.Status,
		&i.ResourceUri,
		&i.LastSequenceNum,
		&i.StartTime,
		&i.EndTime,
		&i.ItemsProcessed,
		&i.ProgressDetails,
		&i.LastCheckpoint,
		&i.StallReason,
		&i.LastHeartbeatAt,
		&i.StalledAt,
		&i.PausedAt,
		&i.RecoveryAttempts,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const getTaskSourceType = `-- name: GetTaskSourceType :one
SELECT source_type FROM tasks WHERE task_id = $1
`

func (q *Queries) GetTaskSourceType(ctx context.Context, taskID pgtype.UUID) (string, error) {
	row := q.db.QueryRow(ctx, getTaskSourceType, taskID)
	var source_type string
	err := row.Scan(&source_type)
	return source_type, err
}

const incrementTotalTasks = `-- name: IncrementTotalTasks :execrows
UPDATE scan_job_metrics
SET total_tasks = total_tasks + $2,
    updated_at = NOW()
WHERE job_id = $1
`

type IncrementTotalTasksParams struct {
	JobID      pgtype.UUID
	TotalTasks int32
}

func (q *Queries) IncrementTotalTasks(ctx context.Context, arg IncrementTotalTasksParams) (int64, error) {
	result, err := q.db.Exec(ctx, incrementTotalTasks, arg.JobID, arg.TotalTasks)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected(), nil
}

const listScanTasksByJobAndStatus = `-- name: ListScanTasksByJobAndStatus :many
SELECT
    t.task_id,
    t.job_id,
    t.status,
    t.resource_uri,
    t.last_sequence_num,
    t.start_time,
    t.end_time,
    t.items_processed,
    t.progress_details,
    t.last_checkpoint,
    t.stall_reason,
    t.stalled_at,
    t.paused_at,
    t.recovery_attempts,
    t.last_heartbeat_at,
    t.created_at,
    t.updated_at
FROM scan_tasks t
WHERE t.job_id = $1
  AND t.status = $2
ORDER BY t.created_at ASC
`

type ListScanTasksByJobAndStatusParams struct {
	JobID  pgtype.UUID
	Status ScanTaskStatus
}

type ListScanTasksByJobAndStatusRow struct {
	TaskID           pgtype.UUID
	JobID            pgtype.UUID
	Status           ScanTaskStatus
	ResourceUri      string
	LastSequenceNum  int64
	StartTime        pgtype.Timestamptz
	EndTime          pgtype.Timestamptz
	ItemsProcessed   int64
	ProgressDetails  []byte
	LastCheckpoint   []byte
	StallReason      NullScanTaskStallReason
	StalledAt        pgtype.Timestamptz
	PausedAt         pgtype.Timestamptz
	RecoveryAttempts int32
	LastHeartbeatAt  pgtype.Timestamptz
	CreatedAt        pgtype.Timestamptz
	UpdatedAt        pgtype.Timestamptz
}

func (q *Queries) ListScanTasksByJobAndStatus(ctx context.Context, arg ListScanTasksByJobAndStatusParams) ([]ListScanTasksByJobAndStatusRow, error) {
	rows, err := q.db.Query(ctx, listScanTasksByJobAndStatus, arg.JobID, arg.Status)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []ListScanTasksByJobAndStatusRow
	for rows.Next() {
		var i ListScanTasksByJobAndStatusRow
		if err := rows.Scan(
			&i.TaskID,
			&i.JobID,
			&i.Status,
			&i.ResourceUri,
			&i.LastSequenceNum,
			&i.StartTime,
			&i.EndTime,
			&i.ItemsProcessed,
			&i.ProgressDetails,
			&i.LastCheckpoint,
			&i.StallReason,
			&i.StalledAt,
			&i.PausedAt,
			&i.RecoveryAttempts,
			&i.LastHeartbeatAt,
			&i.CreatedAt,
			&i.UpdatedAt,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const updateJob = `-- name: UpdateJob :execrows
UPDATE scan_jobs
SET status = $2,
    start_time = $3,
    end_time = $4,
    updated_at = NOW()
WHERE job_id = $1
`

type UpdateJobParams struct {
	JobID     pgtype.UUID
	Status    ScanJobStatus
	StartTime pgtype.Timestamptz
	EndTime   pgtype.Timestamptz
}

func (q *Queries) UpdateJob(ctx context.Context, arg UpdateJobParams) (int64, error) {
	result, err := q.db.Exec(ctx, updateJob,
		arg.JobID,
		arg.Status,
		arg.StartTime,
		arg.EndTime,
	)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected(), nil
}

const updateJobMetricsAndCheckpoint = `-- name: UpdateJobMetricsAndCheckpoint :exec
WITH checkpoint_update AS (
    INSERT INTO job_metrics_checkpoints (
        job_id,
        partition_id,
        partition_offset,
        last_processed_at
    ) VALUES (
        $1, $2, $3, NOW()
    )
    ON CONFLICT (job_id, partition_id, partition_offset)
    DO UPDATE SET
        partition_id = EXCLUDED.partition_id,
        partition_offset = EXCLUDED.partition_offset,
        last_processed_at = NOW()
),
metrics_upsert AS (
    INSERT INTO scan_job_metrics (
        job_id,
        pending_tasks,
        in_progress_tasks,
        completed_tasks,
        failed_tasks,
        stale_tasks,
        cancelled_tasks,
        paused_tasks,
        created_at,
        updated_at
    ) VALUES (
        $1, $4, $5, $6, $7, $8, $9, $10, NOW(), NOW()
    )
    ON CONFLICT (job_id)
    DO UPDATE SET
        pending_tasks = EXCLUDED.pending_tasks,
        in_progress_tasks = EXCLUDED.in_progress_tasks,
        completed_tasks = EXCLUDED.completed_tasks,
        failed_tasks = EXCLUDED.failed_tasks,
        stale_tasks = EXCLUDED.stale_tasks,
        cancelled_tasks = EXCLUDED.cancelled_tasks,
        paused_tasks = EXCLUDED.paused_tasks,
        updated_at = NOW()
    RETURNING job_id
)
SELECT job_id FROM metrics_upsert
`

type UpdateJobMetricsAndCheckpointParams struct {
	JobID           pgtype.UUID
	PartitionID     int32
	PartitionOffset int64
	PendingTasks    int32
	InProgressTasks int32
	CompletedTasks  int32
	FailedTasks     int32
	StaleTasks      int32
	CancelledTasks  int32
	PausedTasks     int32
}

// Explicitly ignore total_tasks as it should not be updated
// outside the enumeration process.
func (q *Queries) UpdateJobMetricsAndCheckpoint(ctx context.Context, arg UpdateJobMetricsAndCheckpointParams) error {
	_, err := q.db.Exec(ctx, updateJobMetricsAndCheckpoint,
		arg.JobID,
		arg.PartitionID,
		arg.PartitionOffset,
		arg.PendingTasks,
		arg.InProgressTasks,
		arg.CompletedTasks,
		arg.FailedTasks,
		arg.StaleTasks,
		arg.CancelledTasks,
		arg.PausedTasks,
	)
	return err
}

const updateScanTask = `-- name: UpdateScanTask :execrows
UPDATE scan_tasks
SET
    status = $2,
    last_sequence_num = $3,
    end_time = $4,
    items_processed = $5,
    progress_details = $6,
    last_checkpoint = $7,
    stall_reason = $8,
    stalled_at = $9,
    paused_at = $10,
    recovery_attempts = $11,
    start_time = $12,
    updated_at = NOW()
WHERE task_id = $1
`

type UpdateScanTaskParams struct {
	TaskID           pgtype.UUID
	Status           ScanTaskStatus
	LastSequenceNum  int64
	EndTime          pgtype.Timestamptz
	ItemsProcessed   int64
	ProgressDetails  []byte
	LastCheckpoint   []byte
	StallReason      NullScanTaskStallReason
	StalledAt        pgtype.Timestamptz
	PausedAt         pgtype.Timestamptz
	RecoveryAttempts int32
	StartTime        pgtype.Timestamptz
}

func (q *Queries) UpdateScanTask(ctx context.Context, arg UpdateScanTaskParams) (int64, error) {
	result, err := q.db.Exec(ctx, updateScanTask,
		arg.TaskID,
		arg.Status,
		arg.LastSequenceNum,
		arg.EndTime,
		arg.ItemsProcessed,
		arg.ProgressDetails,
		arg.LastCheckpoint,
		arg.StallReason,
		arg.StalledAt,
		arg.PausedAt,
		arg.RecoveryAttempts,
		arg.StartTime,
	)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected(), nil
}
