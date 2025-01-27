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
    status
) VALUES (
    $1, -- job_id UUID
    $2  -- status scan_job_status
)
`

type CreateJobParams struct {
	JobID  pgtype.UUID
	Status ScanJobStatus
}

// Scanning Domain Queries
func (q *Queries) CreateJob(ctx context.Context, arg CreateJobParams) error {
	_, err := q.db.Exec(ctx, createJob, arg.JobID, arg.Status)
	return err
}

const createScanTask = `-- name: CreateScanTask :exec
INSERT INTO scan_tasks (
    task_id,
    job_id,
    status,
    resource_uri,
    last_sequence_num,
    start_time
) VALUES (
    $1, -- task_id UUID
    $2, -- job_id UUID
    $3, -- status TEXT (TaskStatus)
    $4, -- resource_uri VARCHAR(1024)
    $5, -- last_sequence_num BIGINT
    $6 -- start_time TIMESTAMPTZ
)
`

type CreateScanTaskParams struct {
	TaskID          pgtype.UUID
	JobID           pgtype.UUID
	Status          ScanTaskStatus
	ResourceUri     string
	LastSequenceNum int64
	StartTime       pgtype.Timestamptz
}

func (q *Queries) CreateScanTask(ctx context.Context, arg CreateScanTaskParams) error {
	_, err := q.db.Exec(ctx, createScanTask,
		arg.TaskID,
		arg.JobID,
		arg.Status,
		arg.ResourceUri,
		arg.LastSequenceNum,
		arg.StartTime,
	)
	return err
}

const findStaleTasks = `-- name: FindStaleTasks :many
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
    t.recovery_attempts,
    t.created_at,
    t.updated_at
FROM scan_tasks t
WHERE t.status = 'IN_PROGRESS'
  AND (t.last_heartbeat_at IS NULL OR t.last_heartbeat_at < $1)
`

type FindStaleTasksRow struct {
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
	RecoveryAttempts int32
	CreatedAt        pgtype.Timestamptz
	UpdatedAt        pgtype.Timestamptz
}

func (q *Queries) FindStaleTasks(ctx context.Context, lastHeartbeatAt pgtype.Timestamptz) ([]FindStaleTasksRow, error) {
	rows, err := q.db.Query(ctx, findStaleTasks, lastHeartbeatAt)
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
			&i.RecoveryAttempts,
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
    j.start_time,
    j.end_time,
    j.updated_at,
    j.total_tasks,
    j.completed_tasks,
    j.failed_tasks,
    t.scan_target_id
FROM scan_jobs j
LEFT JOIN scan_job_targets t ON j.job_id = t.job_id
WHERE j.job_id = $1
`

type GetJobRow struct {
	JobID          pgtype.UUID
	Status         ScanJobStatus
	StartTime      pgtype.Timestamptz
	EndTime        pgtype.Timestamptz
	UpdatedAt      pgtype.Timestamptz
	TotalTasks     int32
	CompletedTasks int32
	FailedTasks    int32
	ScanTargetID   pgtype.UUID
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
			&i.StartTime,
			&i.EndTime,
			&i.UpdatedAt,
			&i.TotalTasks,
			&i.CompletedTasks,
			&i.FailedTasks,
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
    stalled_at,
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
	StalledAt        pgtype.Timestamptz
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
		&i.StalledAt,
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
    t.recovery_attempts,
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
	RecoveryAttempts int32
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
			&i.RecoveryAttempts,
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
    total_tasks = $5,
    completed_tasks = $6,
    failed_tasks = $7,
    updated_at = NOW()
WHERE job_id = $1
`

type UpdateJobParams struct {
	JobID          pgtype.UUID
	Status         ScanJobStatus
	StartTime      pgtype.Timestamptz
	EndTime        pgtype.Timestamptz
	TotalTasks     int32
	CompletedTasks int32
	FailedTasks    int32
}

func (q *Queries) UpdateJob(ctx context.Context, arg UpdateJobParams) (int64, error) {
	result, err := q.db.Exec(ctx, updateJob,
		arg.JobID,
		arg.Status,
		arg.StartTime,
		arg.EndTime,
		arg.TotalTasks,
		arg.CompletedTasks,
		arg.FailedTasks,
	)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected(), nil
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
    recovery_attempts = $10,
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
	RecoveryAttempts int32
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
		arg.RecoveryAttempts,
	)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected(), nil
}
