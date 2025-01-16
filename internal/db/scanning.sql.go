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
    last_sequence_num,
    start_time,
    last_update_time,
    items_processed,
    progress_details,
    last_checkpoint
) VALUES (
    $1, -- task_id UUID
    $2, -- job_id UUID
    $3, -- status TEXT (TaskStatus)
    $4, -- last_sequence_num BIGINT
    $5, -- start_time TIMESTAMPTZ
    $6, -- last_update_time TIMESTAMPTZ
    $7, -- items_processed BIGINT
    $8, -- progress_details JSONB
    $9 -- last_checkpoint JSONB
)
`

type CreateScanTaskParams struct {
	TaskID          pgtype.UUID
	JobID           pgtype.UUID
	Status          ScanTaskStatus
	LastSequenceNum int64
	StartTime       pgtype.Timestamptz
	LastUpdateTime  pgtype.Timestamptz
	ItemsProcessed  int64
	ProgressDetails []byte
	LastCheckpoint  []byte
}

func (q *Queries) CreateScanTask(ctx context.Context, arg CreateScanTaskParams) error {
	_, err := q.db.Exec(ctx, createScanTask,
		arg.TaskID,
		arg.JobID,
		arg.Status,
		arg.LastSequenceNum,
		arg.StartTime,
		arg.LastUpdateTime,
		arg.ItemsProcessed,
		arg.ProgressDetails,
		arg.LastCheckpoint,
	)
	return err
}

const getJob = `-- name: GetJob :many
SELECT
    j.job_id,
    j.status,
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

const getScanTask = `-- name: GetScanTask :one
SELECT
    task_id,
    job_id,
    status,
    last_sequence_num,
    start_time,
    last_update_time,
    items_processed,
    progress_details,
    last_checkpoint,
    created_at,
    updated_at
FROM scan_tasks
WHERE task_id = $1
`

func (q *Queries) GetScanTask(ctx context.Context, taskID pgtype.UUID) (ScanTask, error) {
	row := q.db.QueryRow(ctx, getScanTask, taskID)
	var i ScanTask
	err := row.Scan(
		&i.TaskID,
		&i.JobID,
		&i.Status,
		&i.LastSequenceNum,
		&i.StartTime,
		&i.LastUpdateTime,
		&i.ItemsProcessed,
		&i.ProgressDetails,
		&i.LastCheckpoint,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const listScanTasksByJobAndStatus = `-- name: ListScanTasksByJobAndStatus :many
SELECT
    t.task_id,
    t.job_id,
    t.status,
    t.last_sequence_num,
    t.start_time,
    t.last_update_time,
    t.items_processed,
    t.progress_details,
    t.last_checkpoint,
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

func (q *Queries) ListScanTasksByJobAndStatus(ctx context.Context, arg ListScanTasksByJobAndStatusParams) ([]ScanTask, error) {
	rows, err := q.db.Query(ctx, listScanTasksByJobAndStatus, arg.JobID, arg.Status)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []ScanTask
	for rows.Next() {
		var i ScanTask
		if err := rows.Scan(
			&i.TaskID,
			&i.JobID,
			&i.Status,
			&i.LastSequenceNum,
			&i.StartTime,
			&i.LastUpdateTime,
			&i.ItemsProcessed,
			&i.ProgressDetails,
			&i.LastCheckpoint,
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

const updateScanTask = `-- name: UpdateScanTask :execrows
UPDATE scan_tasks
SET
    status = $2,
    last_sequence_num = $3,
    last_update_time = $4,
    items_processed = $5,
    progress_details = $6,
    last_checkpoint = $7,
    updated_at = NOW()
WHERE task_id = $1
`

type UpdateScanTaskParams struct {
	TaskID          pgtype.UUID
	Status          ScanTaskStatus
	LastSequenceNum int64
	LastUpdateTime  pgtype.Timestamptz
	ItemsProcessed  int64
	ProgressDetails []byte
	LastCheckpoint  []byte
}

func (q *Queries) UpdateScanTask(ctx context.Context, arg UpdateScanTaskParams) (int64, error) {
	result, err := q.db.Exec(ctx, updateScanTask,
		arg.TaskID,
		arg.Status,
		arg.LastSequenceNum,
		arg.LastUpdateTime,
		arg.ItemsProcessed,
		arg.ProgressDetails,
		arg.LastCheckpoint,
	)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected(), nil
}
