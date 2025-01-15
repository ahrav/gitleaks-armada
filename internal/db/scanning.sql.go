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
