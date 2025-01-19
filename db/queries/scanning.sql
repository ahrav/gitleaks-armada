-- Scanning Domain Queries

-- name: CreateJob :exec
INSERT INTO scan_jobs (
    job_id,
    status
) VALUES (
    $1, -- job_id UUID
    $2  -- status scan_job_status
);

-- name: UpdateJob :execrows
UPDATE scan_jobs
SET status = $2,
    start_time = $3,
    end_time = $4,
    total_tasks = $5,
    completed_tasks = $6,
    failed_tasks = $7,
    updated_at = NOW()
WHERE job_id = $1;

-- name: AssociateTarget :exec
INSERT INTO scan_job_targets (
    job_id,
    scan_target_id
) VALUES (
    $1, -- job_id UUID
    $2  -- scan_target_id UUID
);

-- name: BulkAssociateTargets :copyfrom
INSERT INTO scan_job_targets (
    job_id,
    scan_target_id
) VALUES ($1, $2);

-- name: GetJob :many
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
WHERE j.job_id = $1;

-- name: CreateScanTask :exec
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
);

-- name: GetScanTask :one
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
WHERE task_id = $1;

-- name: UpdateScanTask :execrows
UPDATE scan_tasks
SET
    status = $2,
    last_sequence_num = $3,
    last_update_time = $4,
    items_processed = $5,
    progress_details = $6,
    last_checkpoint = $7,
    updated_at = NOW()
WHERE task_id = $1;

-- name: ListScanTasksByJobAndStatus :many
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
ORDER BY t.created_at ASC;
