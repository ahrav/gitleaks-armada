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
    t.scan_target_id
FROM scan_jobs j
LEFT JOIN scan_job_targets t ON j.job_id = t.job_id
WHERE j.job_id = $1;

-- name: CreateScanTask :exec
INSERT INTO scan_tasks (
    task_id,
    job_id,
    owner_controller_id,
    status,
    resource_uri,
    last_sequence_num,
    start_time
) VALUES (
    $1, -- task_id UUID
    $2, -- job_id UUID
    $3, -- owner_controller_id VARCHAR(255)
    $4, -- status TEXT (TaskStatus)
    $5, -- resource_uri VARCHAR(1024)
    $6, -- last_sequence_num BIGINT
    $7 -- start_time TIMESTAMPTZ
);

-- name: GetScanTask :one
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
    recovery_attempts,
    created_at,
    updated_at
FROM scan_tasks
WHERE task_id = $1;

-- name: UpdateScanTask :execrows
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
WHERE task_id = $1;

-- name: ListScanTasksByJobAndStatus :many
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
    t.last_heartbeat_at,
    t.created_at,
    t.updated_at
FROM scan_tasks t
WHERE t.job_id = $1
  AND t.status = $2
ORDER BY t.created_at ASC;

-- name: GetTaskSourceType :one
SELECT source_type FROM tasks WHERE task_id = $1;

-- name: CreateBaseTask :exec
INSERT INTO tasks (task_id, source_type)
VALUES ($1, $2);

-- name: FindStaleTasks :many
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
    t.recovery_attempts,
    t.last_heartbeat_at,
    t.created_at,
    t.updated_at
FROM scan_tasks t
WHERE t.owner_controller_id = $1
  AND t.status = 'IN_PROGRESS'
  AND t.last_heartbeat_at < $2;

-- name: GetJobMetrics :one
SELECT
    total_tasks,
    pending_tasks,
    in_progress_tasks,
    completed_tasks,
    failed_tasks,
    stale_tasks
FROM scan_job_metrics
WHERE job_id = $1;

-- name: GetJobCheckpoints :many
SELECT partition_id, partition_offset
FROM job_metrics_checkpoints
WHERE job_id = $1;

-- name: UpdateJobMetricsAndCheckpoint :exec
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
        total_tasks,
        pending_tasks,
        in_progress_tasks,
        completed_tasks,
        failed_tasks,
        stale_tasks,
        created_at,
        updated_at
    ) VALUES (
        $1, $4, $5, $6, $7, $8, $9, NOW(), NOW()
    )
    ON CONFLICT (job_id)
    DO UPDATE SET
        total_tasks = EXCLUDED.total_tasks,
        pending_tasks = EXCLUDED.pending_tasks,
        in_progress_tasks = EXCLUDED.in_progress_tasks,
        completed_tasks = EXCLUDED.completed_tasks,
        failed_tasks = EXCLUDED.failed_tasks,
        stale_tasks = EXCLUDED.stale_tasks,
        updated_at = NOW()
    RETURNING job_id
)
SELECT job_id FROM metrics_upsert;
