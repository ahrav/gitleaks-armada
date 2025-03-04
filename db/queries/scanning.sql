-- Scanning Domain Queries

-- name: CreateJob :exec
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

-- name: GetJob :one
SELECT
    j.job_id,
    j.status,
    j.source_type,
    j.config,
    j.start_time,
    j.end_time,
    j.updated_at
FROM scan_jobs j
WHERE j.job_id = $1;

-- name: GetJobSourceTypeConfig :one
SELECT
    source_type,
    config
FROM scan_jobs
WHERE job_id = $1;

-- name: CreateScanTask :exec
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
    paused_at,
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
    paused_at = $10,
    recovery_attempts = $11,
    start_time = $12,
    updated_at = NOW()
WHERE task_id = $1;

-- name: GetTasksToResume :many
SELECT
    t.task_id,
    t.job_id,
    j.source_type,
    t.resource_uri,
    t.last_sequence_num,
    t.last_checkpoint
FROM scan_tasks t
JOIN scan_jobs j ON t.job_id = j.job_id
WHERE t.job_id = $1
  AND t.status = 'PAUSED'
ORDER BY t.created_at ASC;

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
  AND j.status NOT IN ('PAUSED', 'PAUSING', 'CANCELLING', 'CANCELLED');

-- name: CreateJobMetrics :exec
INSERT INTO scan_job_metrics (
    job_id,
    created_at,
    updated_at
) VALUES (
    $1,
    NOW(),
    NOW()
);

-- name: IncrementTotalTasks :execrows
UPDATE scan_job_metrics
SET total_tasks = total_tasks + $2,
    updated_at = NOW()
WHERE job_id = $1;

-- name: GetJobMetrics :one
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
WHERE job_id = $1;

-- name: GetJobCheckpoints :many
SELECT partition_id, partition_offset
FROM job_metrics_checkpoints
WHERE job_id = $1;

-- name: UpdateJobMetricsAndCheckpoint :exec
-- Explicitly ignore total_tasks as it should not be updated
-- outside the enumeration process.
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
SELECT job_id FROM metrics_upsert;

-- name: GetJobWithMetrics :one
-- Retrieves a job with its metrics in a single query, including computed completion percentage
SELECT
    j.job_id,
    j.status,
    j.source_type,
    j.config,
    j.start_time,
    j.end_time,
    j.created_at,
    j.updated_at,
    m.total_tasks,
    m.pending_tasks,
    m.in_progress_tasks,
    m.completed_tasks,
    m.failed_tasks,
    m.stale_tasks,
    m.cancelled_tasks,
    m.paused_tasks,
    CASE
        WHEN m.total_tasks > 0 THEN (m.completed_tasks::float / m.total_tasks::float) * 100.0
        ELSE 0.0
    END AS completion_percentage
FROM scan_jobs j
LEFT JOIN scan_job_metrics m ON j.job_id = m.job_id
WHERE j.job_id = $1;

-- Scanner Group Queries

-- name: CreateScannerGroup :execrows
INSERT INTO scanner_groups (
    id,
    name,
    description
) VALUES (
    $1, -- id UUID
    $2, -- name VARCHAR(255)
    $3  -- description TEXT
) ON CONFLICT DO NOTHING;

-- Scanner Queries

-- name: CreateScanner :exec
INSERT INTO scanners (
    id,
    group_id,
    name,
    version,
    last_heartbeat,
    status,
    ip_address,
    hostname,
    metadata
) VALUES (
    $1, -- id UUID
    $2, -- group_id UUID
    $3, -- name VARCHAR(255)
    $4, -- version VARCHAR(50)
    $5, -- last_heartbeat TIMESTAMPTZ
    $6, -- status scanner_status
    $7, -- ip_address INET
    $8, -- hostname VARCHAR(255)
    $9  -- metadata JSONB
);
