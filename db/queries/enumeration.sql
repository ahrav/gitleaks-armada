-- Enumeration Domain Queries

-- ============================================
-- Checkpoints
-- ============================================
-- name: UpsertCheckpoint :one
INSERT INTO checkpoints (target_id, data, created_at, updated_at)
VALUES ($1, $2, NOW(), NOW())
ON CONFLICT (target_id) DO UPDATE
    SET data = EXCLUDED.data,
        updated_at = NOW()
RETURNING id;

-- name: GetCheckpoint :one
SELECT id, target_id, data, created_at, updated_at
FROM checkpoints
WHERE target_id = $1;

-- name: DeleteCheckpoint :exec
DELETE FROM checkpoints
WHERE target_id = $1;

-- name: GetCheckpointByID :one
SELECT id, target_id, data, created_at, updated_at
FROM checkpoints
WHERE id = $1;

-- ============================================
-- Enumeration States
-- ============================================
-- name: UpsertEnumerationSessionState :exec
INSERT INTO enumeration_session_states (
    session_id, source_type, config, last_checkpoint_id, status, failure_reason
) VALUES (
    $1, $2, $3, $4, $5, $6
)
ON CONFLICT (session_id) DO UPDATE
SET source_type = EXCLUDED.source_type,
    config = EXCLUDED.config,
    last_checkpoint_id = EXCLUDED.last_checkpoint_id,
    status = EXCLUDED.status,
    failure_reason = EXCLUDED.failure_reason,
    updated_at = NOW();

-- name: GetEnumerationSessionState :one
SELECT * FROM enumeration_session_states
WHERE session_id = $1;

-- name: DeleteEnumerationSessionState :exec
DELETE FROM enumeration_session_states
WHERE session_id = $1;

-- name: GetActiveEnumerationSessionStates :many
SELECT session_id, source_type, config, last_checkpoint_id, failure_reason,
       status, created_at, updated_at
FROM enumeration_session_states
WHERE status IN ('INITIALIZED', 'IN_PROGRESS')
ORDER BY created_at DESC;

-- name: ListEnumerationSessionStates :many
SELECT session_id, source_type, config, last_checkpoint_id, failure_reason,
       status, created_at, updated_at
FROM enumeration_session_states
ORDER BY created_at DESC
LIMIT $1;

-- ============================================
-- Enumeration Tasks
-- ============================================
-- name: CreateTask :exec
WITH core_task AS (
    INSERT INTO tasks (task_id, source_type)
    VALUES ($1, $2)
    RETURNING task_id
)
INSERT INTO enumeration_tasks (
    task_id,
    session_id,
    resource_uri,
    metadata
) VALUES (
    (SELECT task_id FROM core_task),
    $3,
    $4,
    $5
);

-- name: GetTaskByID :one
SELECT
    t.task_id,
    t.source_type,
    et.session_id,
    et.resource_uri,
    et.metadata,
    et.created_at,
    et.updated_at
FROM tasks t
JOIN enumeration_tasks et ON t.task_id = et.task_id
WHERE t.task_id = $1;

-- ============================================
-- Session State and Metrics operations
-- ============================================
-- name: UpsertSessionState :exec
INSERT INTO enumeration_session_states (
   session_id,
   source_type,
   config,
   status,
   failure_reason,
   last_checkpoint_id,
   started_at,
   completed_at,
   last_update
) VALUES (
   $1, $2, $3, $4, $5, $6, $7, $8, $9
)
ON CONFLICT (session_id) DO UPDATE SET
   status = EXCLUDED.status,
   failure_reason = EXCLUDED.failure_reason,
   last_checkpoint_id = EXCLUDED.last_checkpoint_id,
   completed_at = EXCLUDED.completed_at,
   last_update = EXCLUDED.last_update,
   updated_at = NOW();

-- name: UpsertSessionMetrics :exec
INSERT INTO enumeration_session_metrics (
   session_id,
   total_batches,
   failed_batches,
   items_found,
   items_processed
) VALUES (
   $1, $2, $3, $4, $5
)
ON CONFLICT (session_id) DO UPDATE SET
   total_batches = EXCLUDED.total_batches,
   failed_batches = EXCLUDED.failed_batches,
   items_found = EXCLUDED.items_found,
   items_processed = EXCLUDED.items_processed,
   updated_at = NOW();

-- name: GetSessionState :one
SELECT * FROM enumeration_session_states
WHERE session_id = $1;

-- name: GetSessionMetrics :one
SELECT * FROM enumeration_session_metrics
WHERE session_id = $1;

-- ============================================
-- Batch (Entity) operations
-- ============================================
-- name: UpsertBatch :exec
INSERT INTO enumeration_batches (
   batch_id,
   session_id,
   status,
   checkpoint_id,
   started_at,
   completed_at,
   last_update,
   items_processed,
   expected_items,
   error_details
) VALUES (
   $1, $2, $3, $4, $5, $6, $7, $8, $9, $10
)
ON CONFLICT (batch_id) DO UPDATE SET
   status = EXCLUDED.status,
   checkpoint_id = EXCLUDED.checkpoint_id,
   completed_at = EXCLUDED.completed_at,
   last_update = EXCLUDED.last_update,
   items_processed = EXCLUDED.items_processed,
   error_details = EXCLUDED.error_details,
   updated_at = NOW();

-- name: GetBatch :one
SELECT * FROM enumeration_batches
WHERE batch_id = $1;

-- name: GetBatchesForSession :many
SELECT *
FROM enumeration_batches
WHERE session_id = $1
ORDER BY started_at ASC;

-- ============================================
-- GitHub Repositories
-- ============================================

-- name: CreateGitHubRepo :one
INSERT INTO github_repositories (
    name,
    url,
    is_active,
    metadata,
    created_at,
    updated_at
) VALUES (
    $1, $2, $3, $4, $5, $6
)
RETURNING id;

-- name: UpdateGitHubRepo :execrows
UPDATE github_repositories
SET
    name = $2,
    url = $3,
    is_active = $4,
    metadata = $5,
    updated_at = $6
WHERE id = $1;

-- name: GetGitHubRepoByID :one
SELECT
    id,
    name,
    url,
    is_active,
    metadata,
    created_at,
    updated_at
FROM github_repositories
WHERE id = $1;

-- name: GetGitHubRepoByURL :one
SELECT
    id,
    name,
    url,
    is_active,
    metadata,
    created_at,
    updated_at
FROM github_repositories
WHERE url = $1;

-- name: ListGitHubRepos :many
SELECT
    id,
    name,
    url,
    is_active,
    metadata,
    created_at,
    updated_at
FROM github_repositories
ORDER BY created_at DESC
LIMIT $1 OFFSET $2;

-- ============================================
-- Scan Targets
-- ============================================

-- name: CreateScanTarget :one
INSERT INTO scan_targets (
    id,
    name,
    target_type,
    target_id,
    metadata,
    created_at,
    updated_at
) VALUES (
    $1, $2, $3, $4, $5, NOW(), NOW()
)
RETURNING id;

-- name: UpdateScanTarget :execrows
UPDATE scan_targets
SET
    name = $2,
    target_type = $3,
    target_id = $4,
    last_scan_time = $5,
    metadata = $6,
    updated_at = NOW()
WHERE id = $1;

-- name: GetScanTargetByID :one
SELECT
    id,
    name,
    target_type,
    target_id,
    last_scan_time,
    metadata,
    created_at,
    updated_at
FROM scan_targets
WHERE id = $1;

-- name: FindScanTarget :one
SELECT
    id,
    name,
    target_type,
    target_id,
    last_scan_time,
    metadata,
    created_at,
    updated_at
FROM scan_targets
WHERE target_type = $1 AND target_id = $2;

-- name: ListScanTargets :many
SELECT
    id,
    name,
    target_type,
    target_id,
    last_scan_time,
    metadata,
    created_at,
    updated_at
FROM scan_targets
ORDER BY created_at DESC
LIMIT $1 OFFSET $2;

-- name: UpdateScanTargetScanTime :execrows
UPDATE scan_targets
SET
    last_scan_time = $2,
    metadata = $3,
    updated_at = NOW()
WHERE id = $1;
