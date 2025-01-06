-- queries.sql

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
SELECT id, session_id, source_type, config, last_checkpoint_id, failure_reason,
       status, created_at, updated_at
FROM enumeration_session_states
WHERE status IN ('INITIALIZED', 'IN_PROGRESS')
ORDER BY created_at DESC;

-- name: ListEnumerationSessionStates :many
SELECT id, session_id, source_type, config, last_checkpoint_id, failure_reason,
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
-- Progress Tracking
-- ============================================
-- name: UpsertEnumerationProgress :exec
INSERT INTO enumeration_progress (
    session_id, started_at, items_found, items_processed, failed_batches, total_batches
) VALUES (
    $1, $2, $3, $4, $5, $6
)
ON CONFLICT (session_id) DO UPDATE SET
    items_found = EXCLUDED.items_found,
    items_processed = EXCLUDED.items_processed,
    failed_batches = EXCLUDED.failed_batches,
    total_batches = EXCLUDED.total_batches,
    updated_at = NOW();

-- name: GetEnumerationProgressForSession :one
SELECT * FROM enumeration_progress
WHERE session_id = $1;

-- name: GetEnumerationBatchProgressForSession :many
SELECT * FROM enumeration_batch_progress
WHERE session_id = $1
ORDER BY started_at ASC;

-- name: UpsertEnumerationBatchProgress :one
INSERT INTO enumeration_batch_progress (
    batch_id, session_id, status, started_at, completed_at,
    items_processed, error_details, checkpoint_id
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8
)
ON CONFLICT (batch_id) DO UPDATE SET
    status = EXCLUDED.status,
    completed_at = EXCLUDED.completed_at,
    items_processed = EXCLUDED.items_processed,
    error_details = EXCLUDED.error_details,
    checkpoint_id = EXCLUDED.checkpoint_id,
    updated_at = NOW()
RETURNING id;

-- ============================================
-- Rules
-- ============================================
-- name: UpsertRule :one
INSERT INTO rules (
    rule_id, description, entropy, secret_group, regex, path, tags, keywords
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8
)
ON CONFLICT (rule_id) DO UPDATE
SET description = EXCLUDED.description,
    entropy = EXCLUDED.entropy,
    secret_group = EXCLUDED.secret_group,
    regex = EXCLUDED.regex,
    path = EXCLUDED.path,
    tags = EXCLUDED.tags,
    keywords = EXCLUDED.keywords,
    updated_at = NOW()
RETURNING id;

-- name: BulkInsertRules :copyfrom
INSERT INTO rules (
    rule_id, description, entropy, secret_group, regex, path, tags, keywords
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8);

-- ============================================
-- Allowlists
-- ============================================
-- name: UpsertAllowlist :one
INSERT INTO allowlists (
    rule_id, description, match_condition, regex_target
) VALUES (
    $1, $2, $3, $4
)
ON CONFLICT (rule_id, match_condition, regex_target) DO UPDATE
SET description = EXCLUDED.description,
    updated_at = NOW()
RETURNING id;

-- name: BulkInsertAllowlists :copyfrom
INSERT INTO allowlists (
    rule_id, description, match_condition, regex_target
) VALUES ($1, $2, $3, $4);

-- ============================================
-- Allowlist Commits
-- ============================================
-- name: DeleteAllowlistCommits :exec
DELETE FROM allowlist_commits WHERE allowlist_id = $1;

-- name: BulkInsertAllowlistCommits :copyfrom
INSERT INTO allowlist_commits (allowlist_id, commit)
VALUES ($1, $2);

-- ============================================
-- Allowlist Paths
-- ============================================
-- name: DeleteAllowlistPaths :exec
DELETE FROM allowlist_paths WHERE allowlist_id = $1;

-- name: BulkInsertAllowlistPaths :copyfrom
INSERT INTO allowlist_paths (allowlist_id, path)
VALUES ($1, $2);

-- ============================================
-- Allowlist Regexes
-- ============================================
-- name: DeleteAllowlistRegexes :exec
DELETE FROM allowlist_regexes WHERE allowlist_id = $1;

-- name: BulkInsertAllowlistRegexes :copyfrom
INSERT INTO allowlist_regexes (allowlist_id, regex)
VALUES ($1, $2);

-- ============================================
-- Allowlist Stopwords
-- ============================================
-- name: DeleteAllowlistStopwords :exec
DELETE FROM allowlist_stopwords WHERE allowlist_id = $1;

-- name: BulkInsertAllowlistStopwords :copyfrom
INSERT INTO allowlist_stopwords (allowlist_id, stopword)
VALUES ($1, $2);
