-- queries.sql

-- ============================================
-- Checkpoints
-- ============================================
-- name: CreateOrUpdateCheckpoint :exec
INSERT INTO checkpoints (target_id, data, created_at, updated_at)
VALUES ($1, $2, NOW(), NOW())
ON CONFLICT (target_id) DO UPDATE
    SET data = EXCLUDED.data,
        updated_at = NOW();

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
-- name: CreateOrUpdateEnumerationState :exec
INSERT INTO enumeration_states (
  session_id,
  source_type,
  config,
  last_checkpoint_id,
  status,
  created_at,
  updated_at
)
VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
ON CONFLICT (session_id) DO UPDATE
    SET source_type       = EXCLUDED.source_type,
        config            = EXCLUDED.config,
        last_checkpoint_id= EXCLUDED.last_checkpoint_id,
        status            = EXCLUDED.status,
        updated_at        = NOW();

-- name: GetEnumerationState :one
SELECT session_id, source_type, config, last_checkpoint_id,
       status, created_at, updated_at
FROM enumeration_states
WHERE session_id = $1;

-- name: DeleteEnumerationState :exec
DELETE FROM enumeration_states
WHERE session_id = $1;

-- name: ListEnumerationStates :many
SELECT session_id, source_type, config, last_checkpoint_id,
       status, created_at, updated_at
FROM enumeration_states;
