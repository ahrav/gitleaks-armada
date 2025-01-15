// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.27.0
// source: enumeration.sql

package db

import (
	"context"

	"github.com/jackc/pgx/v5/pgtype"
)

const createGitHubRepo = `-- name: CreateGitHubRepo :one

INSERT INTO github_repositories (
    name,
    url,
    is_active,
    metadata,
    created_at,
    updated_at
) VALUES (
    $1, $2, $3, $4, NOW(), NOW()
)
RETURNING id
`

type CreateGitHubRepoParams struct {
	Name     string
	Url      string
	IsActive bool
	Metadata []byte
}

// ============================================
// GitHub Repositories
// ============================================
func (q *Queries) CreateGitHubRepo(ctx context.Context, arg CreateGitHubRepoParams) (int64, error) {
	row := q.db.QueryRow(ctx, createGitHubRepo,
		arg.Name,
		arg.Url,
		arg.IsActive,
		arg.Metadata,
	)
	var id int64
	err := row.Scan(&id)
	return id, err
}

const createScanTarget = `-- name: CreateScanTarget :one

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
RETURNING id
`

type CreateScanTargetParams struct {
	ID         pgtype.UUID
	Name       string
	TargetType string
	TargetID   int64
	Metadata   []byte
}

// ============================================
// Scan Targets
// ============================================
func (q *Queries) CreateScanTarget(ctx context.Context, arg CreateScanTargetParams) (pgtype.UUID, error) {
	row := q.db.QueryRow(ctx, createScanTarget,
		arg.ID,
		arg.Name,
		arg.TargetType,
		arg.TargetID,
		arg.Metadata,
	)
	var id pgtype.UUID
	err := row.Scan(&id)
	return id, err
}

const createTask = `-- name: CreateTask :exec
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
)
`

type CreateTaskParams struct {
	TaskID      pgtype.UUID
	SourceType  string
	SessionID   pgtype.UUID
	ResourceUri string
	Metadata    []byte
}

// ============================================
// Enumeration Tasks
// ============================================
func (q *Queries) CreateTask(ctx context.Context, arg CreateTaskParams) error {
	_, err := q.db.Exec(ctx, createTask,
		arg.TaskID,
		arg.SourceType,
		arg.SessionID,
		arg.ResourceUri,
		arg.Metadata,
	)
	return err
}

const createURLTarget = `-- name: CreateURLTarget :one

INSERT INTO url_targets (
    url,
    metadata,
    created_at,
    updated_at
) VALUES (
    $1, $2, NOW(), NOW()
)
RETURNING id
`

type CreateURLTargetParams struct {
	Url      string
	Metadata []byte
}

// ============================================
// URL Targets
// ============================================
func (q *Queries) CreateURLTarget(ctx context.Context, arg CreateURLTargetParams) (int64, error) {
	row := q.db.QueryRow(ctx, createURLTarget, arg.Url, arg.Metadata)
	var id int64
	err := row.Scan(&id)
	return id, err
}

const deleteCheckpoint = `-- name: DeleteCheckpoint :exec
DELETE FROM checkpoints
WHERE target_id = $1
`

func (q *Queries) DeleteCheckpoint(ctx context.Context, targetID pgtype.UUID) error {
	_, err := q.db.Exec(ctx, deleteCheckpoint, targetID)
	return err
}

const deleteEnumerationSessionState = `-- name: DeleteEnumerationSessionState :exec
DELETE FROM enumeration_session_states
WHERE session_id = $1
`

func (q *Queries) DeleteEnumerationSessionState(ctx context.Context, sessionID pgtype.UUID) error {
	_, err := q.db.Exec(ctx, deleteEnumerationSessionState, sessionID)
	return err
}

const findScanTarget = `-- name: FindScanTarget :one
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
WHERE target_type = $1 AND target_id = $2
`

type FindScanTargetParams struct {
	TargetType string
	TargetID   int64
}

func (q *Queries) FindScanTarget(ctx context.Context, arg FindScanTargetParams) (ScanTarget, error) {
	row := q.db.QueryRow(ctx, findScanTarget, arg.TargetType, arg.TargetID)
	var i ScanTarget
	err := row.Scan(
		&i.ID,
		&i.Name,
		&i.TargetType,
		&i.TargetID,
		&i.LastScanTime,
		&i.Metadata,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const getActiveEnumerationSessionStates = `-- name: GetActiveEnumerationSessionStates :many
SELECT session_id, source_type, config, last_checkpoint_id, failure_reason,
       status, created_at, updated_at
FROM enumeration_session_states
WHERE status IN ('INITIALIZED', 'IN_PROGRESS')
ORDER BY created_at DESC
`

type GetActiveEnumerationSessionStatesRow struct {
	SessionID        pgtype.UUID
	SourceType       string
	Config           []byte
	LastCheckpointID pgtype.Int8
	FailureReason    pgtype.Text
	Status           EnumerationStatus
	CreatedAt        pgtype.Timestamptz
	UpdatedAt        pgtype.Timestamptz
}

func (q *Queries) GetActiveEnumerationSessionStates(ctx context.Context) ([]GetActiveEnumerationSessionStatesRow, error) {
	rows, err := q.db.Query(ctx, getActiveEnumerationSessionStates)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []GetActiveEnumerationSessionStatesRow
	for rows.Next() {
		var i GetActiveEnumerationSessionStatesRow
		if err := rows.Scan(
			&i.SessionID,
			&i.SourceType,
			&i.Config,
			&i.LastCheckpointID,
			&i.FailureReason,
			&i.Status,
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

const getBatch = `-- name: GetBatch :one
SELECT batch_id, session_id, status, checkpoint_id, started_at, completed_at, last_update, items_processed, expected_items, error_details, created_at, updated_at FROM enumeration_batches
WHERE batch_id = $1
`

func (q *Queries) GetBatch(ctx context.Context, batchID pgtype.UUID) (EnumerationBatch, error) {
	row := q.db.QueryRow(ctx, getBatch, batchID)
	var i EnumerationBatch
	err := row.Scan(
		&i.BatchID,
		&i.SessionID,
		&i.Status,
		&i.CheckpointID,
		&i.StartedAt,
		&i.CompletedAt,
		&i.LastUpdate,
		&i.ItemsProcessed,
		&i.ExpectedItems,
		&i.ErrorDetails,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const getBatchesForSession = `-- name: GetBatchesForSession :many
SELECT batch_id, session_id, status, checkpoint_id, started_at, completed_at, last_update, items_processed, expected_items, error_details, created_at, updated_at
FROM enumeration_batches
WHERE session_id = $1
ORDER BY started_at ASC
`

func (q *Queries) GetBatchesForSession(ctx context.Context, sessionID pgtype.UUID) ([]EnumerationBatch, error) {
	rows, err := q.db.Query(ctx, getBatchesForSession, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []EnumerationBatch
	for rows.Next() {
		var i EnumerationBatch
		if err := rows.Scan(
			&i.BatchID,
			&i.SessionID,
			&i.Status,
			&i.CheckpointID,
			&i.StartedAt,
			&i.CompletedAt,
			&i.LastUpdate,
			&i.ItemsProcessed,
			&i.ExpectedItems,
			&i.ErrorDetails,
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

const getCheckpoint = `-- name: GetCheckpoint :one
SELECT id, target_id, data, created_at, updated_at
FROM checkpoints
WHERE target_id = $1
`

func (q *Queries) GetCheckpoint(ctx context.Context, targetID pgtype.UUID) (Checkpoint, error) {
	row := q.db.QueryRow(ctx, getCheckpoint, targetID)
	var i Checkpoint
	err := row.Scan(
		&i.ID,
		&i.TargetID,
		&i.Data,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const getCheckpointByID = `-- name: GetCheckpointByID :one
SELECT id, target_id, data, created_at, updated_at
FROM checkpoints
WHERE id = $1
`

func (q *Queries) GetCheckpointByID(ctx context.Context, id int64) (Checkpoint, error) {
	row := q.db.QueryRow(ctx, getCheckpointByID, id)
	var i Checkpoint
	err := row.Scan(
		&i.ID,
		&i.TargetID,
		&i.Data,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const getEnumerationSessionState = `-- name: GetEnumerationSessionState :one
SELECT session_id, source_type, config, last_checkpoint_id, status, failure_reason, started_at, completed_at, last_update, created_at, updated_at FROM enumeration_session_states
WHERE session_id = $1
`

func (q *Queries) GetEnumerationSessionState(ctx context.Context, sessionID pgtype.UUID) (EnumerationSessionState, error) {
	row := q.db.QueryRow(ctx, getEnumerationSessionState, sessionID)
	var i EnumerationSessionState
	err := row.Scan(
		&i.SessionID,
		&i.SourceType,
		&i.Config,
		&i.LastCheckpointID,
		&i.Status,
		&i.FailureReason,
		&i.StartedAt,
		&i.CompletedAt,
		&i.LastUpdate,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const getGitHubRepoByID = `-- name: GetGitHubRepoByID :one
SELECT
    id,
    name,
    url,
    is_active,
    metadata,
    created_at,
    updated_at
FROM github_repositories
WHERE id = $1
`

func (q *Queries) GetGitHubRepoByID(ctx context.Context, id int64) (GithubRepository, error) {
	row := q.db.QueryRow(ctx, getGitHubRepoByID, id)
	var i GithubRepository
	err := row.Scan(
		&i.ID,
		&i.Name,
		&i.Url,
		&i.IsActive,
		&i.Metadata,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const getGitHubRepoByURL = `-- name: GetGitHubRepoByURL :one
SELECT
    id,
    name,
    url,
    is_active,
    metadata,
    created_at,
    updated_at
FROM github_repositories
WHERE url = $1
`

func (q *Queries) GetGitHubRepoByURL(ctx context.Context, url string) (GithubRepository, error) {
	row := q.db.QueryRow(ctx, getGitHubRepoByURL, url)
	var i GithubRepository
	err := row.Scan(
		&i.ID,
		&i.Name,
		&i.Url,
		&i.IsActive,
		&i.Metadata,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const getScanTargetByID = `-- name: GetScanTargetByID :one
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
WHERE id = $1
`

func (q *Queries) GetScanTargetByID(ctx context.Context, id pgtype.UUID) (ScanTarget, error) {
	row := q.db.QueryRow(ctx, getScanTargetByID, id)
	var i ScanTarget
	err := row.Scan(
		&i.ID,
		&i.Name,
		&i.TargetType,
		&i.TargetID,
		&i.LastScanTime,
		&i.Metadata,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const getSessionMetrics = `-- name: GetSessionMetrics :one
SELECT session_id, total_batches, failed_batches, items_found, items_processed, created_at, updated_at FROM enumeration_session_metrics
WHERE session_id = $1
`

func (q *Queries) GetSessionMetrics(ctx context.Context, sessionID pgtype.UUID) (EnumerationSessionMetric, error) {
	row := q.db.QueryRow(ctx, getSessionMetrics, sessionID)
	var i EnumerationSessionMetric
	err := row.Scan(
		&i.SessionID,
		&i.TotalBatches,
		&i.FailedBatches,
		&i.ItemsFound,
		&i.ItemsProcessed,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const getSessionState = `-- name: GetSessionState :one
SELECT session_id, source_type, config, last_checkpoint_id, status, failure_reason, started_at, completed_at, last_update, created_at, updated_at FROM enumeration_session_states
WHERE session_id = $1
`

func (q *Queries) GetSessionState(ctx context.Context, sessionID pgtype.UUID) (EnumerationSessionState, error) {
	row := q.db.QueryRow(ctx, getSessionState, sessionID)
	var i EnumerationSessionState
	err := row.Scan(
		&i.SessionID,
		&i.SourceType,
		&i.Config,
		&i.LastCheckpointID,
		&i.Status,
		&i.FailureReason,
		&i.StartedAt,
		&i.CompletedAt,
		&i.LastUpdate,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const getTaskByID = `-- name: GetTaskByID :one
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
WHERE t.task_id = $1
`

type GetTaskByIDRow struct {
	TaskID      pgtype.UUID
	SourceType  string
	SessionID   pgtype.UUID
	ResourceUri string
	Metadata    []byte
	CreatedAt   pgtype.Timestamptz
	UpdatedAt   pgtype.Timestamptz
}

func (q *Queries) GetTaskByID(ctx context.Context, taskID pgtype.UUID) (GetTaskByIDRow, error) {
	row := q.db.QueryRow(ctx, getTaskByID, taskID)
	var i GetTaskByIDRow
	err := row.Scan(
		&i.TaskID,
		&i.SourceType,
		&i.SessionID,
		&i.ResourceUri,
		&i.Metadata,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const getURLTargetByURL = `-- name: GetURLTargetByURL :one
SELECT
    id,
    url,
    metadata
FROM url_targets
WHERE url = $1
`

type GetURLTargetByURLRow struct {
	ID       int64
	Url      string
	Metadata []byte
}

func (q *Queries) GetURLTargetByURL(ctx context.Context, url string) (GetURLTargetByURLRow, error) {
	row := q.db.QueryRow(ctx, getURLTargetByURL, url)
	var i GetURLTargetByURLRow
	err := row.Scan(&i.ID, &i.Url, &i.Metadata)
	return i, err
}

const listEnumerationSessionStates = `-- name: ListEnumerationSessionStates :many
SELECT session_id, source_type, config, last_checkpoint_id, failure_reason,
       status, created_at, updated_at
FROM enumeration_session_states
ORDER BY created_at DESC
LIMIT $1
`

type ListEnumerationSessionStatesRow struct {
	SessionID        pgtype.UUID
	SourceType       string
	Config           []byte
	LastCheckpointID pgtype.Int8
	FailureReason    pgtype.Text
	Status           EnumerationStatus
	CreatedAt        pgtype.Timestamptz
	UpdatedAt        pgtype.Timestamptz
}

func (q *Queries) ListEnumerationSessionStates(ctx context.Context, limit int32) ([]ListEnumerationSessionStatesRow, error) {
	rows, err := q.db.Query(ctx, listEnumerationSessionStates, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []ListEnumerationSessionStatesRow
	for rows.Next() {
		var i ListEnumerationSessionStatesRow
		if err := rows.Scan(
			&i.SessionID,
			&i.SourceType,
			&i.Config,
			&i.LastCheckpointID,
			&i.FailureReason,
			&i.Status,
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

const listGitHubRepos = `-- name: ListGitHubRepos :many
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
LIMIT $1 OFFSET $2
`

type ListGitHubReposParams struct {
	Limit  int32
	Offset int32
}

func (q *Queries) ListGitHubRepos(ctx context.Context, arg ListGitHubReposParams) ([]GithubRepository, error) {
	rows, err := q.db.Query(ctx, listGitHubRepos, arg.Limit, arg.Offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []GithubRepository
	for rows.Next() {
		var i GithubRepository
		if err := rows.Scan(
			&i.ID,
			&i.Name,
			&i.Url,
			&i.IsActive,
			&i.Metadata,
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

const listScanTargets = `-- name: ListScanTargets :many
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
LIMIT $1 OFFSET $2
`

type ListScanTargetsParams struct {
	Limit  int32
	Offset int32
}

func (q *Queries) ListScanTargets(ctx context.Context, arg ListScanTargetsParams) ([]ScanTarget, error) {
	rows, err := q.db.Query(ctx, listScanTargets, arg.Limit, arg.Offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []ScanTarget
	for rows.Next() {
		var i ScanTarget
		if err := rows.Scan(
			&i.ID,
			&i.Name,
			&i.TargetType,
			&i.TargetID,
			&i.LastScanTime,
			&i.Metadata,
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

const updateGitHubRepo = `-- name: UpdateGitHubRepo :execrows
UPDATE github_repositories
SET
    name = $2,
    url = $3,
    is_active = $4,
    metadata = $5,
    updated_at = NOW()
WHERE id = $1
`

type UpdateGitHubRepoParams struct {
	ID       int64
	Name     string
	Url      string
	IsActive bool
	Metadata []byte
}

func (q *Queries) UpdateGitHubRepo(ctx context.Context, arg UpdateGitHubRepoParams) (int64, error) {
	result, err := q.db.Exec(ctx, updateGitHubRepo,
		arg.ID,
		arg.Name,
		arg.Url,
		arg.IsActive,
		arg.Metadata,
	)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected(), nil
}

const updateScanTarget = `-- name: UpdateScanTarget :execrows
UPDATE scan_targets
SET
    name = $2,
    target_type = $3,
    target_id = $4,
    last_scan_time = $5,
    metadata = $6,
    updated_at = NOW()
WHERE id = $1
`

type UpdateScanTargetParams struct {
	ID           pgtype.UUID
	Name         string
	TargetType   string
	TargetID     int64
	LastScanTime pgtype.Timestamptz
	Metadata     []byte
}

func (q *Queries) UpdateScanTarget(ctx context.Context, arg UpdateScanTargetParams) (int64, error) {
	result, err := q.db.Exec(ctx, updateScanTarget,
		arg.ID,
		arg.Name,
		arg.TargetType,
		arg.TargetID,
		arg.LastScanTime,
		arg.Metadata,
	)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected(), nil
}

const updateScanTargetScanTime = `-- name: UpdateScanTargetScanTime :execrows
UPDATE scan_targets
SET
    last_scan_time = $2,
    metadata = $3,
    updated_at = NOW()
WHERE id = $1
`

type UpdateScanTargetScanTimeParams struct {
	ID           pgtype.UUID
	LastScanTime pgtype.Timestamptz
	Metadata     []byte
}

func (q *Queries) UpdateScanTargetScanTime(ctx context.Context, arg UpdateScanTargetScanTimeParams) (int64, error) {
	result, err := q.db.Exec(ctx, updateScanTargetScanTime, arg.ID, arg.LastScanTime, arg.Metadata)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected(), nil
}

const updateURLTarget = `-- name: UpdateURLTarget :execrows
UPDATE url_targets
SET
    url = $2,
    metadata = $3,
    updated_at = NOW()
WHERE id = $1
`

type UpdateURLTargetParams struct {
	ID       int64
	Url      string
	Metadata []byte
}

func (q *Queries) UpdateURLTarget(ctx context.Context, arg UpdateURLTargetParams) (int64, error) {
	result, err := q.db.Exec(ctx, updateURLTarget, arg.ID, arg.Url, arg.Metadata)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected(), nil
}

const upsertBatch = `-- name: UpsertBatch :exec
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
   updated_at = NOW()
`

type UpsertBatchParams struct {
	BatchID        pgtype.UUID
	SessionID      pgtype.UUID
	Status         BatchStatus
	CheckpointID   pgtype.Int8
	StartedAt      pgtype.Timestamptz
	CompletedAt    pgtype.Timestamptz
	LastUpdate     pgtype.Timestamptz
	ItemsProcessed int32
	ExpectedItems  int32
	ErrorDetails   pgtype.Text
}

// ============================================
// Batch (Entity) operations
// ============================================
func (q *Queries) UpsertBatch(ctx context.Context, arg UpsertBatchParams) error {
	_, err := q.db.Exec(ctx, upsertBatch,
		arg.BatchID,
		arg.SessionID,
		arg.Status,
		arg.CheckpointID,
		arg.StartedAt,
		arg.CompletedAt,
		arg.LastUpdate,
		arg.ItemsProcessed,
		arg.ExpectedItems,
		arg.ErrorDetails,
	)
	return err
}

const upsertCheckpoint = `-- name: UpsertCheckpoint :one

INSERT INTO checkpoints (target_id, data, created_at, updated_at)
VALUES ($1, $2, NOW(), NOW())
ON CONFLICT (target_id) DO UPDATE
    SET data = EXCLUDED.data,
        updated_at = NOW()
RETURNING id
`

type UpsertCheckpointParams struct {
	TargetID pgtype.UUID
	Data     []byte
}

// Enumeration Domain Queries
// ============================================
// Checkpoints
// ============================================
func (q *Queries) UpsertCheckpoint(ctx context.Context, arg UpsertCheckpointParams) (int64, error) {
	row := q.db.QueryRow(ctx, upsertCheckpoint, arg.TargetID, arg.Data)
	var id int64
	err := row.Scan(&id)
	return id, err
}

const upsertEnumerationSessionState = `-- name: UpsertEnumerationSessionState :exec
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
    updated_at = NOW()
`

type UpsertEnumerationSessionStateParams struct {
	SessionID        pgtype.UUID
	SourceType       string
	Config           []byte
	LastCheckpointID pgtype.Int8
	Status           EnumerationStatus
	FailureReason    pgtype.Text
}

// ============================================
// Enumeration States
// ============================================
func (q *Queries) UpsertEnumerationSessionState(ctx context.Context, arg UpsertEnumerationSessionStateParams) error {
	_, err := q.db.Exec(ctx, upsertEnumerationSessionState,
		arg.SessionID,
		arg.SourceType,
		arg.Config,
		arg.LastCheckpointID,
		arg.Status,
		arg.FailureReason,
	)
	return err
}

const upsertSessionMetrics = `-- name: UpsertSessionMetrics :exec
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
   updated_at = NOW()
`

type UpsertSessionMetricsParams struct {
	SessionID      pgtype.UUID
	TotalBatches   int32
	FailedBatches  int32
	ItemsFound     int32
	ItemsProcessed int32
}

func (q *Queries) UpsertSessionMetrics(ctx context.Context, arg UpsertSessionMetricsParams) error {
	_, err := q.db.Exec(ctx, upsertSessionMetrics,
		arg.SessionID,
		arg.TotalBatches,
		arg.FailedBatches,
		arg.ItemsFound,
		arg.ItemsProcessed,
	)
	return err
}

const upsertSessionState = `-- name: UpsertSessionState :exec
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
   updated_at = NOW()
`

type UpsertSessionStateParams struct {
	SessionID        pgtype.UUID
	SourceType       string
	Config           []byte
	Status           EnumerationStatus
	FailureReason    pgtype.Text
	LastCheckpointID pgtype.Int8
	StartedAt        pgtype.Timestamptz
	CompletedAt      pgtype.Timestamptz
	LastUpdate       pgtype.Timestamptz
}

// ============================================
// Session State and Metrics operations
// ============================================
func (q *Queries) UpsertSessionState(ctx context.Context, arg UpsertSessionStateParams) error {
	_, err := q.db.Exec(ctx, upsertSessionState,
		arg.SessionID,
		arg.SourceType,
		arg.Config,
		arg.Status,
		arg.FailureReason,
		arg.LastCheckpointID,
		arg.StartedAt,
		arg.CompletedAt,
		arg.LastUpdate,
	)
	return err
}
