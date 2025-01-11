-- Scanning Domain Queries

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
