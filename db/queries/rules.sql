-- Rules Domain Queries

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
