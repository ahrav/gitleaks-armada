-- 0002_add_scanning_tables.up.sql

-- Github Repositories Table
CREATE TABLE github_repositories (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    url TEXT NOT NULL UNIQUE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Scan Targets Table
CREATE TABLE scan_targets (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    target_type VARCHAR(255) NOT NULL,  -- e.g. "github_repositories"
    target_id BIGINT NOT NULL,          -- references the row in that table
    last_scan_time TIMESTAMPTZ,
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- Scan Job Status Enum
CREATE TYPE scan_job_status AS ENUM (
    'queued',
    'running',
    'completed',
    'failed'
);

-- Scan Jobs Table
CREATE TABLE scan_jobs (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    scan_target_id BIGINT NOT NULL REFERENCES scan_targets (id),
    status scan_job_status NOT NULL,
    start_time TIMESTAMPTZ,
    end_time TIMESTAMPTZ,
    commit_hash VARCHAR(255),
    kafka_offset BIGINT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Rules Table
CREATE TABLE rules (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    rule_id VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    entropy FLOAT,
    secret_group INTEGER,
    regex TEXT NOT NULL,
    path TEXT,
    tags TEXT[],
    keywords TEXT[],
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Allowlist Table
CREATE TABLE allowlists (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    rule_id BIGINT NOT NULL REFERENCES rules (id) ON DELETE CASCADE,
    description TEXT,
    match_condition VARCHAR(3) NOT NULL, -- 'OR' or 'AND'
    regex_target VARCHAR(5), -- Can be NULL, 'match', or 'line'.
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Allowlist Commits Table
CREATE TABLE allowlist_commits (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    allowlist_id BIGINT NOT NULL REFERENCES allowlists (id) ON DELETE CASCADE,
    commit VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Allowlist Paths Table
CREATE TABLE allowlist_paths (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    allowlist_id BIGINT NOT NULL REFERENCES allowlists (id) ON DELETE CASCADE,
    path TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Allowlist Regexes Table
CREATE TABLE allowlist_regexes (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    allowlist_id BIGINT NOT NULL REFERENCES allowlists (id) ON DELETE CASCADE,
    regex TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Allowlist Stopwords Table
CREATE TABLE allowlist_stopwords (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    allowlist_id BIGINT NOT NULL REFERENCES allowlists (id) ON DELETE CASCADE,
    stopword VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Findings Table
CREATE TABLE findings (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    scan_job_id BIGINT NOT NULL REFERENCES scan_jobs (id),
    rule_id BIGINT NOT NULL REFERENCES rules (id),
    scan_target_id BIGINT NOT NULL REFERENCES scan_targets (id),

    fingerprint VARCHAR(255) NOT NULL UNIQUE,  -- For deduping
    file_path TEXT,        -- The path where the secret was found
    line_number INTEGER,   -- The line number
    line TEXT,             -- The entire line (if you want quick reference)
    match TEXT,
    author_email VARCHAR(255),

    -- JSONB for ephemeral/per-scan data: commit hash, secret, commit message, start line, end line, etc.
    raw_finding JSONB NOT NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- Indexes
CREATE INDEX idx_github_repositories_name ON github_repositories (name);
CREATE INDEX idx_github_repositories_url ON github_repositories (url);

CREATE INDEX idx_scan_targets_target_type ON scan_targets (target_type);
CREATE INDEX idx_scan_targets_target_id ON scan_targets (target_id);

CREATE INDEX idx_scan_jobs_scan_target_id ON scan_jobs (scan_target_id);
CREATE INDEX idx_scan_jobs_status ON scan_jobs (status);
CREATE INDEX idx_scan_jobs_commit_hash ON scan_jobs (commit_hash);

CREATE INDEX idx_findings_scan_job_id ON findings (scan_job_id);
CREATE INDEX idx_findings_rule_id ON findings (rule_id);
CREATE INDEX idx_findings_scan_target_id ON findings (scan_target_id);
CREATE INDEX idx_findings_fingerprint ON findings (fingerprint);

CREATE INDEX idx_allowlists_rule_id ON allowlists (rule_id);

CREATE INDEX idx_allowlist_commits_allowlist_id ON allowlist_commits (allowlist_id);
CREATE UNIQUE INDEX idx_unique_commits_per_allowlist ON allowlist_commits (allowlist_id, commit);

CREATE INDEX idx_allowlist_paths_allowlist_id ON allowlist_paths (allowlist_id);

CREATE INDEX idx_allowlist_regexes_allowlist_id ON allowlist_regexes (allowlist_id);

CREATE INDEX idx_allowlist_stopwords_allowlist_id ON allowlist_stopwords (allowlist_id);
CREATE UNIQUE INDEX idx_unique_stopwords_per_allowlist ON allowlist_stopwords (allowlist_id, stopword);
