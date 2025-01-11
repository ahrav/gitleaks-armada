-- 0002_add_scanning_tables.up.sql

-- Github Repositories Table
CREATE TABLE github_repositories (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    url VARCHAR(512) NOT NULL UNIQUE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_github_repositories_name ON github_repositories (name);
CREATE INDEX idx_github_repositories_url ON github_repositories (url);

-- Scan Targets Table
CREATE TABLE scan_targets (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    target_type VARCHAR(255) NOT NULL,  -- e.g. "github_repositories"
    target_id BIGINT NOT NULL,          -- references the row in that table
    last_scan_time TIMESTAMPTZ,
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_scan_targets_name ON scan_targets (name);
CREATE INDEX idx_scan_targets_target_id ON scan_targets (target_id);

-- Scan Job Status Enum
CREATE TYPE scan_job_status AS ENUM (
    'QUEUED',
    'RUNNING',
    'COMPLETED',
    'FAILED'
);

-- Scan Jobs Table
CREATE TABLE scan_jobs (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    job_id UUID NOT NULL UNIQUE,
    scan_target_id BIGINT NOT NULL REFERENCES scan_targets (id),
    status scan_job_status NOT NULL,
    start_time TIMESTAMPTZ,
    end_time TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_scan_jobs_scan_target_id ON scan_jobs (scan_target_id);
CREATE INDEX idx_scan_jobs_status ON scan_jobs (status);

-- Rules Table
CREATE TABLE rules (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    rule_id VARCHAR(255) NOT NULL UNIQUE,
    description VARCHAR(1024),
    entropy FLOAT,
    secret_group INTEGER,
    regex VARCHAR(1024) NOT NULL,
    path VARCHAR(512),
    tags VARCHAR(64)[],
    keywords VARCHAR(64)[],
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_rules_rule_id ON rules (rule_id);

-- Allowlist Table
CREATE TABLE allowlists (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    rule_id BIGINT NOT NULL REFERENCES rules (id) ON DELETE CASCADE,
    description VARCHAR(1024),
    match_condition VARCHAR(3) NOT NULL, -- 'OR' or 'AND'
    regex_target VARCHAR(5), -- Can be NULL, 'match', or 'line'
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_allowlist_config UNIQUE (rule_id, match_condition, regex_target)  -- Added unique constraint
);

-- Indexes
CREATE INDEX idx_allowlists_rule_id ON allowlists (rule_id);

-- Allowlist Commits Table
CREATE TABLE allowlist_commits (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    allowlist_id BIGINT NOT NULL REFERENCES allowlists (id) ON DELETE CASCADE,
    commit VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_allowlist_commits_allowlist_id ON allowlist_commits (allowlist_id);
CREATE UNIQUE INDEX idx_unique_commits_per_allowlist ON allowlist_commits (allowlist_id, commit);

-- Allowlist Paths Table
CREATE TABLE allowlist_paths (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    allowlist_id BIGINT NOT NULL REFERENCES allowlists (id) ON DELETE CASCADE,
    path VARCHAR(512) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_path_per_allowlist UNIQUE (allowlist_id, path)
);

-- Indexes
CREATE INDEX idx_allowlist_paths_allowlist_id ON allowlist_paths (allowlist_id);

-- Allowlist Regexes Table
CREATE TABLE allowlist_regexes (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    allowlist_id BIGINT NOT NULL REFERENCES allowlists (id) ON DELETE CASCADE,
    regex VARCHAR(1024) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_regex_per_allowlist UNIQUE (allowlist_id, regex)
);

-- Indexes
CREATE INDEX idx_allowlist_regexes_allowlist_id ON allowlist_regexes (allowlist_id);

-- Allowlist Stopwords Table
CREATE TABLE allowlist_stopwords (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    allowlist_id BIGINT NOT NULL REFERENCES allowlists (id) ON DELETE CASCADE,
    stopword VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_allowlist_stopwords_allowlist_id ON allowlist_stopwords (allowlist_id);
CREATE UNIQUE INDEX idx_unique_stopwords_per_allowlist ON allowlist_stopwords (allowlist_id, stopword);

-- Findings Table
CREATE TABLE findings (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    scan_job_id BIGINT NOT NULL REFERENCES scan_jobs (id),
    rule_id BIGINT NOT NULL REFERENCES rules (id),
    scan_target_id BIGINT NOT NULL REFERENCES scan_targets (id),

    fingerprint VARCHAR(255) NOT NULL UNIQUE,  -- For deduping
    file_path VARCHAR(512),
    line_number INTEGER,
    line VARCHAR(1024),
    match VARCHAR(1024),
    author_email VARCHAR(255),

    -- JSONB for ephemeral/per-scan data: commit hash, secret, commit message, start line, end line, etc.
    raw_finding JSONB NOT NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_findings_scan_job_id ON findings (scan_job_id);
CREATE INDEX idx_findings_rule_id ON findings (rule_id);
CREATE INDEX idx_findings_scan_target_id ON findings (scan_target_id);
CREATE INDEX idx_findings_fingerprint ON findings (fingerprint);
