-- Scanning Domain Schemas

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
CREATE INDEX idx_scan_targets_target_type ON scan_targets (target_type);

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

