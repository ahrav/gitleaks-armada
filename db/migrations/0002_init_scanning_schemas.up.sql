-- 0003_init_scanning_schemas.up.sql

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
