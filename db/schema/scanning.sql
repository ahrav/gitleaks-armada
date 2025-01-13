-- Scanning Domain Schemas

-- Scan Job Status Enum
CREATE TYPE scan_job_status AS ENUM (
    'QUEUED',
    'RUNNING',
    'COMPLETED',
    'FAILED'
);

-- Scan Jobs Table
CREATE TABLE scan_jobs (
    job_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    status scan_job_status NOT NULL,
    start_time TIMESTAMPTZ,
    end_time TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_scan_jobs_status ON scan_jobs (status);

-- Scan Job Targets Table (Associative table between scan jobs and scan targets)
CREATE TABLE scan_job_targets (
    job_id UUID NOT NULL REFERENCES scan_jobs (job_id),
    scan_target_id UUID NOT NULL REFERENCES scan_targets (id),
    PRIMARY KEY(job_id, scan_target_id)
);
