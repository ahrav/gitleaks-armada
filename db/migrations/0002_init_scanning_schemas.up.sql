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

-- Scan Task Status Enum
CREATE TYPE scan_task_status AS ENUM (
    'IN_PROGRESS',
    'COMPLETED',
    'FAILED',
    'STALE'
);

-- Scan Tasks Table
CREATE TABLE scan_tasks (
    task_id           UUID PRIMARY KEY,
    job_id            UUID NOT NULL,
    status            scan_task_status NOT NULL,
    last_sequence_num BIGINT NOT NULL DEFAULT 0,
    start_time        TIMESTAMPTZ NOT NULL,
    last_update_time  TIMESTAMPTZ,
    items_processed   BIGINT NOT NULL DEFAULT 0,
    progress_details  JSONB,
    last_checkpoint   JSONB,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT fk_scan_job
        FOREIGN KEY (job_id) REFERENCES scan_jobs(job_id)
);

-- Indexes
CREATE INDEX idx_scan_tasks_job_id ON scan_tasks (job_id);
CREATE INDEX idx_scan_tasks_status ON scan_tasks (status);
