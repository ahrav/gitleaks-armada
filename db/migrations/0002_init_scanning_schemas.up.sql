-- 0002_init_scanning_schemas.up.sql

-- Scan Job Status Enum
CREATE TYPE scan_job_status AS ENUM (
    'QUEUED',
    'ENUMERATING',
    'RUNNING',
    'PAUSING',
    'PAUSED',
    'COMPLETED',
    'CANCELLING',
    'CANCELLED',
    'FAILED'
);

-- Scan Jobs Table
CREATE TABLE scan_jobs (
    job_id UUID PRIMARY KEY,
    status scan_job_status NOT NULL,
    source_type VARCHAR(32) NOT NULL,
    config JSONB NOT NULL,
    start_time TIMESTAMPTZ,
    end_time TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_scan_jobs_status ON scan_jobs (status);

-- Scan Job Metrics Table
CREATE TABLE scan_job_metrics (
    job_id UUID PRIMARY KEY REFERENCES scan_jobs(job_id),
    total_tasks INT NOT NULL DEFAULT 0,
    pending_tasks INT NOT NULL DEFAULT 0,
    in_progress_tasks INT NOT NULL DEFAULT 0,
    completed_tasks INT NOT NULL DEFAULT 0,
    failed_tasks INT NOT NULL DEFAULT 0,
    stale_tasks INT NOT NULL DEFAULT 0,
    cancelled_tasks INT NOT NULL DEFAULT 0,
    paused_tasks INT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_scan_job_metrics ON scan_job_metrics (job_id, total_tasks, pending_tasks, in_progress_tasks, completed_tasks, failed_tasks, stale_tasks);

-- Job Metrics Checkpoints Table
CREATE TABLE job_metrics_checkpoints (
    job_id UUID NOT NULL REFERENCES scan_jobs (job_id),
    partition_id INT NOT NULL,
    partition_offset BIGINT NOT NULL,
    last_processed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (job_id, partition_id, partition_offset)
);

-- Scan Job Targets Table (Associative table between scan jobs and scan targets)
CREATE TABLE scan_job_targets (
    job_id UUID NOT NULL REFERENCES scan_jobs (job_id),
    scan_target_id UUID NOT NULL REFERENCES scan_targets (id),
    PRIMARY KEY(job_id, scan_target_id)
);

-- Scan Task Status Enum
CREATE TYPE scan_task_status AS ENUM (
    'PENDING',
    'IN_PROGRESS',
    'PAUSED',
    'COMPLETED',
    'CANCELLED',
    'FAILED',
    'STALE'
);

-- Scan Task Stall Reason Enum
CREATE TYPE scan_task_stall_reason AS ENUM (
    'NO_PROGRESS',
    'LOW_THROUGHPUT',
    'HIGH_ERRORS'
);

-- Scan Tasks Table
CREATE TABLE scan_tasks (
    task_id           UUID PRIMARY KEY REFERENCES tasks(task_id),
    job_id            UUID NOT NULL,
    owner_controller_id VARCHAR(255) NOT NULL,
    status            scan_task_status NOT NULL,
    resource_uri      VARCHAR(1024) NOT NULL,
    last_sequence_num BIGINT NOT NULL DEFAULT 0,
    last_heartbeat_at TIMESTAMPTZ,
    start_time        TIMESTAMPTZ,
    end_time          TIMESTAMPTZ,
    items_processed   BIGINT NOT NULL DEFAULT 0,
    progress_details  JSONB,
    last_checkpoint   JSONB,
    stall_reason      scan_task_stall_reason,
    recovery_attempts INT NOT NULL DEFAULT 0,
    stalled_at        TIMESTAMPTZ,
    paused_at         TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT fk_scan_job
        FOREIGN KEY (job_id) REFERENCES scan_jobs(job_id)
);

-- Indexes
CREATE INDEX idx_scan_tasks_job_id ON scan_tasks (job_id);
CREATE INDEX idx_scan_tasks_owner_controller_id_status_last_heartbeat_at ON scan_tasks (owner_controller_id, status, last_heartbeat_at);

-- Scanner Groups Table
CREATE TABLE scanner_groups (
    id UUID PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (name)
);

-- Indexes
CREATE INDEX idx_scanner_groups_name ON scanner_groups (name);

-- Scanner Status Enum
CREATE TYPE scanner_status AS ENUM ('ONLINE', 'OFFLINE', 'MAINTENANCE', 'ERROR', 'UNKNOWN');

-- Scanners Table
CREATE TABLE scanners (
    id UUID PRIMARY KEY,
    group_id UUID REFERENCES scanner_groups(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    version VARCHAR(50) NOT NULL,
    last_heartbeat TIMESTAMPTZ,
    status scanner_status NOT NULL DEFAULT 'ONLINE',
    ip_address INET,
    hostname VARCHAR(255),
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (group_id, name)
);

-- Indexes
CREATE INDEX idx_scanners_group_id ON scanners(group_id);
