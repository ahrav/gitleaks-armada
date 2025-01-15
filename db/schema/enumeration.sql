-- Enumeration Domain Schemas

-- Enumeration Status Enum
CREATE TYPE enumeration_status AS ENUM (
    'INITIALIZED',
    'IN_PROGRESS',
    'COMPLETED',
    'FAILED',
    'STALLED',
    'PARTIALLY_COMPLETED'
);

-- Batch Status Enum
CREATE TYPE batch_status AS ENUM (
    'SUCCEEDED',
    'FAILED',
    'PARTIALLY_COMPLETED',
    'IN_PROGRESS'
);

-- Checkpoints Table
CREATE TABLE checkpoints (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    target_id UUID NOT NULL UNIQUE,
    data JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Enumeration Session States Table (Aggregate Root)
CREATE TABLE enumeration_session_states (
    session_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_type VARCHAR(32) NOT NULL,
    config JSONB NOT NULL,
    last_checkpoint_id BIGINT REFERENCES checkpoints(id),
    status enumeration_status NOT NULL,
    failure_reason TEXT,
    -- Timeline fields
    started_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    last_update TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_enumeration_session_id UNIQUE (session_id)
);

-- Session Metrics (Value Object)
CREATE TABLE enumeration_session_metrics (
    session_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    total_batches INTEGER NOT NULL DEFAULT 0,
    failed_batches INTEGER NOT NULL DEFAULT 0,
    items_found INTEGER NOT NULL DEFAULT 0,
    items_processed INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_session_metrics UNIQUE (session_id)
);

-- Enumeration Batches Table (Entity)
CREATE TABLE enumeration_batches (
    batch_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID NOT NULL REFERENCES enumeration_session_states(session_id),
    status batch_status NOT NULL,
    checkpoint_id BIGINT REFERENCES checkpoints(id),
    -- Timeline fields
    started_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    last_update TIMESTAMPTZ NOT NULL,
    -- Metrics fields
    items_processed INTEGER NOT NULL DEFAULT 0,
    expected_items INTEGER NOT NULL DEFAULT 0,
    error_details TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_batch_id UNIQUE (batch_id)
);

-- Indexes
CREATE INDEX idx_enumeration_batches_session_id ON enumeration_batches(session_id);
CREATE INDEX idx_enumeration_batches_status ON enumeration_batches(status);

-- Tasks Table
CREATE TABLE tasks (
    task_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_type VARCHAR NOT NULL
);

-- Enumeration Tasks Table
CREATE TABLE enumeration_tasks (
    task_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID NOT NULL REFERENCES enumeration_session_states(session_id),
    resource_uri VARCHAR NOT NULL,
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

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
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
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

-- URL Targets Table
CREATE TABLE urls (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    url VARCHAR(2048) NOT NULL UNIQUE,
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index
CREATE INDEX idx_urls_url ON urls (url);
