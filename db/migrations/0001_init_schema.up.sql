-- 000001_init_schema.up.sql

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
    target_id VARCHAR(512) NOT NULL UNIQUE,
    data JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Enumeration Session States Table (Aggregate Root)
CREATE TABLE enumeration_session_states (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    session_id VARCHAR(64) NOT NULL,
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
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    session_id VARCHAR(64) NOT NULL REFERENCES enumeration_session_states(session_id),
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
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    batch_id VARCHAR(64) NOT NULL UNIQUE,
    session_id VARCHAR(64) NOT NULL REFERENCES enumeration_session_states(session_id),
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

CREATE INDEX idx_enumeration_batches_session_id ON enumeration_batches(session_id);
CREATE INDEX idx_enumeration_batches_status ON enumeration_batches(status);

-- Tasks Table
CREATE TABLE tasks (
    task_id VARCHAR PRIMARY KEY,
    source_type VARCHAR NOT NULL
);

-- Enumeration Tasks Table
CREATE TABLE enumeration_tasks (
    task_id VARCHAR PRIMARY KEY REFERENCES tasks(task_id),
    session_id VARCHAR(64) NOT NULL REFERENCES enumeration_session_states(session_id),
    resource_uri VARCHAR NOT NULL,
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
