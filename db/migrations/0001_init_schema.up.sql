-- 000001_init_schema.up.sql

-- 1. Define the enumeration_status enum
CREATE TYPE enumeration_status AS ENUM (
    'INITIALIZED',
    'IN_PROGRESS',
    'COMPLETED',
    'FAILED',
    'STALLED',
    'PARTIALLY_COMPLETED'
);

-- 2. Create batch_status enum
CREATE TYPE batch_status AS ENUM (
    'SUCCEEDED',
    'FAILED',
    'PARTIALLY_COMPLETED'
);

-- 3. Create checkpoints table
CREATE TABLE checkpoints (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    target_id VARCHAR(512) NOT NULL UNIQUE,
    data JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 4. Create enumeration_session_states table
CREATE TABLE enumeration_session_states (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    session_id VARCHAR(64) NOT NULL,
    source_type VARCHAR(32) NOT NULL,
    config JSONB NOT NULL,
    last_checkpoint_id BIGINT REFERENCES checkpoints(id),
    status enumeration_status NOT NULL,
    failure_reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_enumeration_session_id UNIQUE (session_id)
);

-- 5. Tasks Table
CREATE TABLE tasks (
    task_id VARCHAR PRIMARY KEY,
    source_type VARCHAR NOT NULL
);

-- 6. Enumeration Tasks Table
CREATE TABLE enumeration_tasks (
    task_id VARCHAR PRIMARY KEY REFERENCES tasks(task_id),
    session_id VARCHAR(64) NOT NULL REFERENCES enumeration_session_states(session_id),
    resource_uri VARCHAR NOT NULL,
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 7. Add new progress tables
CREATE TABLE enumeration_progress (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    session_id VARCHAR(64) NOT NULL REFERENCES enumeration_session_states(session_id),
    started_at TIMESTAMPTZ NOT NULL,
    items_found INTEGER NOT NULL DEFAULT 0,
    items_processed INTEGER NOT NULL DEFAULT 0,
    failed_batches INTEGER NOT NULL DEFAULT 0,
    total_batches INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_session_progress UNIQUE (session_id)
);

CREATE TABLE enumeration_batch_progress (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    batch_id VARCHAR(64) NOT NULL UNIQUE,
    session_id VARCHAR(64) NOT NULL REFERENCES enumeration_session_states(session_id),
    status batch_status NOT NULL,
    started_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ NOT NULL,
    items_processed INTEGER NOT NULL DEFAULT 0,
    error_details TEXT,
    checkpoint_id BIGINT REFERENCES checkpoints(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 8. Add indexes
CREATE INDEX idx_batch_progress_session_id ON enumeration_batch_progress(session_id);
CREATE INDEX idx_batch_progress_status ON enumeration_batch_progress(status);
