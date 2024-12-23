-- 000001_init_schema.up.sql

-- 1. Define the enumeration_status enum
CREATE TYPE enumeration_status AS ENUM (
    'initialized',
    'in_progress',
    'completed',
    'failed'
);

-- 2. Create checkpoints table
CREATE TABLE checkpoints (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    target_id TEXT NOT NULL UNIQUE,
    data JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 3. Create enumeration_states table
CREATE TABLE enumeration_states (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    session_id TEXT NOT NULL,
    source_type TEXT NOT NULL,
    config JSONB NOT NULL,
    last_checkpoint_id BIGINT,
    status enumeration_status NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 4. Add a foreign key constraint on enumeration_states referencing checkpoints
ALTER TABLE enumeration_states
  ADD CONSTRAINT fk_last_checkpoint
  FOREIGN KEY (last_checkpoint_id)
  REFERENCES checkpoints (id);
