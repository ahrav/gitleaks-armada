-- 0001_init_enumeration_schemas.down.sql

-- 1. Drop foreign key constraints on child tables
ALTER TABLE enumeration_session_metrics
  DROP CONSTRAINT IF EXISTS enumeration_session_metrics_session_id_fkey;

ALTER TABLE enumeration_batches
  DROP CONSTRAINT IF EXISTS enumeration_batches_session_id_fkey,
  DROP CONSTRAINT IF EXISTS enumeration_batches_checkpoint_id_fkey;

ALTER TABLE enumeration_tasks
  DROP CONSTRAINT IF EXISTS enumeration_tasks_session_id_fkey;

-- 2. Drop indexes (if any were explicitly created)
DROP INDEX IF EXISTS idx_enumeration_batches_session_id;
DROP INDEX IF EXISTS idx_enumeration_batches_status;

-- 3. Drop child tables first
DROP TABLE IF EXISTS enumeration_session_metrics;
DROP TABLE IF EXISTS enumeration_batches;
DROP TABLE IF EXISTS enumeration_tasks;
DROP TABLE IF EXISTS tasks;

-- 4. Drop parent tables
DROP TABLE IF EXISTS enumeration_session_states;
DROP TABLE IF EXISTS checkpoints;

-- 5. Drop types last
DROP TYPE IF EXISTS enumeration_status;
DROP TYPE IF EXISTS batch_status;
