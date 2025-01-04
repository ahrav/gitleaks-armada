-- 000001_init_schema.down.sql

-- Drop foreign key constraints first
ALTER TABLE enumeration_session_states
  DROP CONSTRAINT IF EXISTS fk_last_checkpoint;

ALTER TABLE enumeration_progress
  DROP CONSTRAINT IF EXISTS enumeration_progress_session_id_fkey;

ALTER TABLE enumeration_batch_progress
  DROP CONSTRAINT IF EXISTS enumeration_batch_progress_session_id_fkey,
  DROP CONSTRAINT IF EXISTS enumeration_batch_progress_checkpoint_id_fkey;

-- Drop tables in correct order (child tables first)
DROP TABLE IF EXISTS enumeration_batch_progress;
DROP TABLE IF EXISTS enumeration_progress;
DROP TABLE IF EXISTS enumeration_session_states;
DROP TABLE IF EXISTS checkpoints;

-- Drop types last
DROP TYPE IF EXISTS enumeration_status;
DROP TYPE IF EXISTS batch_status;
