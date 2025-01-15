-- 0001_init_enumeration_schemas.down.sql

ALTER TABLE enumeration_session_metrics
  DROP CONSTRAINT IF EXISTS enumeration_session_metrics_session_id_fkey;

ALTER TABLE enumeration_batches
  DROP CONSTRAINT IF EXISTS enumeration_batches_session_id_fkey,
  DROP CONSTRAINT IF EXISTS enumeration_batches_checkpoint_id_fkey;

ALTER TABLE enumeration_tasks
  DROP CONSTRAINT IF EXISTS enumeration_tasks_session_id_fkey;

DROP INDEX IF EXISTS idx_enumeration_batches_session_id;
DROP INDEX IF EXISTS idx_enumeration_batches_status;

DROP TABLE IF EXISTS enumeration_session_metrics;
DROP TABLE IF EXISTS enumeration_batches;
DROP TABLE IF EXISTS enumeration_tasks;
DROP TABLE IF EXISTS tasks;

DROP TABLE IF EXISTS enumeration_session_states;
DROP TABLE IF EXISTS checkpoints;

DROP TYPE IF EXISTS enumeration_status;
DROP TYPE IF EXISTS batch_status;

DROP TABLE IF EXISTS scan_targets;
DROP TABLE IF EXISTS github_repositories;
DROP TABLE IF EXISTS urls;
