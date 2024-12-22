-- 000001_init_schema.down.sql

ALTER TABLE enumeration_states
  DROP CONSTRAINT IF EXISTS fk_last_checkpoint;

DROP TABLE IF EXISTS enumeration_states;
DROP TABLE IF EXISTS checkpoints;
DROP TYPE IF EXISTS enumeration_status;
