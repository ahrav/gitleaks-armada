-- 0003_init_scanning_schemas.down.sql

DROP TABLE IF EXISTS scan_tasks;
DROP TYPE IF EXISTS scan_task_status;
DROP TABLE IF EXISTS scan_jobs;
DROP TYPE IF EXISTS scan_job_status;
DROP TABLE IF EXISTS scan_job_targets;
