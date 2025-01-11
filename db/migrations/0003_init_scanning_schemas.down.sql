-- 0003_init_scanning_schemas.down.sql

-- 1. Drop table that references the type
DROP TABLE IF EXISTS scan_jobs;

-- 2. Drop the enum type AFTER dropping scan_jobs
DROP TYPE IF EXISTS scan_job_status;

-- 3. Drop remaining tables
DROP TABLE IF EXISTS scan_targets;
DROP TABLE IF EXISTS github_repositories;
