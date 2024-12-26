-- 0002_add_scanning_tables.down.sql

-- Drop the tables in reverse order of creation

DROP TABLE IF EXISTS findings;

DROP TABLE IF EXISTS allowlist_stopwords;
DROP TABLE IF EXISTS allowlist_regexes;
DROP TABLE IF EXISTS allowlist_paths;
DROP TABLE IF EXISTS allowlist_commits;
DROP TABLE IF EXISTS allowlists;

DROP TABLE IF EXISTS rules;
DROP TABLE IF EXISTS scan_jobs;
DROP TABLE IF EXISTS scan_targets;
DROP TABLE IF EXISTS github_repositories;
DROP TABLE IF EXISTS target_types;

DROP TABLE IF EXISTS scan_job_status;
