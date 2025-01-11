-- 0002_init_rules_schemas.down.sql

-- Drop the tables in reverse order of creation
DROP TABLE IF EXISTS findings;
DROP TABLE IF EXISTS allowlist_stopwords;
DROP TABLE IF EXISTS allowlist_regexes;
DROP TABLE IF EXISTS allowlist_paths;
DROP TABLE IF EXISTS allowlist_commits;
DROP TABLE IF EXISTS allowlists;
DROP TABLE IF EXISTS rules;
