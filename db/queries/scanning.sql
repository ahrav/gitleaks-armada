-- Scanning Domain Queries

-- name: CreateJob :exec
INSERT INTO scan_jobs (
    job_id,
    status,
    start_time,
    end_time
) VALUES (
    $1, -- job_id UUID
    $2, -- status scan_job_status
    $3, -- start_time TIMESTAMPTZ
    $4  -- end_time TIMESTAMPTZ
);

-- name: UpdateJob :exec
UPDATE scan_jobs
SET
    status = $2,
    start_time = $3,
    end_time = $4,
    updated_at = NOW()
WHERE job_id = $1;

-- name: AssociateTarget :exec
INSERT INTO scan_job_targets (
    job_id,
    scan_target_id
) VALUES (
    $1, -- job_id UUID
    $2  -- scan_target_id UUID
);

-- name: BulkAssociateTargets :copyfrom
INSERT INTO scan_job_targets (
    job_id,
    scan_target_id
) VALUES ($1, $2);

-- name: GetJob :many
SELECT
    j.job_id,
    j.status,
    j.start_time,
    j.end_time,
    j.updated_at,
    t.scan_target_id
FROM scan_jobs j
LEFT JOIN scan_job_targets t ON j.job_id = t.job_id
WHERE j.job_id = $1;
