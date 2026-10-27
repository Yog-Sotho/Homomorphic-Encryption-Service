-- Durable job queue. Job inputs and results move to the job store directory
-- (<JOB_STORE_DIR>/<job id>/{in0,in1,out}); rows keep only metadata.
ALTER TABLE jobs ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE jobs ADD COLUMN started_at DATETIME;
ALTER TABLE jobs ADD COLUMN finished_at DATETIME;
-- Earliest time a retried job may run again (exponential backoff).
ALTER TABLE jobs ADD COLUMN not_before DATETIME;
ALTER TABLE jobs ADD COLUMN input_bytes INTEGER;
ALTER TABLE jobs ADD COLUMN result_bytes INTEGER;
-- Client-supplied Idempotency-Key and a hash of the request it was used with.
ALTER TABLE jobs ADD COLUMN idempotency_key TEXT;
ALTER TABLE jobs ADD COLUMN request_sha256 TEXT;

-- Workers claim the oldest runnable pending job.
CREATE INDEX IF NOT EXISTS idx_jobs_status_created ON jobs(status, created_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_jobs_user_idempotency
    ON jobs(user_id, idempotency_key) WHERE idempotency_key IS NOT NULL;

-- Jobs queued by the previous in-memory runner have no stored inputs and were
-- lost when it stopped; close them out instead of leaving them pending forever.
UPDATE jobs
SET status = 'failed',
    error_message = 'Interrupted by a server upgrade; please resubmit',
    finished_at = CURRENT_TIMESTAMP,
    updated_at = CURRENT_TIMESTAMP
WHERE status IN ('pending', 'processing');
