-- Add composite index to jobs table for faster list_jobs and account deletion
CREATE INDEX IF NOT EXISTS idx_jobs_user_id_created_at ON jobs(user_id, created_at DESC);
