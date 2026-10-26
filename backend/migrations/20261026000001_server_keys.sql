-- Per-user TFHE server (evaluation) keys. The key material itself lives in the
-- key store directory as <id>.bin; only metadata is kept here.
CREATE TABLE IF NOT EXISTS server_keys (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    sha256     TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_server_keys_user_id ON server_keys(user_id);

-- Jobs are evaluated with the submitting user's key. Older jobs have none.
ALTER TABLE jobs ADD COLUMN key_id TEXT REFERENCES server_keys(id) ON DELETE SET NULL;
