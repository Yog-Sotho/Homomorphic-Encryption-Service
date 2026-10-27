-- Refresh-token rotation with reuse detection. Every sign-in starts a family;
-- each refresh marks the presented token rotated and issues its successor in the
-- same family. Presenting a rotated token again (after a short grace period for
-- concurrent tabs) means it was copied, so the whole family is revoked.
ALTER TABLE refresh_tokens ADD COLUMN family_id TEXT;
ALTER TABLE refresh_tokens ADD COLUMN rotated_at DATETIME;
-- When the user last proved who they are (password, email link or OAuth).
-- Carried through rotations; sensitive actions require a recent one.
ALTER TABLE refresh_tokens ADD COLUMN authenticated_at DATETIME;
UPDATE refresh_tokens SET family_id = id, authenticated_at = created_at WHERE family_id IS NULL;
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_family ON refresh_tokens(family_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires ON refresh_tokens(expires_at);

-- One-time codes that hand an OAuth sign-in from the provider callback to the
-- frontend without putting tokens in a URL. Stored hashed, valid for a minute.
CREATE TABLE IF NOT EXISTS login_codes (
    code_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_login_codes_expires ON login_codes(expires_at);

ALTER TABLE users ADD COLUMN email_verify_expires_at DATETIME;

-- Tokens are now only ever looked up by their SHA-256 (64 hex characters).
-- Older rows stored some tokens in plain text; those links stop working, and
-- users can request new ones.
UPDATE users SET email_verify_token = NULL
WHERE email_verify_token IS NOT NULL AND length(email_verify_token) != 64;
UPDATE users SET password_reset_token = NULL, password_reset_expires_at = NULL
WHERE password_reset_token IS NOT NULL AND length(password_reset_token) != 64;
UPDATE users SET email_verify_expires_at = datetime('now', '+24 hours')
WHERE email_verify_token IS NOT NULL;
