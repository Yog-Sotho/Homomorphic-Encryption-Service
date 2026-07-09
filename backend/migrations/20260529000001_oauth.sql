CREATE TABLE IF NOT EXISTS oauth_accounts (
    id           TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider     TEXT NOT NULL CHECK(provider IN ('google', 'github')),
    provider_id  TEXT NOT NULL,
    provider_email TEXT,
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (provider, provider_id)
);
