# Changelog

All notable changes to HEaaS. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/) (before 1.0, minor versions may break
compatibility).

## [0.4.0] - 2026-10-28

A rebuild after the audit in `docs/project/codebase_audit.md`, delivered in
phases (PRs #100, #114, #119, #120, #121, #122, #129 and this release). Earlier
history is in git.

### Security
- **The server no longer holds secret keys.** Clients generate their TFHE key
  pair (in the browser through TFHE-rs's WebAssembly build, or with the Rust
  SDK) and upload only the compressed server key. The server-side key pool,
  its client keys and the plaintext "sandbox" endpoint are gone.
- Uploaded keys and ciphertexts are checked with size-limited, conformance-
  checked deserialization; homomorphic operations use carry-propagating
  operators.
- Sessions: short-lived access tokens kept in memory, rotating refresh tokens
  in an `HttpOnly; Secure; SameSite=Strict` cookie, reuse detection that
  revokes the session family, `Origin` checks, JWTs with pinned algorithm,
  issuer, audience and type, keys derived per purpose from `JWT_SECRET`.
- OAuth: PKCE and a signed state cookie, provider-verified emails only,
  one-time login codes instead of tokens in URLs, the pre-registration
  takeover guard kept and tested.
- Email links land on frontend pages and are redeemed by POST, once.
- Rate limits keyed on the real client IP (trusted-proxy aware), per account
  and per email address.
- Client keys in the browser are sealed with AES-256-GCM under a
  PBKDF2-SHA256 (600,000 iterations) passphrase key, with encrypted backups.
- A strict CSP with hashed inline scripts, cross-origin isolation, and
  security headers on every API response.
- All RustSec and npm advisories open at the audit are fixed; `cargo deny`
  and `pnpm audit` run in CI.

### Added
- Durable job queue in SQLite with a bounded worker pool, per-job timeouts,
  retries with backoff, idempotent submissions, back-pressure (`429`/`503`
  with `Retry-After`), cursor pagination, and requeueing after a restart.
- Per-user server keys (`/api/v1/keys`) with a decompressed-key cache.
- `heaas-core`, `heaas-sdk` and the `heaas` CLI.
- OpenAPI 3.1 document generated from the handlers, committed and
  drift-checked, at `/api/v1/openapi.json`.
- One error envelope, `{"error":{"code","message"}}`, for every error.
- Structured JSON logs with request ids, Prometheus metrics, readiness probe,
  `he-backend healthcheck` and `he-backend backup`.
- Dashboard pages for keys and jobs, accessibility tests (axe, WCAG 2.2 AA),
  and a full-stack browser test against the real backend.
- `docs/parameters.md`, generated from the code; `SECURITY.md`,
  `CONTRIBUTING.md`, this changelog.
- A new banner, logo and diagrams, a dashboard screenshot, a short README and
  separate guides in `docs/`: user guide (formerly `Customer_guide.md`),
  how it works, API, self-hosting.
- A new banner, logo and diagrams, a dashboard screenshot, a short README and
  separate guides in `docs/`: user guide (formerly `Customer_guide.md`),
  how it works, API, self-hosting.

### Changed
- The API moved to `/api/v1`. `/api/...` still answers, with `Deprecation`
  and `Link: rel="successor-version"` headers.
- Configuration is validated at startup: every invalid value is reported and
  the server exits with status 2. `APP_BASE_URL` is required in production.
- The Rust code is one Cargo workspace (`backend`, `core`, `sdk`).
- Docker: a distroless, non-root backend image and a production frontend
  image. Compose runs both with read-only roots and no capabilities, and keeps
  state in the `heaas-data` volume.

### Fixed
- SMTP used implicit TLS on port 587, which fails against standard
  submission servers; `SMTP_TLS` now selects STARTTLS by default.
- The dashboard was unusable: the CSP blocked SvelteKit's bootstrap and the
  dev server failed. Login, verification and reset links now work.
- Quota is charged only for accepted jobs, and a database error is `503`, not
  `429`.

### Removed
- The SEAL/BFV claims and other descriptions of features that did not exist.
- `axios`, `bincode`, `backend/src/db/schema.sql`, `foldertree.txt`,
  `backend/examples/client.rs` (replaced by the SDK and CLI).

### Upgrading
- Users sign in again once (the refresh cookie moved to `/api/v1/auth`).
- Register `<APP_BASE_URL>/api/v1/auth/{google,github}/callback` with the
  OAuth providers.
- Docker: copy `./data` into the `heaas-data` volume once (docs/self-hosting.md, "Backups").
- Server-generated keys from before the rebuild cannot be used; users create
  a key in the dashboard or with `heaas keygen`.
