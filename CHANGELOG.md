# Changelog

All notable changes to the Homomorphic Encryption Engine (HE Engine, formerly
HEaaS). The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/) (before 1.0, minor versions may break
compatibility).

## [Unreleased]

### Added
- **More types.** Jobs compute on `u8`, `u16`, `u32`, `u64` and `i8`, `i16`, `i32`,
  `i64` (`integer_type` in the request, `u16` if absent).
- **More operations.** The comparisons `eq`, `ne`, `lt`, `le`, `gt`, `ge` (an
  encrypted boolean result), and `sum` of 2 to 16 inputs. Jobs report a
  `result_type` to decrypt as.
- **Plain operands.** Binary operations can take their right-hand side as a
  decimal `scalar` the server sees, instead of a ciphertext.
- **Proven inputs.** `proven_inputs`: one TFHE-rs `ProvenCompactCiphertextList`
  with a zero-knowledge proof of well-formed encryption, checked against the
  key's public key (`PUT /api/v1/keys/{id}/public-key`) and a CRS the server
  generates and serves (`GET /api/v1/he/crs`). Proofs are bound to the key id.
- The dashboard, the SDK and the `heaas` CLI support all of the above (`heaas run
  --type i32 --scalar 5 --prove …`, `heaas prove`); keys are generated with a
  public key, which `heaas keygen` saves as `heaas-public.key`.
- Property tests (homomorphic results against the plaintext oracle, corrupted
  keys, ciphertexts and proven lists), a scheduled workflow for the heavy ones,
  and coverage floors in CI (Rust and frontend).

### Changed
- New keys are made with Zama's dedicated compact-public-key parameters on top of
  `ConfigBuilder::default()`. Keys made before are still accepted, but cannot take
  proven inputs.
- Results that TFHE-rs leaves partly unencrypted because a plain operand makes
  them known (e.g. `x * 0`) are re-encrypted, so every result is a conformant
  ciphertext.
- Renamed to **Homomorphic Encryption Engine** (HE Engine), formerly HEaaS, and
  described as what it is: a self-hosted server whose operator runs it for its
  users, not a hosted service. New banner, logo and wording in the app, emails,
  API description and documentation. Code names (`he-backend`, `heaas-core`,
  `heaas-sdk`, the `heaas` CLI, environment variables, metric and cookie names)
  are unchanged.

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
