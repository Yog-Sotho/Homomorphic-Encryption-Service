# Plan — HEaaS from 4.0/10 (SOTA 3/10) to ≥ 9/10

## Context
The audit (`docs/project/codebase_audit.md`, pushed on `ccr-ea1e4a6d-o48ujy`) found:
- **The core promise is false.** The server generates and holds the TFHE client key (`backend/src/crypto/engine.rs:291`). The key pool rotates over unrelated key pairs, and keys are regenerated on every boot.
- **The UI is dead.** The meta CSP blocks SvelteKit's inline bootstrap (verified in Chromium), `vite dev` returns HTTP 500, and the OAuth/verify/reset fragments are never consumed.
- **Security gaps:** spoofable rate-limit IP, OAuth email-verification gaps, tokens in localStorage, raw `bincode` + `unchecked_*` ops on untrusted ciphertexts.
- **Hygiene:** no CI, 14 RustSec and 48 npm advisories, no observability, an in-memory job runner.

Decisions taken: **client-held keys (browser WASM + Rust SDK)**, **keep SQLite**, **replace the sandbox with the real browser flow**.

Target: every audit dimension ≥ 9 and no CRITICAL/HIGH findings left. The work is delivered as phased commits on `ccr-ea1e4a6d-o48ujy`, each phase green in CI before the next starts.

---

## Phase 0: Guard rails (do first)
1. **CI** in `.github/workflows/ci.yml`:
   - backend job: `cargo fmt --check`, `cargo clippy --all-targets -D warnings`, `cargo test`, `cargo deny check` (advisories, licenses, bans; new `backend/deny.toml`)
   - frontend job: `pnpm install --frozen-lockfile`, `svelte-check --fail-on-warnings`, `vitest`, `pnpm build`, Playwright e2e against `vite preview` with a mocked API
   - Docker build job; `hadolint`
   - Add `.github/dependabot.yml` covering cargo, npm, docker and actions.
2. **Dependency refresh**:
   - `cargo update` clears the transitive RustSec items (rustls, webpki, quinn-proto, h2, crossbeam-epoch, tokio ≥ 1.53.3).
   - Bump `tfhe` to 1.8.x with features `integer, zk-pok`. First confirm with `cargo doc` that the 1.8 names are still `CompressedServerKey`, `safe_serialization::{safe_serialize, safe_deserialize_conformant}`, `FheUint16` and `ProvenCompactCiphertextList`. Verified present in 1.3.3; must be re-checked on 1.8.
   - Remove `bincode`.
   - Standardise on rustls: sqlx `runtime-tokio-rustls`, lettre `tokio1-rustls-tls`. Trim sqlx features so the unused `sqlx-mysql`/`rsa` tree drops out, or document it in a `deny.toml` exception with justification.
   - Frontend: drop axios for `fetch`. Bump to `@sveltejs/kit` latest 2.x, `vite-plugin-svelte` 5/6, vite 6/7 (fixes the dev-server 500 and the npm advisories). Add `@types/node`, `vitest`, `@playwright/test`.

## Phase 1: Cryptographic core (CRITICAL)
New module layout under `backend/src/crypto/`:
- **`params.rs`**: a single source of truth (TFHE high-level `ConfigBuilder::default()` = TUniform 2^-128). It is exported to clients via `GET /api/v1/he/params`, which returns parameter id, tfhe version, max serialized sizes and supported ops.
- **`keys.rs`**: per-user key sets.
  - `POST /api/v1/keys` (multipart or octet-stream; body limit about 64 MB, configurable) accepts a client-generated `CompressedServerKey`.
  - The key is checked with `safe_deserialize_conformant` against the config's conformance params and a size limit.
  - It is stored at `${KEY_STORE_DIR}/{user_id}/{key_id}.bin` (written atomically: tmp, fsync, rename). The DB row is in a new table `server_keys(id, user_id, sha256, size, created_at, revoked_at)`.
  - Also: `GET /keys`, `DELETE /keys/{id}`, at most N keys per user.
  - Decompressed `ServerKey`s are held in a bounded LRU (`moka`), keyed by key_id and capped by memory weight.
- **`eval.rs`**: the evaluator, which replaces `engine.rs`.
  - Deserialize inputs with `safe_deserialize_conformant` (limit ~1 MB per ciphertext; accept `CompactCiphertextList`/`FheUint16`).
  - Run `tfhe::set_server_key` inside the worker thread for the job's key.
  - Ops: a typed `enum Op { Add, Sub, Mul, Min, Max, Eq, Lt, Sum(Vec) }` using carry-propagating default high-level operators (no `unchecked_*`).
  - Serialize the result with `safe_serialize`.
  - Fail on a block-count or parameter mismatch with a typed error.
- **Delete** `HeContextPool`, server-side `ClientKey`, `/compute/sandbox` and `sandbox_compute_optimized`.
- **Tests (the core of the 9/10 score)**:
  - Property tests (`proptest`, small case count, `#[ignore]`-gated heavy variants run in a nightly CI job): client keygen → encrypt → server eval with the uploaded compressed key → client decrypt equals the plaintext op mod 2^16, for every Op.
  - Negative tests: wrong-key ciphertext, truncated bytes, oversize, wrong params all return 4xx and never panic.

## Phase 2: Persistent, bounded job system (HIGH)
- New migration:
  - `jobs` gains `key_id`, `attempts`, `started_at`, `finished_at` and an index `(status, created_at)`.
  - Inputs and results move out of the DB into the blob store `${DATA_DIR}/jobs/{id}/{in0,in1,out}`; the DB keeps hashes and sizes.
- **`jobs/worker.rs`**:
  - N workers (`HE_WORKERS`, default = cores) claim jobs atomically with `UPDATE jobs SET status='processing', started_at=… WHERE id = (SELECT id FROM jobs WHERE status='pending' ORDER BY created_at LIMIT 1) RETURNING …`.
  - CPU work runs on a dedicated rayon pool behind a `Semaphore`.
  - Per-job timeout; retry with `attempts < 3`.
  - At startup, stale `processing` jobs are requeued.
  - Workers drain on SIGTERM via an actix `ServerHandle` plus a `CancellationToken`.
- **API (v1)**:
  - `POST /api/v1/jobs` takes `{key_id, op, inputs: [b64…]}` as JSON or multipart. It returns `202` + `Location`, honours the `Idempotency-Key` header, and returns 503 + `Retry-After` when the queue is full.
  - `GET /api/v1/jobs?cursor=&limit=` returns a summary DTO (no blobs, no `user_id`).
  - `GET /api/v1/jobs/{id}` returns status.
  - `GET /api/v1/jobs/{id}/result` returns the ciphertext as octet-stream.
  - `DELETE /api/v1/jobs/{id}`.
- **Quota**: charged only on `POST /jobs`, keeping the existing atomic `INSERT … ON CONFLICT … RETURNING` from `middleware/quota.rs`. A DB error returns 503, not 429.

## Phase 3: Auth & web security (HIGH/MEDIUM)
- **Rate limiting**:
  - Replace `middleware/rate_limit.rs` with the `governor` crate, keyed on `peer_addr()`. A `TRUSTED_PROXIES` CIDR list enables the rightmost-untrusted `X-Forwarded-For` hop.
  - Add a per-email login limiter, stricter limits for email-sending routes, and `Retry-After`/`RateLimit-*` headers.
  - Compose: the backend is no longer published on `0.0.0.0`; only nginx exposes ports.
- **Sessions**:
  - The refresh token moves to an `HttpOnly; Secure; SameSite=Strict; Path=/api/v1/auth` cookie, and the access token stays in memory on the frontend.
  - Refresh rotation runs in a transaction with `family_id`; reuse of a rotated token revokes the family (migration adds `family_id`, `rotated_at`).
  - CSRF: SameSite=Strict, plus an `Origin` check middleware for cookie-authenticated POSTs.
- **JWT**:
  - Claims gain `iss`, `aud`, `typ`, `iat`, `jti`; validation pins the alg, `aud` and `iss`.
  - The OAuth state uses a separate HMAC key derived via HKDF from `JWT_SECRET`.
  - At boot, `JWT_SECRET` must be at least 32 bytes.
- **OAuth**:
  - Random state + PKCE verifier stored in a 10-minute `HttpOnly` cookie and compared on callback.
  - Google: OIDC `id_token` checked for `email_verified == true` (or v3 userinfo `email_verified`).
  - GitHub: always use `/user/emails` with `primary && verified`.
  - Callbacks issue a **one-time login code** (DB row, 60 s TTL, hashed) in the redirect. The frontend POSTs it to `/auth/exchange`, so tokens no longer appear in URLs.
  - One shared `reqwest::Client` with timeouts, and the provider HTTP status is checked.
- **Verify / reset**:
  - The email links land on frontend pages, which POST the token. Verify no longer runs on GET, so link scanners can't consume it.
  - The reset token is consumed atomically with `UPDATE … RETURNING`.
  - Remove the legacy plaintext-token matching.
  - Mail URLs are logged only in debug builds.
- **Account management**: account delete and password reset run in transactions. OAuth-only accounts require recent auth (`auth_time` ≤ 5 min) to delete.
- **Headers**: actix `DefaultHeaders` (nosniff, `frame-ancestors 'none'`, Referrer-Policy, COOP/CORP), with CORS restricted to explicit methods and headers. nginx gets a TLS server block with HSTS and drops `X-XSS-Protection`.

## Phase 4: Frontend rebuild (CRITICAL/HIGH)
- **`svelte.config.js`**: `adapter-node`, `paths.base: '/heaas'`, `kit.csp: { mode: 'hash', directives: {script-src:['self','wasm-unsafe-eval'], …} }`. Remove the meta CSP from `app.html` and self-host the fonts.
- **`$lib/api.ts`**: a typed `fetch` client with `credentials: 'include'`, an in-memory access token, single-flight refresh, and typed `ApiError {code,message}`.
- **`$lib/fhe/`**: a lazy-loaded `tfhe` WASM worker (npm `tfhe`, version matched to the backend crate).
  - Keygen, encrypt and decrypt run in a Web Worker so the UI never blocks.
  - The client key is stored in IndexedDB, encrypted with AES-GCM using a key from PBKDF2/Argon2 (WebCrypto) over a user passphrase.
  - Export/import of the key file.
  - The compressed server key is uploaded to `POST /keys`.
- **Pages**:
  - `/login`: consumes `#code=` → `/auth/exchange`, `#error=`. Adds OAuth buttons, forgot password, and resend verification.
  - `/verify` and `/reset`: landing pages that POST the token.
  - `/keys`: generate/import/export/revoke keys.
  - `/dashboard`: encrypt locally → submit job → poll → decrypt locally. Shows only ciphertext sizes and the honest scheme label ("TFHE (CGGI), FheUint16").
  - `/jobs`: paginated history.
  - `/account`: existing page, kept.
- Migrate to Svelte 5 runes. Share one `$lib/password-policy.ts` (removes the 3× duplication).
- **Tests**: vitest for the api client and policy; Playwright e2e for register → verify → keygen → add job → decrypt correct, CSP-violation listener = 0, and a11y with `@axe-core/playwright`.

## Phase 5: Code structure & API quality (MEDIUM)
- Split `api/auth.rs` (1,413 lines) into `auth/{password,session,email,oauth/{mod,google,github}}.rs`.
- One `Mailer` (built at startup, `web::Data`) with templated bodies (removes the duplication at `auth.rs:139-264`).
- `const USER_COLUMNS` or a `UserRepo`. `#[derive(FromRow)]` structs replace tuple rows (fixes clippy `type_complexity` at `user.rs:54`).
- Error envelope `{error:{code,message,details?}}` plus a `JsonConfig`/`QueryConfig` error handler that returns JSON 400/422/413.
- Typed `Config` built with `envy` or a validated struct: every limit (rate limits, payload sizes, TTLs, quota, workers) becomes configurable, and the server fails fast on invalid values. Remove the personal Tailscale URL default.
- Routes are versioned under `/api/v1`. An OpenAPI spec is generated with `utoipa` and served at `/api/v1/openapi.json`; CI checks it has not drifted.
- **Rust SDK/CLI crate**: `sdk/` (workspace member `heaas-sdk` + `heaas` CLI) with keygen, upload-key, encrypt, submit, wait, decrypt. It reuses `crypto/params.rs`, which moves to a shared `heaas-core` crate so the SDK and server can never disagree on parameters. The workspace root `Cargo.toml` lists `backend`, `core` and `sdk`.

## Phase 6: Observability & lifecycle (MEDIUM)
- `tracing` + `tracing-subscriber` (JSON) + `tracing-actix-web` (request id, propagated as `X-Request-Id`); replace `env_logger`/`log`.
- Prometheus `/metrics` (actix-web-prom + custom counters/histograms for job latency, queue depth, HE op duration, key-cache hits), protected by a bearer token or an internal bind.
- `/api/health` for liveness; `/api/health/ready` checks a DB ping, write access to the key store, and worker liveness.
- Graceful shutdown: stop accepting work, drain workers (timeout), close the pool.
- **Docker**:
  - Multi-stage `cargo-chef` builder; `debian:bookworm-slim` or distroless runtime; non-root user; `HEALTHCHECK`; `.dockerignore`; pinned base tags.
  - Frontend `Dockerfile` (adapter-node, non-root).
  - Compose with `service_healthy`, `read_only`, `cap_drop: [ALL]`, `no-new-privileges`, and named volumes for the DB/keys/blobs.
  - `backup.sh` also backs up the key/blob store.

## Phase 7: Cleanup & honest docs (LOW but blocks 9/10)
- Delete `backend/src/db/schema.sql` and `foldertree.txt`; merge `.Jules/` into `.jules/`.
- Rewrite `README.md` (architecture diagram, threat model: what the server can and cannot learn, parameter sheet generated from `params.rs`, quick start, SDK usage) and `Customer_guide.md`. Remove SEAL/BFV, "n=4096, t=1024", billing and audit claims.
- Add `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`.
- Re-run the codebase-auditor and append the new row to `docs/project/.audit/results_log.md`.

---

## Critical files
- **Replace or remove**: `backend/src/crypto/engine.rs`, `backend/src/api/compute.rs`, `backend/src/middleware/rate_limit.rs`, `frontend/src/app.html`, `frontend/src/lib/api.ts`
- **Major edits**: `backend/src/main.rs`, `backend/src/api/auth.rs` (split), `backend/src/api/user.rs`, `backend/src/config.rs`, `backend/src/errors.rs`, `backend/src/middleware/{jwt,quota}.rs`, `backend/Cargo.toml`, `frontend/svelte.config.js`, `frontend/package.json`, all `frontend/src/routes/**`, `Dockerfile`, `docker-compose.yml`, `nginx-heaas.conf`, `README.md`, `Customer_guide.md`
- **New**: `backend/migrations/2026102500000{1..4}_*.sql` (server_keys, jobs v2, refresh families, login codes), `backend/src/crypto/{params,keys,eval}.rs`, `backend/src/jobs/worker.rs`, `core/`, `sdk/`, `frontend/src/lib/fhe/`, `.github/workflows/ci.yml`, `backend/deny.toml`
- **Reuse**:
  - `hash_token` (`auth.rs:17`)
  - atomic quota SQL (`middleware/quota.rs:443`)
  - the OAuth takeover guard and its test (`auth.rs:853-873, 1263`)
  - `is_valid_email` / `is_strong_password` (`api/validation.rs`)
  - the `spawn_blocking` pattern for bcrypt

## Verification
1. **Every phase**: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test && cargo deny check`, plus `pnpm svelte-check && pnpm test && pnpm build && pnpm exec playwright test`. CI must be green before the push.
2. **Crypto correctness**: an end-to-end Rust integration test using `actix_web::test` with an in-memory SQLite and temp dirs.
   - Flow: SDK keygen → upload compressed key → submit job per Op → worker → fetch result → decrypt equals expected.
   - Negative cases: wrong key, malformed, oversize and foreign-params inputs give 4xx and the process never panics.
   - Restart test: kill the server mid-job, restart, and the job completes.
3. **Security regression tests**:
   - Spoofed `X-Forwarded-For` doesn't bypass the limiter.
   - Google `email_verified=false` is rejected (provider responses mocked with `wiremock`).
   - Refresh reuse revokes the family.
   - The OAuth state cookie mismatch is rejected.
   - Verify via GET has no side effect.
   - `list_jobs` contains no blobs and no `user_id`.
   - Polling doesn't consume quota.
4. **Browser**:
   - Playwright against `docker compose up`: zero CSP violations, the full register → keygen → encrypt → job → decrypt flow, and OAuth with mocked providers.
   - Check that the network tab never carries the client key (assert no request body contains the serialized client-key prefix).
5. **Supply chain**: `cargo audit` / `cargo deny` and `pnpm audit --prod` return 0 high/critical.
6. **Final audit**: re-run the codebase-auditor skill. Pass criteria: every dimension ≥ 9, no CRITICAL/HIGH findings, the report and log updated, and a SOTA re-score ≥ 9.

## Delivery
One commit (or a small series) per phase, pushed to `ccr-ea1e4a6d-o48ujy`. No PR unless asked. The TFHE heavy property tests run as a nightly/`workflow_dispatch` job, because keygen takes 10–60 s per key.
