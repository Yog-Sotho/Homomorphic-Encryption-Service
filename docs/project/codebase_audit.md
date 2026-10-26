# Codebase Audit Report

**Date:** 2026-10-25
**Project:** HEaaS — Homomorphic Encryption-as-a-Service (`he-backend` 0.3.0, `he-frontend` 0.3.0)
**Language / Framework:** Rust 2021 (actix-web 4.13, sqlx 0.8 / SQLite, TFHE-rs 1.3.3) · SvelteKit 2.60 / Svelte 5.55 / Vite 6 (TypeScript)
**Project Type:** Web Service (all 9 dimensions applicable)
**Audit Mode:** Domain-aware (`backend/`, `frontend/`, deployment files)

Every finding below was checked against the source, the tool output, or the vendored crate source. Nothing in it is inferred from names or docs.

---

## Executive Summary

The service's main promise is broken. The backend generates **both** TFHE keys in-process (`crypto/engine.rs:291`) and keeps the client (secret) key in memory. No endpoint exists for a client to supply its own key. The README and Customer Guide promise "local key generation", "we never receive your private key" and a "mathematical guarantee", and the code does none of that: the operator can decrypt everything. On top of that, keys are regenerated on every restart and the job path picks a random slot from a pool of *different* key pairs. So with the default `HE_POOL_SIZE=2`, a submitted ciphertext is evaluated under the wrong server key about half the time.

The web UI is also non-functional as shipped. The `<meta>` CSP blocks SvelteKit's inline bootstrap script, so the production build never hydrates (verified in Chromium). The dev server that `docker-compose` actually runs answers `GET /login` with HTTP 500. The OAuth, email-verification and password-reset flows hand tokens back via URL fragments that no frontend code ever reads.

On the positive side, the Rust backend compiles cleanly (1 clippy warning) and uses parameterised SQL everywhere. It already defends against several classic auth attacks: generic login errors, a dummy bcrypt run on unknown users, hashed single-use tokens, and protection against OAuth takeover of pre-registered accounts.

**Top priority:** move key ownership to the client. Clients generate keys and upload a server/compression key, the server evaluates with *their* key only, and it uses `safe_deserialize_conformant` plus carry-propagating operations. Then fix the frontend CSP and token flows.

## Overall Score: 4.0 / 10  (raw average 4.2, capped at 4.0 because of CRITICAL security findings)

| Dimension | Score | Priority | Status |
|---|---|---|---|
| Security | 2/10 | CRITICAL | FAIL |
| Build & Types | 4/10 | CRITICAL | FAIL |
| Code Principles | 5/10 | HIGH | WARN |
| Code Quality | 5/10 | MEDIUM | WARN |
| Dependencies | 4/10 | MEDIUM | FAIL |
| Dead Code | 6/10 | LOW | WARN |
| Observability | 3/10 | MEDIUM | FAIL |
| Concurrency | 4/10 | HIGH | FAIL |
| Lifecycle | 5/10 | MEDIUM | WARN |

**SOTA rating (vs. state-of-the-art FHE services such as Zama's TFHE-rs / Concrete / fhEVM tooling, OpenFHE-based services): 3 / 10.**
Today it is a TFHE demo with server-side keys behind a standard auth stack. It has no client-side keys, no compressed/serialisable server keys, no conformance-checked deserialisation, no carry-safe or composable operations, no persistent job queue, no SDK, no CI, and the README documents a different scheme (SEAL/BFV, n=4096, t=1024) from the one in the code.

---

## Verification performed

| Check | Result |
|---|---|
| `cargo build --locked` | ✅ success (3m44s) |
| `cargo clippy --all-targets` | 1 warning (`type_complexity`, `api/user.rs:54`) |
| `cargo test --locked` | ✅ 6/6 pass. They cover input-length checks, validators and OAuth takeover. **0 tests exercise HE correctness or any HTTP route** |
| `cargo audit` (RustSec DB as of today, 410 crates) | ❌ **14 vulnerabilities, 7 warnings** (rustls ×4, rustls-webpki, webpki-roots, quinn-proto ×5, h2, crossbeam-epoch, rsa (Marvin; transitive, no fix), tokio 1.52.3 unsound RUSTSEC-2026-0386, bincode 1.x unmaintained RUSTSEC-2025-0141, paste unmaintained, anyhow, event-listener) |
| `pnpm audit` | ❌ **48 vulnerabilities (19 high, 24 moderate, 5 low)**: axios (21), devalue (8), vite (5), @sveltejs/kit (5), nanoid, postcss, follow-redirects, form-data, source-map-js, cookie |
| `svelte-check` | 1 error (`vite.config.ts:13` `process` untyped, `@types/node` missing), 2 warnings |
| `pnpm build` + Chromium (Playwright) | ❌ `Executing inline script violates … 'script-src 'self''`. Page never hydrates; the Register toggle does nothing. The Google Fonts stylesheet is also blocked by CSP |
| `vite dev` (what docker-compose runs) + Chromium | ❌ `GET /login` → **HTTP 500** `TypeError: css is not a function` (from SvelteKit's `render.js`; root cause not isolated, likely svelte 5.55 / vite-plugin-svelte 4.0.4 mismatch) |
| TFHE-rs 1.3.3 source | `PARAM_MESSAGE_2_CARRY_2_KS_PBS` = `…TUNIFORM_2M128` (OK). `unchecked_add` / `unchecked_mul` never propagate carries. `safe_deserialize_conformant`, `add_parallelized` and `mul_parallelized` are available. Latest stable tfhe on crates.io: **1.8.2** |
| actix-web 4.13 source | `realip_remote_addr()` docs: only safe if a proxy guarantees that `Forwarded`/`X-Forwarded-For` cannot be spoofed |

---

## Strengths

1. **Parameterised SQL everywhere.** Every query uses `?` binds and there is no string-built SQL. Migrations are versioned, FK enforcement is on, and WAL mode is enabled.
2. **Several auth threats are already handled:** generic `Invalid credentials`, a dummy bcrypt verify against timing-based enumeration, register returns 202 for duplicate emails, verify/reset/refresh tokens stored as SHA-256 hashes, refresh rotation, sessions revoked on password change/reset, and a regression test for OAuth pre-registration takeover.
3. **CPU-heavy work stays off the async executor.** bcrypt and TFHE run under `spawn_blocking`, and keygen is parallelised.
4. **Atomic quota.** The daily quota uses a single `INSERT … ON CONFLICT … RETURNING`, so it is race-free.
5. **Internal errors are not leaked.** `AppError::Internal` is logged server-side and only "Internal server error" is returned.
6. **The frontend pays attention to accessibility:** labels, `aria-live`, `aria-pressed`.

---

## Findings by Dimension

### Security [2/10]

| Sev | Location | Issue | Recommendation |
|---|---|---|---|
| **CRITICAL** | `crypto/engine.rs:284-292`, `README.md` §1–2, §6, `Customer_guide.md` | The server generates and holds the **client (secret) key**. No API lets a client upload its own server key. The confidentiality claims ("we never receive your private key", "mathematical guarantee", "breach immunity") are false: anyone with access to the process can decrypt. | Keys are generated client-side (tfhe-rs native/WASM SDK). Clients upload a `CompressedServerKey` (per user, per key-id). The server stores only server keys and evaluates with the caller's key. Fix the docs. |
| **CRITICAL** | `engine.rs:380-383`, `compute.rs:149` | Round-robin over *independent* key pairs: a job's ciphertexts are evaluated with an arbitrary server key, which gives garbage results. Keys are also regenerated on every boot, so every ciphertext issued before a restart is permanently undecryptable. | Removed once the server evaluates under the caller's own uploaded key. For the sandbox, persist one demo key set or derive it per request. |
| HIGH | `compute.rs:125-155`, `engine.rs:312-325` | Untrusted bytes go through `bincode::deserialize` with no size limit and no parameter-conformance check. `unchecked_add`/`unchecked_mul` then run on attacker-chosen ciphertexts (wrong block count / degree → panic or silent wrong result; also an OOM/CPU DoS vector). | `tfhe::safe_serialization::safe_deserialize_conformant` with a byte limit + `RadixCiphertextConformanceParams`. Use `add_parallelized`/`mul_parallelized`. Reject mismatched block counts. |
| HIGH | `middleware/rate_limit.rs:518-522`, `docker-compose.yml:7` | The rate-limit key is `realip_remote_addr()`, which trusts client-supplied `Forwarded`/`X-Forwarded-For`. The backend is also published directly on `0.0.0.0:18080`, bypassing nginx. Login brute force and email bombing are therefore unlimited. | Use `peer_addr()`, or a trusted-proxy list that takes the rightmost untrusted hop. Bind the backend to an internal network only. Add a per-account limit and lockout. |
| HIGH | `auth.rs:971-975, 1052` | The Google OAuth flow never checks `verified_email`/`email_verified`, but links to an existing account by email. That allows takeover of an existing (even verified) password account via a Google account carrying an unverified copy of the victim's address. | Use OIDC (`id_token`, verify `email_verified == true`), or reject when `verified_email != true`. Only auto-link when the provider asserts verification. |
| HIGH | `auth.rs:1204` | GitHub: `/user.email` (public profile email) is used without the `verified` check that the `/user/emails` fallback has. | Always use `/user/emails` and take the entry with `primary && verified`. |
| HIGH | `frontend/src/lib/api.ts:10,30`, `login/+page.svelte:20` | Access and refresh tokens live in `localStorage` (readable by any XSS, persistent). | Move the refresh token to an `HttpOnly; Secure; SameSite=Strict` cookie scoped to `/api/auth`, and keep the access token in memory. |
| MEDIUM | `auth.rs:801-826` | The OAuth `state` is a stateless JWT not bound to the user agent, so an attacker-initiated flow can be completed in a victim's browser (login CSRF). No PKCE. | Store a random state + PKCE verifier in a short-lived `HttpOnly` cookie and compare on callback. |
| MEDIUM | `auth.rs:918-928, 452, 652` | JWT, refresh token and email are delivered in the redirect URL fragment, where they persist in history; the email is not URL-encoded. The email-verification link also auto-logs-in on a **GET**, which mail scanners prefetch. | Use a one-time code exchanged through a POST, or set the cookie directly. Make verify a POST behind a landing page. |
| MEDIUM | `middleware/jwt.rs:401-405`, `auth.rs:91-101, 807` | Access tokens and OAuth-state tokens are signed with the same HS256 secret. There are no `iss`/`aud`/`typ` claims, and `JWT_SECRET` length/entropy is never validated. | Add `aud`/`typ`, separate keys, and enforce ≥ 32 random bytes at startup. |
| MEDIUM | `auth.rs:745-766` | Refresh rotation is not atomic: two concurrent uses of one token both succeed, and the failure of the old-token `DELETE` is ignored. There is no reuse detection. | Run `DELETE … RETURNING` in a transaction. On reuse of a rotated token, revoke the whole family. |
| MEDIUM | `user.rs:192-205` | OAuth-only accounts can be deleted with any valid access token and no re-authentication. | Require a fresh re-auth (recent OAuth login or an emailed confirmation). |
| MEDIUM | `nginx-heaas.conf`, `main.rs` | No HSTS and no TLS listener. The CSP is only a `<meta>` tag; the API sends no security headers. `X-XSS-Protection` is deprecated. | Use a TLS server block with HSTS, send the CSP as a header (with SvelteKit `kit.csp` hashes), and add `DefaultHeaders` in actix. |
| LOW | `auth.rs:146-152, 211-217` | When SMTP is absent, verification and reset URLs (live secrets) are written to the info log. | Only do this in debug builds, or redact. |
| LOW | `auth.rs:401, 598, 674` | Legacy plaintext-token match (`OR token = ?`) is still accepted. | Remove it after a migration. |
| LOW | `compute.rs:98, 167` | Raw internal errors (`Internal error: {e}`, `HE Error: {e}`) are persisted and shown to users. | Map to stable error codes. |

### Build & Types [4/10]

| Sev | Location | Issue | Recommendation |
|---|---|---|---|
| **CRITICAL** | `frontend/src/app.html:8` | The meta CSP `script-src 'self'` blocks SvelteKit's inline hydration script, so **the production UI is inert** (verified). | Remove the meta tag and configure `kit.csp` (`mode: 'hash'`) so SvelteKit emits hashes. |
| HIGH | `frontend` dev server | `vite dev` returns 500 on every page (`css is not a function`). docker-compose runs exactly this. | Align versions (`@sveltejs/vite-plugin-svelte` ≥ 5 for Svelte 5.5x, Vite 6/7), then add a Playwright smoke test to CI. |
| HIGH | repo root | No CI at all (no `.github/workflows`). Nothing runs build/clippy/test/audit/svelte-check on PRs. | Add a CI pipeline: `cargo fmt --check`, `clippy -D warnings`, `test`, `cargo audit`/`deny`, `pnpm build`, `svelte-check`, Playwright e2e, Docker build. |
| MEDIUM | `vite.config.ts:13`, `tsconfig.json` | `svelte-check` reports 1 error because `@types/node` is missing. | Add it as a devDependency. |
| MEDIUM | `svelte.config.js` | `adapter-auto` cannot detect a target (build warning), and no `paths.base` is set while nginx serves the app under `/heaas/` and the code mixes `${base}` with hard-coded `/heaas/login` and `/dashboard` (`+page.svelte:9-11`, `api.ts:43,48`). | Use `adapter-node` (or `adapter-static` + nginx) and set `paths.base: '/heaas'` consistently. |
| LOW | `api/user.rs:54` | clippy `type_complexity`. | Use a `FromRow` struct. |
| LOW | all `.svelte` | Svelte 5 is used in legacy mode (`$:`, `on:click`, `<slot>`, `export let`). Deprecated. | Migrate to runes. |

### Concurrency [4/10]

| Sev | Location | Issue | Recommendation |
|---|---|---|---|
| HIGH | `compute.rs:92-101` | Each job is a detached `tokio::spawn` + `spawn_blocking`. There is no concurrency cap (the blocking pool allows up to 512 threads × multi-second TFHE ops) and no back-pressure, so a quota of 100/user × N users saturates the CPU. | Use a bounded worker pool (`Semaphore` sized to cores, or a rayon pool) with a queue-depth limit that returns 503 + `Retry-After`. |
| HIGH | `compute.rs:92` | Jobs live only in memory. A restart or crash leaves rows stuck in `pending`/`processing` forever. | Use a persistent queue: workers claim jobs with `UPDATE … WHERE status='pending' RETURNING`. Requeue stale `processing` jobs at boot, and add retry and timeout. |
| MEDIUM | `user.rs:208-231`, `auth.rs:707-719`, `find_or_create_oauth_user` | Multi-statement mutations run without a transaction (account delete = 5 statements, password reset = 2, OAuth create = 2-3), so a partial failure leaves inconsistent state. | Use `pool.begin()` … `commit()`. |
| MEDIUM | `auth.rs:686-714` | The reset token is checked, then consumed later (TOCTOU), so concurrent resets can both succeed. | Consume atomically: `UPDATE … SET token=NULL WHERE token=? AND expires_at>now RETURNING id`. |
| LOW | `rate_limit.rs:496` | The `DashMap` never evicts IPs, so memory grows without bound, especially with spoofed IPs. | Use a periodic sweep or an LRU/`governor` crate keyed on a trusted IP. |
| LOW | `compute.rs:181` | `update_job_status` discards DB errors (`let _ =`). | Log them and propagate. |

### Code Principles [5/10]

| Sev | Location | Issue | Recommendation |
|---|---|---|---|
| MEDIUM | `auth.rs:139-264` | `send_verification_email` and `send_reset_email` are ~60 duplicated lines each. A new SMTP transport is built per email. | Use one `Mailer` built once at startup and shared via `web::Data`, with templated bodies. |
| MEDIUM | `auth.rs` (×6) | The full `SELECT id, email, password_hash, … FROM users` column list is repeated 6 times. | Use a `const USER_COLUMNS` or repository functions. |
| MEDIUM | `main.rs:93-131` | The debug and release CORS branches are identical except for the env fallback. | Use one function and make the fallback conditional. |
| MEDIUM | `auth.rs:571-656` | The same `Found` redirect block is written 5 times (instead of using `oauth_error_redirect`). | Reuse the helper. |
| MEDIUM | `auth.rs:1004, 1155` | A `reqwest::Client::new()` is created per callback with no timeouts. | Share one client with connect/request timeouts. |
| LOW | `models.rs:436` | `input_data_b64` is a JSON array *inside a string* inside JSON, which is an awkward API contract. | Use `inputs: [String; 2]` (or `Vec<String>` with a length check) and a typed `operation` enum. |
| LOW | `compute.rs` | `operation` is a stringly-typed `"add"`/`"multiply"` compared in 4 places. | `#[derive(Deserialize)] enum Op`. |

### Code Quality [5/10]

| Sev | Location | Issue | Recommendation |
|---|---|---|---|
| HIGH | `compute.rs:215-228` | `list_jobs` returns full `input_data_b64` (≤ 2 MB each) for 50 jobs, so one call can be ~100 MB. It also exposes `user_id`. There is no pagination. | Return a summary DTO (id, status, op, timestamps), use cursor pagination, and serve the result through `GET /jobs/{id}/result`. |
| MEDIUM | `quota.rs` + `main.rs:78-84` | The quota middleware wraps the whole `/compute` scope, so **polling `GET /jobs/{id}` and `GET /jobs` uses up the daily compute quota.** | Apply the quota to `POST /sandbox` and `POST /jobs` only. |
| MEDIUM | `quota.rs:465` | A DB error is reported as 429 "temporarily unavailable". | Return 503 + `Retry-After`. |
| MEDIUM | `errors.rs`, actix defaults | Error envelope is `{message}` only, with no machine-readable `code`. JSON-extractor errors return text/plain 400. | Use `{error:{code,message}}` and a `JsonConfig::error_handler`. |
| MEDIUM | `dashboard/+page.svelte:76-80` | The UI says "TFHE-rs **BFV**", "**Radix64**", "Zero-Knowledge". The scheme is TFHE/CGGI with 8×2-bit blocks = 16-bit, and the server decrypts. | Use accurate labels. |
| LOW | `rate_limit.rs:488`, `compute.rs:66`, `auth.rs:94,110,540` | Magic numbers (10 req/60 s, 2,000,000, 1 h, 30 d) are hard-coded instead of configurable. | Move them into `Config`. |
| LOW | `auth.rs` (1,413 lines) | Mixes JWT, email, password reset, refresh and two OAuth providers in one file. | Split into `auth/{password,tokens,email,oauth/{google,github}}.rs`. |

### Dependencies [4/10]

| Sev | Location | Issue | Recommendation |
|---|---|---|---|
| HIGH | `frontend/pnpm-lock.yaml` | 48 npm advisories (19 high): axios, devalue, vite, @sveltejs/kit, etc. | Run `pnpm update`, raise floors to the patched versions, and drop axios for `fetch`. |
| HIGH | `backend/Cargo.lock` | 14 RustSec vulnerabilities in transitive deps (rustls, webpki, quinn-proto, h2, crossbeam-epoch); tokio 1.52.3 is in the unsound range. | Run `cargo update`, add `cargo-deny` to CI. `rsa`/Marvin comes in through the sqlx macro dependency tree: confirm it is unused at runtime, or trim sqlx features. |
| MEDIUM | `Cargo.toml` | `tfhe ~1.3` (latest 1.8.2). `bincode 1` is unmaintained (RUSTSEC-2025-0141) and is the wrong serialiser for TFHE objects. | Upgrade tfhe and use `tfhe::safe_serialization`. |
| MEDIUM | `Cargo.toml` | Both `native-tls` (sqlx, lettre) and `rustls` (reqwest) are pulled in, which means OpenSSL in the image. | Standardise on rustls. |
| LOW | `docker-compose.yml:37` | `npm install` ignores `pnpm-lock.yaml`. | `pnpm install --frozen-lockfile`. |
| LOW | repo | No Dependabot/Renovate. | Add it. |

### Observability [3/10]

| Sev | Location | Issue | Recommendation |
|---|---|---|---|
| HIGH | `main.rs:44` | No access logging (`middleware::Logger` absent), no request IDs, no structured logs. | `tracing` + `tracing-actix-web` (JSON, request-id). |
| MEDIUM | `main.rs:15` | `/api/health` does not check the DB or the HE pool, and there is no readiness probe. | Add `/api/health/ready` (DB ping, keys loaded). |
| MEDIUM | — | No metrics (job latency, queue depth, HE op duration, 4xx/5xx). | Add a Prometheus `/metrics` endpoint. |

### Lifecycle [5/10]

| Sev | Location | Issue | Recommendation |
|---|---|---|---|
| MEDIUM | `config.rs` | Only `JWT_SECRET` presence is validated. Invalid numbers silently fall back to defaults, and `APP_BASE_URL`/`FROM_EMAIL` are not validated. | Do fail-fast validation at boot. |
| MEDIUM | `Dockerfile` | Runs as root, has no `HEALTHCHECK`, no `.dockerignore`, and does not pin the base digest. The frontend is not built into an image; production runs the Vite **dev** server (`docker-compose.yml:37`). | Multi-stage, non-root, healthcheck, `adapter-node` image, compose `depends_on: service_healthy`, `read_only`, `cap_drop`. |
| MEDIUM | `main.rs` | actix's default graceful shutdown covers HTTP only; in-flight background jobs are dropped. | Drain the worker pool on shutdown. |
| LOW | `docker-compose.yml:15` | The default `APP_BASE_URL` is a personal Tailscale hostname. | Use a neutral placeholder and require it to be set. |

### Dead Code [6/10]

| Sev | Location | Issue | Recommendation |
|---|---|---|---|
| LOW | `backend/src/db/schema.sql` | A stale duplicate of the migrations. | Delete it. |
| LOW | `foldertree.txt` | Describes a nonexistent layout ("Microsoft SEAL", `lib.rs`, `error.rs`). | Delete it or regenerate it. |
| LOW | `engine.rs:295-305` | `encrypt`/`decrypt` are `#[allow(dead_code)]`. | Use them in tests, or delete them. |
| LOW | `.Jules/` and `.jules/` | Two case-variant agent-notes directories. | Merge them. |
| LOW | `api.ts:55-79` | The jobs API, `forgotPassword`/`resetPassword` and `resendVerification` have no UI. | Wire them up, or remove them. |

---

## Advisory Findings

- `auth.rs` size: cohesion check scores 2/4 (one domain, but mixed abstraction levels), so the split recommendation is kept as LOW. `[High cohesion: partial]`
- Rule 2 (trivial DRY) removed nothing: every DRY finding above is ≥ 5 lines.

## Cross-Domain DRY Violations

| Pattern | Domains | Recommendation |
|---|---|---|
| Password policy implemented 3× (`validation.rs`, `login/+page.svelte:11`, `account/+page.svelte`) | backend, frontend ×2 | Expose the policy from the API, or share a single TS helper in `$lib`. |
| Login redirect path hard-coded in backend (`/heaas/login`) and frontend (`api.ts`) | backend, frontend | Use one configured base path. |

---

## Recommended Actions (Priority Order)

1. **[CRITICAL]** Client-held keys: per-user uploaded `CompressedServerKey`, evaluation only under the caller's key, removal of the server-side client key from the job path, and honest docs.
2. **[CRITICAL]** Fix the frontend CSP (`kit.csp` hashes) and the dev-server 500. Implement the fragment/one-time-code handling for OAuth, verify and reset.
3. **[HIGH]** Use `safe_deserialize_conformant` with limits and carry-safe parallel ops. Upgrade tfhe and drop bincode.
4. **[HIGH]** Make the rate limiter use the trusted peer IP. Fix OAuth email verification (Google `email_verified`, GitHub `/user/emails`).
5. **[HIGH]** Add a persistent, bounded job queue. Paginate and slim down `list_jobs`. Stop charging quota on polling.
6. **[HIGH]** Add CI (Rust + frontend + audit + e2e). Clear the 14 RustSec and 48 npm advisories.
7. **[MEDIUM]** Cookie-based refresh tokens, PKCE plus a state cookie, atomic rotation with reuse detection, transactions.
8. **[MEDIUM]** Observability (`tracing`, request IDs, readiness, metrics) and a hardened Docker/compose setup.
9. **[LOW]** Dead files, DRY clean-ups, Svelte runes migration.

---

## Sources Consulted

- Repository source (every file in `backend/src`, `backend/migrations`, `frontend/src`, Dockerfile, compose, nginx, README, Customer guide, `.jules` notes)
- Vendored crate source: `tfhe-1.3.3` (`shortint/parameters/aliases.rs`, `integer/server_key/radix/{add,mul}.rs`, `safe_serialization.rs`), `actix-web-4.13.0/src/info.rs`
- RustSec advisory-db (cloned 2026-10-25) via `cargo audit`; `pnpm audit`; crates.io API (`tfhe` max_stable_version = 1.8.2)
- Runtime checks: `cargo build/clippy/test`, `pnpm build`, `svelte-check`, Playwright/Chromium against `vite preview` and `vite dev`
- Skills applied: codebase-auditor, security-review (+ advanced: JWT, CSRF, timing), rust-pro, coding-typescript, api-design, docker-patterns
