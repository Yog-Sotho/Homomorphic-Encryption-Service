# Codebase Audit Report

**Date:** 2026-10-28
**Project:** HEaaS: Homomorphic Encryption as a Service (workspace 0.4.0: `he-backend`, `heaas-core`, `heaas-sdk`; `he-frontend` 0.4.0)
**Language / Framework:** Rust 2021, MSRV 1.91.1 (actix-web 4.18, sqlx 0.8 / SQLite, TFHE-rs 1.8.2, utoipa 6, tracing, prometheus 0.14) · SvelteKit 3.1 / Svelte 5 / Vite 8 (TypeScript, strict), TFHE-rs 1.8.2 WebAssembly
**Project Type:** Web Service with a worker pool (all 9 dimensions applicable)
**Audit Mode:** Domain-aware (`backend/`, `core/`, `sdk/`, `frontend/`, deployment files)
**Previous audit:** 2026-10-25, overall 4.0 / 10, SOTA 3 / 10

Every finding below was checked against the source, tool output or the vendored
crate source; scores are based on that evidence, not on documentation.

---

## Executive Summary

Every CRITICAL and HIGH finding from the previous audit is fixed. The CRITICAL
ones were server-held secret keys, a dead UI and unsafe deserialization.

- **Keys:** clients generate their TFHE keys in the browser (WebAssembly in a
  Web Worker) or with the Rust SDK, and the server only ever holds compressed
  evaluation keys.
- **Inputs:** keys and ciphertexts are checked with size-limited,
  conformance-checked deserialization.
- **Jobs:** jobs run from a durable SQLite queue on a bounded worker pool.
- **Accounts:** session, OAuth and rate-limit handling follow current practice,
  with regression tests.
- **Tooling:** CI enforces formatting, lints, tests, supply-chain checks,
  OpenAPI and parameter-sheet drift, and runs the hardened images.

What remains is at most LOW severity in every dimension except one: test
depth, which is MEDIUM. There is no coverage measurement, and the property
tests the plan called for were not written. On features, HEaaS is now a sound
but narrow FHE service: one encrypted type (`FheUint16`) and five binary
operations. That, not code quality, is what holds the SOTA rating below the
target.

## Overall Score: 8.9 / 10  (no caps apply: no CRITICAL findings)

| Dimension | Score | Priority | Status |
|---|---|---|---|
| Security | 9/10 | CRITICAL | PASS |
| Build & Types | 10/10 | CRITICAL | PASS |
| Code Principles | 9/10 | HIGH | PASS |
| Code Quality | 8/10 | MEDIUM | WARN |
| Dependencies | 9/10 | MEDIUM | PASS |
| Dead Code | 9/10 | LOW | PASS |
| Observability | 9/10 | MEDIUM | PASS |
| Concurrency | 9/10 | HIGH | PASS |
| Lifecycle | 9/10 | MEDIUM | PASS |

**SOTA rating: 7 / 10** (previously 3). The yardstick is the same as before:
state-of-the-art FHE services and tooling such as Zama's TFHE-rs, Concrete and
fhEVM tooling, and OpenFHE-based services.

At or near that bar:
- client-held keys, with compressed evaluation keys only on the server;
- conformance-checked inputs and carry-propagating operations;
- a parameter set pinned to TFHE-rs defaults (≥ 128-bit security, p_fail ≤ 2⁻¹²⁸
  per Zama), published as a generated parameter sheet;
- in-browser WASM keygen with sealed key storage;
- a typed SDK and CLI built on a shared core crate, so parameters cannot drift;
- a durable, idempotent job API with OpenAPI;
- production observability.

Missing, and needed for 9:
- **Breadth of computation.** Only `FheUint16` and add, subtract, multiply,
  min and max. There are no comparisons (`eq`/`lt`, planned in Phase 1 but not
  built), no sums over many inputs, no other widths (8/32/64-bit, signed), no
  scalar (plaintext-operand) operations, and no programs combining several
  operations in one job.
- **Proofs of well-formed encryption.** Inputs are not zero-knowledge proven
  `ProvenCompactCiphertextList`s; TFHE-rs supports them via `zk-pok`.
- **Throughput options.** No compact public-key encryption, no batching, no
  GPU backend.

Verifiable computation is out of reach of TFHE itself and is documented as a
limitation, not counted against the rating.

---

## Strengths

- **Correct trust boundary, tested end to end.**
  - A browser test asserts that only the ~60 MB evaluation key is uploaded and
    that the sealed client key never leaves IndexedDB (`frontend/e2e/fhe.spec.ts:191-199`).
  - An SDK test drives a real HTTP server through every operation and decrypts
    locally (`backend/src/api/integration_tests.rs`, `the_sdk_runs_the_whole_flow_against_a_live_server`).
  - A full-stack Playwright test does the same with the real backend and
    browser TFHE.
- **Single source of truth for parameters.** `heaas-core` holds the TFHE
  configuration, the operations and the API types.
  - A test pins `ConfigBuilder::default()` to the documented parameter set.
  - Another pins `TFHE_VERSION` to `Cargo.lock` and the npm `tfhe` version.
  - `docs/parameters.md` and `docs/api/openapi.json` are generated and
    drift-checked.
  - A test fails if any documented operation is not routed.
- **Defence in depth on accounts.**
  - Sessions: rotating refresh-token families with reuse detection; HKDF-derived
    per-purpose keys; JWT algorithm, issuer, audience and type pinned.
  - Sign-in links: PKCE plus a signed state cookie; one-time login codes; email
    links redeemed by POST.
  - Abuse limits: rate limits keyed on the real client IP behind trusted proxies,
    plus per-account and per-address email caps.
  - Each defence has a regression test (`backend/src/api/auth_tests.rs`).
- **Operational maturity.**
  - The config is validated as a whole: every problem is listed and the server
    exits 2.
  - Every response gets an `X-Request-Id`, including middleware refusals.
  - Logs are JSON; metrics are labelled by route pattern; readiness checks the
    database, both stores and the workers.
  - The backend runs on a distroless, non-root image pinned by digest, with a
    read-only root and no capabilities.
  - Backups use consistent `VACUUM INTO` snapshots.
  - CI builds both images, runs them hardened and waits for them to report
    healthy.

---

## Findings by Dimension

### Security [9/10]

Scans: hard-coded secrets (none outside tests and `.env.example`), SQL built by
interpolation (two `format!` queries, both from compile-time constants:
`password.rs:367` `VALID`, `user.rs:239` a fixed table list), `{@html}` /
`innerHTML` (none), `unsafe` (none), tracked `.env` (none; `.env` is now
git-ignored), `cargo deny` (advisories, bans, licences, sources: ok).

| Severity | Location | Issue | Recommendation |
|---|---|---|---|
| LOW | `frontend/vite.config.ts:46` | `style-src` allows `'unsafe-inline'`. Scripts are hash-pinned; styles are not. Impact is limited to CSS injection, which the app has no sink for. | Move to style hashes (SvelteKit `csp.mode: 'hash'` covers `<style>`) once Svelte no longer needs inline `style` attributes. |
| LOW | `backend/src/middleware/rate_limit.rs` | Only `/api/v1/auth` is rate-limited per IP. Authenticated reads (`GET /keys`, `/compute/jobs`) rely on authentication alone. Writes are bounded by the key cap, active-job cap and daily quota. | Add a per-user limiter on the authenticated scope. |
| LOW | `backend/src/middleware/rate_limit.rs` (per-email login limit) | An attacker can spend a victim's per-email sign-in budget and block their password sign-in for up to 15 minutes. This is the usual trade-off of per-account limits. | Accept, or exempt requests carrying a valid refresh cookie. |
| INFO | `backend/src/middleware/jwt.rs` | Access tokens stay valid for up to `ACCESS_TOKEN_TTL_SECS` (900 s) after sign-out or a password change. This is by design and documented. | None. |

### Build & Types [10/10]

- `cargo fmt --check` and `cargo clippy --workspace --all-targets -D warnings`:
  clean. There is now no `#[allow]` left in the Rust code (the last one,
  `clippy::too_many_arguments` at `compute.rs:170`, was replaced by a struct
  during this audit).
- An MSRV 1.91.1 `cargo check` runs in CI.
- `svelte-check --fail-on-warnings`: 0 errors and 0 warnings across 377 files,
  with `strict: true`.
- Release and debug builds are reproducible with `--locked`.

No findings.

### Code Principles [9/10]

- Layering is clear in every domain:
  - core: parameters, operations, DTOs;
  - backend: `api/` → `jobs/`, `crypto/`, `storage`, `telemetry`;
  - sdk: `client`, `fhe`, `bin`;
  - frontend: `lib/api`, `lib/fhe` (worker, vault), routes.
- Shared logic is extracted:
  - the error-code mapping lives in core and is used by both server and SDK;
  - one atomic-write helper (`storage::write_atomic`);
  - one `Mailer`;
  - one password policy (`frontend/src/lib/password-policy.ts`).

| Severity | Location | Issue | Recommendation |
|---|---|---|---|
| LOW | `backend/src/config.rs` (797 lines with tests) | The longest non-test module. [High cohesion: one responsibility, one data model, consistent abstraction.] | None now; split by area if it keeps growing. |

### Code Quality [8/10]

- There are 112 Rust tests:
  - unit tests;
  - HTTP integration tests against the real router;
  - wiremock OAuth and SDK tests;
  - CLI binary tests;
  - an SDK run against a live server.
- There are 43 TypeScript tests: 29 Vitest, 13 Playwright including axe
  WCAG 2.2 AA scans, and 1 full-stack.
- No TODO, FIXME or HACK markers. The largest source files are 400–630 lines,
  apart from the test modules.

| Severity | Location | Issue | Recommendation |
|---|---|---|---|
| MEDIUM | `.github/workflows/ci.yml` | No coverage measurement, so untested paths are invisible. | Add `cargo llvm-cov` and Vitest coverage to CI with a floor. |
| MEDIUM | `backend/src/crypto/`, `core/src/operation.rs` | The plan's property tests are missing: `proptest` comparing homomorphic results with `apply_plain` over random inputs, and fuzzing of the deserialization paths. The nightly heavy-TFHE job is also missing. The current tests cover fixed values only. | Add `proptest` with a small case count to normal CI, an `#[ignore]` heavy variant, and a scheduled workflow that runs it. |

### Dependencies [9/10]

- `cargo deny check` (advisories, bans, licences, sources): ok.
- `pnpm audit`: 1 low advisory. Dependabot covers cargo, npm, both Dockerfiles
  and Actions.
- TFHE-rs is pinned to one release on both sides, enforced by a test.
- Base images are pinned: `rust:1.99.1-bookworm`, `node:22.23.4-alpine3.24`,
  and distroless by digest.

| Severity | Location | Issue | Recommendation |
|---|---|---|---|
| LOW | `frontend` → `@sveltejs/vite-plugin-svelte` → `deepmerge 4.3.1` | GHSA-gcqx-w48m-w2h4 (low): prototype pollution in `mergeObject()`. It is a build-time dev dependency and no patched release exists. | Track it; CI fails only at moderate and above. |
| LOW | `Cargo.lock` | Duplicate major versions (e.g. `base64` 0.22/0.23, `getrandom` 0.2/0.3/0.4, `hashbrown` ×4) come in through transitive dependencies. They are warnings in `deny.toml`. | Let them converge through Dependabot. |

### Dead Code [9/10]

The dead files flagged last time (`backend/src/db/schema.sql`,
`foldertree.txt`, the `.Jules/` duplicate) are removed, along with the server
key pool, the sandbox endpoint, `axios`, `bincode` and the example client. The
compiler reports no dead code.

| Severity | Location | Issue | Recommendation |
|---|---|---|---|
| LOW | `jobs.input_data_b64`, `jobs.result_b64`, `compute.rs` legacy read path | Columns kept for rows from before ciphertexts moved to disk. New rows write `''` and `NULL`. | Drop both in a migration once old jobs have passed `JOB_RETENTION_DAYS`. |
| INFO | `backend/src/api/mod.rs` (`/api` alias) | The deprecated unversioned API is intentional and marked with `Deprecation` and `Link` headers. | Remove in a later major version. |

### Observability [9/10]

- `tracing` writes JSON lines; library `log` records are bridged in.
- Request ids are taken from the client when sane, echoed, and exposed to CORS.
- One access line per request; job spans carry `job_id`, operation and attempt.
- `/metrics` is token-protected: HTTP traffic by route pattern, queue depth,
  job wait and evaluation time, outcomes, key-cache hits and misses, worker
  liveness, build info.
- Readiness checks the database, both stores and the workers.

| Severity | Location | Issue | Recommendation |
|---|---|---|---|
| LOW | `backend/src/telemetry.rs` | Spans are logged, not exported. There is no OpenTelemetry trace export. | Add an optional OTLP exporter if the deployment has a collector. |
| LOW | `frontend` | Browser-side errors (e.g. a failed WASM load) are shown to the user but not reported anywhere. | Optional client error reporting endpoint. |

### Concurrency [9/10]

- Quota charging, key-count limits, job capacity and job claiming each run as
  one SQL statement (`INSERT … SELECT … WHERE`, `UPDATE … RETURNING`).
- Multi-step changes run in transactions: password change and reset, account
  deletion, OAuth linking.
- bcrypt and TFHE work run on blocking threads, with per-job timeouts. A
  timed-out evaluation keeps its worker busy until the thread ends, so
  concurrency never exceeds the pool size.
- Idempotency keys make submissions safe to retry; the SDK relies on this.
- Background tasks log their own errors.

| Severity | Location | Issue | Recommendation |
|---|---|---|---|
| LOW | `backend/src/crypto/keys.rs` (`KeyStore::load`) | Two jobs missing the cache for the same key both decompress it (~0.5 s and ~180 MB each). The cache stays correct; the work is duplicated. | Single-flight the decompression per key id. |

### Lifecycle [9/10]

- Configuration is validated before anything starts. Startup failures now exit
  1 with a single log line instead of panicking; this was fixed during the audit
  in `main.rs`.
- On SIGTERM the server stops accepting work, drains the workers within a grace
  period, and requeues interrupted jobs at the next start (tested).
- `healthcheck` and `backup` subcommands; both images have HEALTHCHECKs, and the
  frontend waits for a healthy backend.
- Backups are consistent; restore and migration are documented.

| Severity | Location | Issue | Recommendation |
|---|---|---|---|
| INFO | `backend/src/api/health.rs` | Readiness does not switch to 503 while the server drains. actix stops accepting connections at the same moment, so a load balancer sees refused connections rather than 503s. | Optionally flip readiness on SIGTERM before stopping. |

---

## Advisory Findings

- `backend/src/config.rs` length: [High cohesion module] (see Code Principles).
- `backend/src/api/integration_tests.rs` (1,127 lines) and `auth_tests.rs`
  (824 lines): test modules, one scenario per test. [High cohesion module]

---

## Cross-Domain DRY Violations

None. The patterns found duplicated in the previous audit now live once:
- operations and parameters in `heaas-core`;
- error codes in `heaas-core::api::error_codes`;
- the password policy in one frontend module.

---

## Recommended Actions (Priority Order)

1. [MEDIUM] Add coverage measurement (Rust and frontend) to CI with a floor.
2. [MEDIUM] Add property tests (homomorphic result vs `apply_plain`, random
   inputs; deserialization fuzzing), plus the scheduled heavy-TFHE job.
3. [SOTA] Widen computation:
   - comparisons (`eq`, `lt`, …) returning encrypted booleans;
   - multi-input `sum`;
   - scalar operations;
   - more integer widths;
   - multi-operation programs.
4. [SOTA] Accept zero-knowledge-proven compact ciphertext lists (`zk-pok`) for
   inputs.
5. [LOW] A per-user rate limit on the authenticated scope; single-flight key
   decompression; drop the legacy job columns; style hashes in the CSP.

---

## Sources Consulted

- Source, tests and tool output in this repository at the audit date:
  `cargo fmt`, `cargo clippy`, `cargo test --workspace`, `cargo deny check`,
  `svelte-check`, `pnpm audit`, and the Playwright e2e and full-stack suites.
- Vendored TFHE-rs 1.8.2 source (`high_level_api/keys/inner.rs`: default
  parameter set; `shortint/parameters/classic.rs`).
- Zama, [TFHE-rs: Security and cryptography](https://docs.zama.org/tfhe-rs/get-started/security-and-cryptography):
  default parameters' security level and failure probability.
- GitHub Advisory [GHSA-gcqx-w48m-w2h4](https://github.com/advisories/GHSA-gcqx-w48m-w2h4) (deepmerge).
