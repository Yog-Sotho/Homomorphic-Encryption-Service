# Codebase Audit Report

**Date:** 2026-10-29
**Project:** Homomorphic Encryption Engine (HE Engine; workspace 0.4.0 + Phase 8: `he-backend`, `heaas-core`, `heaas-sdk`; `he-frontend` 0.4.0)
**Language / Framework:** Rust 2021, MSRV 1.91.1 (actix-web 4.18, sqlx 0.8 / SQLite, TFHE-rs 1.8.2, utoipa 6, tracing, prometheus 0.14) · SvelteKit 3.1 / Svelte 5 / Vite 8 (TypeScript, strict), TFHE-rs 1.8.2 WebAssembly
**Project Type:** Web Service with a worker pool (all 9 dimensions applicable)
**Audit Mode:** Domain-aware (`backend/`, `core/`, `sdk/`, `frontend/`, deployment files)
**Previous audits:** 2026-10-25 (overall 4.0, SOTA 3), 2026-10-28 (overall 9.0, reported
as 8.9 by an arithmetic slip; SOTA 7)

Every finding below was checked against the source, tool output or the vendored
crate source; scores are based on that evidence, not on documentation.

---

## Executive Summary

Phase 8 closed both MEDIUM findings of the previous audit and the two feature gaps
that held the SOTA rating back.

- **Tests:** `proptest` property tests compare homomorphic results with the plaintext
  oracle on random operations, types and values, and throw random and corrupted
  bytes at every deserialization path (ciphertexts, proven lists, public and server
  keys). Heavier variants (every type, 64-bit multiplication, proofs) run in a
  scheduled workflow. CI now measures coverage with floors: Rust 91% of lines
  (floor 88%), frontend library code 92% (floor 88%).
- **Computation:** eight integer types (8 to 64 bits, signed and unsigned), the six
  comparisons with encrypted boolean results, sums of up to 16 inputs, and plaintext
  (scalar) right-hand operands, in the server, SDK, CLI and dashboard.
- **Proven inputs:** TFHE-rs `ProvenCompactCiphertextList`s with zero-knowledge
  proofs of well-formed encryption, verified against the key's public key and a
  server-generated CRS, bound to the key id. Browser proving is covered by the
  full-stack test.

Every finding left is LOW or INFO. The SOTA rating rises to 8: what is still missing
is multi-operation programs and throughput options (batching, GPU).

## Overall Score: 9.1 / 10  (average of the nine dimensions; no caps apply: no CRITICAL findings)

| Dimension | Score | Priority | Status |
|---|---|---|---|
| Security | 9/10 | CRITICAL | PASS |
| Build & Types | 10/10 | CRITICAL | PASS |
| Code Principles | 9/10 | HIGH | PASS |
| Code Quality | 9/10 | MEDIUM | PASS |
| Dependencies | 9/10 | MEDIUM | PASS |
| Dead Code | 9/10 | LOW | PASS |
| Observability | 9/10 | MEDIUM | PASS |
| Concurrency | 9/10 | HIGH | PASS |
| Lifecycle | 9/10 | MEDIUM | PASS |

**SOTA rating: 8 / 10** (previously 7). The yardstick is the same as before:
state-of-the-art FHE services and tooling such as Zama's TFHE-rs, Concrete and
fhEVM tooling, and OpenFHE-based services.

At or near that bar:
- client-held keys, with compressed evaluation keys only on the server;
- conformance-checked inputs and results, and carry-propagating operations;
- zero-knowledge-proven inputs (TFHE-rs compact PKE proofs), bound to the key;
- eight integer types, comparisons, sums and scalar operands;
- a parameter set pinned to TFHE-rs defaults (≥ 128-bit security, p_fail ≤ 2⁻¹²⁸
  per Zama) plus Zama's dedicated compact-public-key parameters, published as a
  generated parameter sheet;
- in-browser WASM keygen, encryption and proving, with sealed key storage;
- a typed SDK and CLI built on a shared core crate, so parameters cannot drift;
- a durable, idempotent job API with OpenAPI;
- production observability, property tests and measured coverage.

Missing, and needed for 9:
- **Programs.** Each job is one operation. Comparable systems evaluate circuits
  (several operations, `if_then_else` on encrypted conditions, bitwise operations,
  division) in one job, keeping intermediate values on the server.
- **Throughput options.** No batching of many jobs per request and no GPU backend.
- **Proofs today protect the server from its own users only.** Only a key's owner
  can submit jobs for it; accepting proven inputs from other parties (the case
  proofs are designed for) is not offered.

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
- **Proofs and types end to end.** One evaluator per TFHE-rs type, generated by a
  macro, with results re-encrypted where TFHE-rs would leave trivial blocks
  (`backend/src/crypto/eval.rs`); the SDK, the CLI and the browser worker encrypt,
  prove and decrypt every type, and the backend's tests play the client through
  the SDK.
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
| LOW | `backend/src/crypto/params.rs` (`get_crs`) | `GET /api/v1/he/crs` serves ~1.9 MB to anyone, unauthenticated and not rate-limited. It sends `ETag` and `Cache-Control: public`, so caches absorb repeats, but a client can still make the server send it repeatedly. | Rate-limit `/he` per IP like `/auth`, or let nginx cache it. |
| LOW | `backend/src/crypto/proofs.rs` | The server generates the CRS itself, so its operator is trusted not to keep a trapdoor. This is documented (`docs/how-it-works.md#proven-inputs`, `SECURITY.md`). | Accept; or load a CRS from a public ceremony when one is available. |
| LOW | `backend/src/middleware/rate_limit.rs` | Only `/api/v1/auth` is rate-limited per IP. Authenticated reads (`GET /keys`, `/compute/jobs`) rely on authentication alone. Writes are bounded by the key cap, active-job cap and daily quota. | Add a per-user limiter on the authenticated scope. |
| LOW | `backend/src/middleware/rate_limit.rs` (per-email login limit) | An attacker can spend a victim's per-email sign-in budget and block their password sign-in for up to 15 minutes. This is the usual trade-off of per-account limits. | Accept, or exempt requests carrying a valid refresh cookie. |
| INFO | `backend/src/middleware/jwt.rs` | Access tokens stay valid for up to `ACCESS_TOKEN_TTL_SECS` (900 s) after sign-out or a password change. This is by design and documented. | None. |

### Build & Types [10/10]

- `cargo fmt --check` and `cargo clippy --workspace --all-targets -D warnings`:
  clean, with no `#[allow]` in the Rust code. (`submit_job` reads the CRS from
  the request's app data rather than taking an eighth extractor.)
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
| LOW | `backend/src/crypto/eval.rs` (`typed_evaluator!`), `sdk/src/fhe.rs` (`per_type!`) | Two macros map `IntegerType` to the TFHE-rs types and their conformance parameters. Same table, two crates. (The browser worker needs its own, in TypeScript.) | Export one `#[macro_export]` dispatch macro from `heaas-core`. |
| LOW | `backend/src/config.rs` (797 lines with tests) | The longest non-test module. [High cohesion: one responsibility, one data model, consistent abstraction.] | None now; split by area if it keeps growing. |

### Code Quality [9/10]

- Rust: unit tests; property tests (`core/src/operation.rs`,
  `backend/src/crypto/property_tests.rs`); HTTP integration tests against the real
  router, including typed jobs, scalars, sums and proven inputs; wiremock OAuth and
  SDK tests; CLI binary tests; an SDK run against a live server with proofs.
  `#[ignore]`d heavy property tests run in `.github/workflows/heavy.yml`.
- TypeScript: 39 Vitest, 13 Playwright (including axe WCAG 2.2 AA scans), and 1
  full-stack test that proves inputs in the browser and has the real server verify
  them.
- Coverage, measured in CI with floors: Rust 91.4% of lines workspace-wide
  (`cargo llvm-cov`, floor 88%); frontend library code 92.4% (`vitest --coverage`,
  floor 88%; pages and the worker are covered by the Playwright suites).
- No TODO, FIXME or HACK markers.

| Severity | Location | Issue | Recommendation |
|---|---|---|---|
| LOW | `backend/src/main.rs` (38% of lines), `sdk/src/bin/heaas.rs` (42%) | Startup wiring and the networked CLI commands are exercised only by the full-stack and Docker jobs, which coverage does not measure. | Drive the CLI's networked commands against the live test server, as the SDK test does. |

### Dependencies [9/10]

- `cargo deny check` (advisories, bans, licences, sources): ok. `tfhe-zk-pok`
  (BSD-3-Clause-Clear, like the rest of TFHE-rs) is a documented licence exception.
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

1. [SOTA] Multi-operation programs in one job (a small expression language over
   encrypted inputs, with `if_then_else`, bitwise operations and division).
2. [SOTA] Batching, and an optional GPU backend (TFHE-rs `gpu` feature).
3. [LOW] Rate-limit `/he` per IP (or cache the CRS in nginx); a per-user limit on
   the authenticated scope.
4. [LOW] One type-dispatch macro in `heaas-core` for the backend and the SDK.
5. [LOW] Single-flight key decompression; drop the legacy job columns; style hashes
   in the CSP; CLI networked commands under coverage.

---

## Sources Consulted

- Source, tests and tool output in this repository at the audit date:
  `cargo fmt`, `cargo clippy`, `cargo test --workspace`, `cargo deny check`,
  `svelte-check`, `pnpm audit`, and the Playwright e2e and full-stack suites.
- Vendored TFHE-rs 1.8.2 source (`high_level_api/keys/inner.rs`: default
  parameter set and `IntegerServerKeyConformanceParams`;
  `high_level_api/compact_list.rs`: `verify_and_expand`; `high_level_api/zk.rs`:
  `CompactPkeCrs::from_config`; `shortint/ciphertext/standard.rs`: ciphertext
  conformance; `js_on_wasm_api/shortint.rs`: the browser's PKE parameter names).
- Measurements on this machine (4 cores, release build): CRS generation ~8 s
  (1.9 MB compressed); proving 2 × `u16` ~0.8 s, verifying ~0.2 s; a proven list
  ~20 KB; `u64` multiplication ~14 s.
- `cargo llvm-cov --workspace` and `vitest run --coverage` output.
- Zama, [TFHE-rs: Security and cryptography](https://docs.zama.org/tfhe-rs/get-started/security-and-cryptography):
  default parameters' security level and failure probability.
- GitHub Advisory [GHSA-gcqx-w48m-w2h4](https://github.com/advisories/GHSA-gcqx-w48m-w2h4) (deepmerge).
