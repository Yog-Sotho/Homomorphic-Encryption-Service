# Codebase Audit Report

**Date:** 2026-10-30
**Project:** Homomorphic Encryption Engine (HE Engine; workspace 0.4.0 + Phases 8 to 10: `he-backend`, `heaas-core`, `heaas-sdk`; `he-frontend` 0.4.0)
**Language / Framework:** Rust 2021, MSRV 1.91.1 (actix-web 4.18, sqlx 0.8 / SQLite, TFHE-rs 1.8.2, utoipa 6, tracing, prometheus 0.14) · SvelteKit 3.1 / Svelte 5 / Vite 8 (TypeScript, strict), TFHE-rs 1.8.2 WebAssembly
**Project Type:** Web Service with a worker pool (all 9 dimensions applicable)
**Audit Mode:** Domain-aware (`backend/`, `core/`, `sdk/`, `frontend/`, deployment files)
**Previous audits:** 2026-10-25 (overall 4.0, SOTA 3), 2026-10-28 (overall 9.0, reported
as 8.9 by an arithmetic slip; SOTA 7), 2026-10-29 after Phase 8 (overall 9.1, SOTA 8),
2026-10-29 after Phase 9 (overall 9.1, SOTA 9)

Every finding below was checked against the source, tool output or the vendored
crate source; scores are based on that evidence, not on documentation.

---

## Executive Summary

This re-audit follows Phase 10, which made programs richer and closed three of
the LOW findings.

- **Lookup tables:** a `lookup` step maps an encrypted value through a plaintext
  table of up to 256 entries with a default, using TFHE-rs's `match_value_or`.
  Signed values are looked up by their two's-complement bits, through the unsigned
  type of the same width. Tests decrypt lookups on signed and unsigned types,
  including a table whose result is known without the input (it comes back
  re-encrypted).
- **Several results:** a program names up to 16 output steps. Each result is stored
  and served on its own (`GET …/result?output=N`), and jobs report `result_types`.
  The dashboard, jobs page, SDK and CLI handle them, and both expression compilers
  (`a + b, lookup(a, [1, 4, 9])`) pass the shared file of test cases, now 93.
- **Compressed results:** keys made with TFHE-rs's compression parameters return all
  of a job's results as one `CompressedCiphertextList`. Measured here: 1.9 KB for one
  `u16` or `u64` (from 132 KB and 528 KB), 2.0 KB for four `u16`s. Such a server key
  is 106 MB instead of 60 MB. TFHE-rs 1.8.2's browser build has no compressed lists
  and no compression configuration (checked in `js_on_wasm_api`), so this is for the
  SDK and CLI; gzip saves 0.5% of a ciphertext, so HTTP compression would not help.
- **LOW findings closed:**
  - `style-src` no longer allows `'unsafe-inline'`. Only SvelteKit's route announcer
    style is allowed, pinned by hash, and the e2e tests fail on any CSP violation.
  - Signed-in routes are rate-limited per account.
  - Concurrent cache misses decompress a key once, with a test.
- **Tests:** random programs in the property tests now include lookups (sometimes
  keyed on an input's value, so both branches run) and programs with two outputs.

Every finding is LOW or INFO. The SOTA rating stays at 9: GPU evaluation and
inputs from other parties are still missing.

## Overall Score: 9.2 / 10  (average of the nine dimensions; no caps apply: no CRITICAL findings)

| Dimension | Score | Priority | Status |
|---|---|---|---|
| Security | 9/10 | CRITICAL | PASS |
| Build & Types | 10/10 | CRITICAL | PASS |
| Code Principles | 9/10 | HIGH | PASS |
| Code Quality | 9/10 | MEDIUM | PASS |
| Dependencies | 9/10 | MEDIUM | PASS |
| Dead Code | 9/10 | LOW | PASS |
| Observability | 9/10 | MEDIUM | PASS |
| Concurrency | 10/10 | HIGH | PASS |
| Lifecycle | 9/10 | MEDIUM | PASS |

**SOTA rating: 9 / 10** (unchanged). The yardstick is the same as before:
state-of-the-art FHE services and tooling such as Zama's TFHE-rs, Concrete and
fhEVM tooling, and OpenFHE-based services.

At that bar:
- client-held keys, with compressed evaluation keys only on the server;
- conformance-checked inputs and results, and carry-propagating operations;
- zero-knowledge-proven inputs (TFHE-rs compact PKE proofs), bound to the key;
- programs: multi-step circuits with encrypted control flow (`select`), lookup
  tables, division, bitwise operations and shifts on eight integer types, with
  several results, written in an expression syntax that compiles identically in
  Rust and in the browser;
- results compressed into one TFHE-rs list (SDK keys with compression keys);
- batch submission, durable and idempotent, with OpenAPI;
- a parameter set pinned to TFHE-rs defaults (≥ 128-bit security, p_fail ≤ 2⁻¹²⁸
  per Zama) plus Zama's dedicated compact-public-key parameters, published as a
  generated parameter sheet;
- in-browser WASM keygen, encryption and proving, with sealed key storage;
- a typed SDK and CLI built on a shared core crate;
- production observability, property tests and measured coverage.

Still missing for 10:
- **GPU evaluation.** TFHE-rs has a CUDA backend; the service runs on CPU only.
- **Inputs from other parties.** Only a key's owner submits jobs; proven inputs from
  third parties encrypting under the owner's public key (surveys, aggregation),
  the case proofs are designed for, are not offered.
- **Compressed results in the browser.** They need a TFHE-rs browser build with
  compressed ciphertext lists; 1.8.2 has none.

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
- **One semantics, checked everywhere.** The plaintext oracle in `heaas-core` is
  tested against native Rust integers; homomorphic programs are tested against the
  oracle (random well-typed programs, every step operation, every type in the
  scheduled run); the browser's compiler and oracle pass the same test vectors.
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
| LOW | `backend/src/crypto/proofs.rs` | The server generates the CRS itself, so its operator is trusted not to keep a trapdoor. This is documented (`docs/how-it-works.md#proven-inputs`, `SECURITY.md`). | Accept; or load a CRS from a public ceremony when one is available. |
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
| LOW | `backend/src/config.rs` (797 lines with tests) | The longest non-test module. [High cohesion: one responsibility, one data model, consistent abstraction.] | None now; split by area if it keeps growing. |

### Code Quality [9/10]

- Rust (155 tests, 3 heavy ones ignored): unit tests; property tests
  (`core/src/operation.rs`, `core/src/program.rs`,
  `backend/src/crypto/property_tests.rs`, including random programs); HTTP
  integration tests against the real router, including programs, batches, typed
  jobs, scalars, sums and proven inputs; wiremock OAuth and SDK tests; CLI binary
  tests; an SDK run against a live server with proofs, a program and a batch.
  `#[ignore]`d heavy property tests run in `.github/workflows/heavy.yml`.
- TypeScript: 138 Vitest (93 of them the shared program vectors), 13 Playwright
  (including axe WCAG 2.2 AA scans), and 1 full-stack test that proves inputs in the
  browser and runs a program with a lookup and two results on the real server.
- Coverage, measured in CI with floors: Rust 91.2% of lines workspace-wide
  (`cargo llvm-cov`, floor 88%); frontend library code 93.0% (`vitest --coverage`,
  floor 88%; pages and the worker are covered by the Playwright suites).
- No TODO, FIXME or HACK markers.

| Severity | Location | Issue | Recommendation |
|---|---|---|---|
| LOW | `backend/src/main.rs` (38% of lines), `sdk/src/bin/heaas.rs` (44%) | Startup wiring and the networked CLI commands are exercised only by the full-stack and Docker jobs, which coverage does not measure. | Drive the CLI's networked commands against the live test server, as the SDK test does. |

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
| LOW | `jobs.input_data_b64`, `jobs.result_b64`, `compute.rs` legacy read path | Columns kept for rows from before ciphertexts moved to disk (0.4.0, 2026-10-28). New rows write `''` and `NULL`. Not dropped in Phase 10: the default `JOB_RETENTION_DAYS` (7) has not passed since that release, so a deployment may still hold such rows. | Drop both in a migration after 2026-11-04. |
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

### Concurrency [10/10]

- Quota charging, key-count limits, job capacity and job claiming each run as
  one SQL statement (`INSERT … SELECT … WHERE`, `UPDATE … RETURNING`).
- Multi-step changes run in transactions: password change and reset, account
  deletion, OAuth linking.
- bcrypt and TFHE work run on blocking threads, with per-job timeouts. A
  timed-out evaluation keeps its worker busy until the thread ends, so
  concurrency never exceeds the pool size.
- Idempotency keys make submissions safe to retry; the SDK relies on this.
- Background tasks log their own errors.

- Key decompression is single-flight per key id (`KeyStore::load`): jobs that miss
  the cache for the same key at once wait for one decompression and share it
  (`concurrent_cache_misses_decompress_a_key_once`).

No findings.

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
- `frontend/src/lib/fhe/program.ts` mirrors `core/src/program.rs` and
  `core/src/expression.rs` in TypeScript: the dashboard needs the compiler and the
  oracle offline, and WebAssembly for this alone would be heavier. Drift is caught
  by `core/tests/program_vectors.json`, which both test suites run.
  [Cross-language by necessity, guarded by shared tests]
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

1. [SOTA] An optional GPU backend (TFHE-rs `gpu` feature) for evaluation.
2. [SOTA] Contributions from other parties: shareable submission links that accept
   proven inputs under a key owner's public key, for aggregation.
3. [SOTA] Compressed results in the browser, once a TFHE-rs browser build has
   compressed ciphertext lists.
4. [LOW] Drop the legacy job columns after 2026-11-04; put the CLI's networked
   commands under coverage.

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
- Phase 9 measurements with TFHE-rs 1.8.2 (`div_rem`, scalar division, shifts,
  rotations, `if_then_else`, `abs`): encrypted `x / 0` gives `MAX` (unsigned) or
  −1 / 1 (signed), remainder `x`; `MIN / −1` gives `MIN`; signed division
  truncates; scalar division by 0 panics (refused before evaluation); shifts by the
  type's width or more give 0 (or the sign for signed `>>`).
- Zama, [TFHE-rs: Security and cryptography](https://docs.zama.org/tfhe-rs/get-started/security-and-cryptography):
  default parameters' security level and failure probability.
- GitHub Advisory [GHSA-gcqx-w48m-w2h4](https://github.com/advisories/GHSA-gcqx-w48m-w2h4) (deepmerge).
