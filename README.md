<div align="center">
<img src="./he-saas-logo.svg" alt="HEaaS Logo" width="400"/>
</div>

# HEaaS: Homomorphic Encryption as a Service

HEaaS runs computations on encrypted integers. You encrypt on your own device, the
server computes directly on the ciphertexts, and you decrypt the result locally. The
server never has your secret key, so it cannot read your inputs or results.

It is built on [TFHE-rs](https://github.com/zama-ai/tfhe-rs) (the TFHE/CGGI scheme)
with a Rust backend (actix-web, SQLite) and a SvelteKit dashboard that does all
key handling and encryption in the browser through TFHE-rs's WebAssembly build.

> **Status:** pre-1.0. Working end to end, with the limits stated under
> [What the server can and cannot learn](#what-the-server-can-and-cannot-learn).
> The latest audit is in [`docs/project/codebase_audit.md`](docs/project/codebase_audit.md).
> Read [Licensing](#licensing) before any commercial use.

| Document | For |
|---|---|
| [Customer guide](Customer_guide.md) | Using the dashboard and the API |
| [`docs/api/openapi.json`](docs/api/openapi.json) | The API, as OpenAPI 3.1 (also served at `/api/v1/openapi.json`) |
| [`docs/parameters.md`](docs/parameters.md) | The cryptographic parameters (generated from the code) |
| [SECURITY.md](SECURITY.md) | Reporting vulnerabilities; the threat model in brief |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Building, testing and the checks a change must pass |
| [CHANGELOG.md](CHANGELOG.md) | What changed between releases |

## Quick start

```sh
cp .env.example .env    # set JWT_SECRET (openssl rand -base64 48) and APP_BASE_URL
docker compose up -d --build
docker compose ps       # backend and frontend "healthy"
```

The app is then at `http://127.0.0.1:3000/heaas` and the API at
`http://127.0.0.1:8080/api/v1`. Put nginx in front of both for HTTPS (see
[Deployment](#deployment)). For local development without Docker, see
[Development](#development).

---

## How it works

```
 Your device                                      HEaaS server
 ───────────                                      ────────────
 1. generate key pair  ──────────────────────────▶ (nothing)
    client key (secret) stays here
 2. upload compressed server key  ──────────────▶ stores it; can compute,
                                                   cannot decrypt
 3. encrypt inputs, submit job  ────────────────▶ evaluates op(a, b) on
                                                   ciphertexts with your key
 4. fetch encrypted result  ◀───────────────────── queued job runs on a
                                                   worker; returns a ciphertext
 5. decrypt locally
```

### Architecture

```
 Browser (SvelteKit app)            Rust client (heaas-sdk / heaas CLI)
 TFHE-rs WASM in a Web Worker:      TFHE-rs: keygen, encrypt, decrypt
 keygen, encrypt, decrypt;          client key in a 0600 file
 client key sealed in IndexedDB
        │ HTTPS                              │ HTTPS
        ▼                                    ▼
 ┌──────────────────────── nginx (TLS, HSTS) ────────────────────────┐
 │   /heaas/ ─▶ frontend (node, server.js)    /api/ ─▶ backend        │
 └────────────────────────────────────────────────────────────────────┘
                                                      │
          backend (actix-web, he-backend)             ▼
          ├─ /api/v1: accounts, sessions, keys, jobs, OpenAPI, health
          ├─ job queue in SQLite ─▶ worker pool ─▶ TFHE-rs evaluation
          │                         (bounded, timeouts, retries, durable)
          ├─ /data/he_saas.db  · /data/keys (server keys)  · /data/jobs (ciphertexts)
          └─ /metrics (Prometheus, token) · JSON logs with request ids
```

`heaas-core` holds what the backend, the SDK and the CLI must agree on: the TFHE
parameters, the operations and the API types.

- **Client key** (~31 KB): generated on your device, used to encrypt and decrypt.
  It is never uploaded. In the dashboard it stays in the browser's IndexedDB,
  encrypted with your passphrase (see [Your key in the browser](#your-key-in-the-browser)).
- **Compressed server key** (~60 MB): an evaluation key derived from the client key.
  It lets the server compute on your ciphertexts but not decrypt them. You register
  it once with `POST /api/v1/keys`; the server checks it against its parameters.
- **Ciphertexts** (~132 KB each): `FheUint16` values. Arithmetic wraps modulo 2¹⁶.

### Parameters

| | |
|---|---|
| Scheme | TFHE (CGGI), TFHE-rs **1.8.2** (pinned; clients must use the same release) |
| Configuration | `ConfigBuilder::default()`: TFHE-rs default parameters (`PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128`, failure probability ≤ 2⁻¹²⁸) |
| Integer type | `FheUint16` (0–65535) |
| Operations | `add`, `subtract`, `multiply` (mod 65536), `min`, `max` |
| Live values | `GET /api/v1/he/params` |
| Full parameter sheet | [`docs/parameters.md`](docs/parameters.md), generated from `core/src/params.rs` |

Uploaded keys and ciphertexts are deserialized with TFHE-rs's size-limited,
conformance-checked `safe_deserialize_conformant`, so keys made with other
parameters and malformed or foreign ciphertexts are rejected, not computed on.

### Accounts and sessions

- **Sessions.** Signing in returns a 15-minute access token and sets a refresh token
  as an `HttpOnly; Secure; SameSite=Strict` cookie scoped to `/api/v1/auth`. The
  dashboard keeps the access token in memory only, so page scripts can never read
  a long-lived credential. Every refresh rotates the cookie; replaying an old one
  (more than 10 seconds after it was rotated) revokes that whole session.
- **Cross-site requests.** Cookie-authenticated endpoints also refuse requests whose
  `Origin` is not the app's own (`APP_BASE_URL` or `ALLOWED_ORIGINS`).
- **Email links** (verification, password reset) open frontend pages that carry the
  token in the URL fragment and submit it with a POST. Opening a link (or a mail
  scanner prefetching it) changes nothing. Links work once; verification links
  expire after 24 hours and reset links after 1 hour. Tokens are stored hashed.
- **Google and GitHub sign-in** use the authorization-code flow with PKCE and a
  signed state cookie. Only provider-verified email addresses are accepted (GitHub:
  the verified primary address). The callback hands the browser a one-time code,
  never a token, which the page exchanges with `POST /api/v1/auth/exchange`.
- **Rate limits** are keyed on the client IP (the rightmost `X-Forwarded-For` hop not
  added by a `TRUSTED_PROXIES` address, so clients cannot choose their own) and on
  the target email address for sign-in attempts and outgoing email.
- **Sensitive changes.** Changing or resetting the password signs out every session.
  Deleting an account needs its password, or, for Google/GitHub-only accounts, a
  sign-in within the last 5 minutes.

### What the server can and cannot learn

The server **cannot** decrypt inputs or results: it only ever holds evaluation keys.

It **does** see metadata: your account, when you submit jobs, which operation each
job uses, ciphertext sizes and how many jobs you run.

Know these limits too:

- **Results are not verifiable.** A dishonest or compromised server could return a
  wrong ciphertext. TFHE alone does not prove that a computation was done correctly.
- **The dashboard trusts its own JavaScript.** The browser code that generates and
  stores your key is served by the operator. If you don't want to trust that code,
  use your own client, such as the [Rust SDK and `heaas` CLI](#rust-sdk-and-heaas-cli).
- **Your passphrase cannot be recovered.** Nobody, including the operator, can reset
  it. Without it (or without a backup file after clearing site data) the key and
  everything encrypted under it is lost.

### Your key in the browser

- **Generated and used in a Web Worker.** Key generation, encryption and decryption run
  in the TFHE worker; the page itself never holds the plaintext client key.
- **Stored sealed.** The worker encrypts the client key with AES-256-GCM under a key
  derived from your passphrase with PBKDF2-HMAC-SHA256 (600,000 iterations, the
  [OWASP recommendation](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html);
  WebCrypto offers no memory-hard KDF). The SHA-256 of the matching evaluation key is
  authenticated alongside, so a sealed key only opens for its own server key.
- **Unlocked per tab.** After a reload, the key must be unlocked with the passphrase
  again. Signing out stops the worker and forgets the unlocked key.
- **Backups.** *Export backup* on the Keys page downloads the sealed key as a JSON
  file (`heaas-key-….json`); it is useless without the passphrase. *Import backup*
  restores it in another browser after checking the passphrase and that the file
  matches one of your registered evaluation keys.
- Keys stored by earlier versions without a passphrase are sealed the first time they
  are unlocked.

---

## Using the dashboard

1. Register and verify your email, then sign in.
2. On **Keys**, choose a passphrase and **Generate encryption key**. Your browser
   creates the key pair (a few seconds), seals the secret key with the passphrase and
   uploads the ~60 MB evaluation key. Then **Export backup**.
3. On the **Dashboard**, choose an operation, enter two numbers and choose **Run**. The
   browser encrypts them, the server computes on the ciphertexts, and the browser
   decrypts the result and checks it against the expected value.
4. **Jobs** lists your past computations (paged) and decrypts their stored results.

The dashboard needs a browser with WebAssembly, Web Workers and `SharedArrayBuffer`,
and it must be served cross-origin isolated (see [Deployment](#deployment)).

## Using the API

The API lives under `/api/v1` and is described by an OpenAPI 3.1 document, served at
`GET /api/v1/openapi.json` and committed at [`docs/api/openapi.json`](docs/api/openapi.json)
(a test fails when it no longer matches the code). The unversioned `/api/...` paths
still answer, marked with `Deprecation` and `Link: </api/v1>; rel="successor-version"`
headers.

Every error has the same shape, whatever produced it (a handler, a malformed body,
an unknown route):

```json
{ "error": { "code": "not_found", "message": "Job not found" } }
```

`code` is stable and machine-readable (`bad_request`, `unauthorized`, `forbidden`,
`not_found`, `method_not_allowed`, `conflict`, `payload_too_large`,
`unsupported_media_type`, `unprocessable`, `rate_limited`, `unavailable`, `internal`);
`message` can be shown to people. `429` and `503` carry `Retry-After`.

### Rust SDK and `heaas` CLI

[`sdk/`](sdk) is a Rust client (`heaas-sdk`) built on the same `heaas-core` crate as
the server, so parameters and request types cannot drift apart. Keys are generated
and kept locally; only the evaluation key and ciphertexts are sent.

```rust
use heaas_sdk::{fhe, Client, Operation};

let client = Client::new("https://heaas.example.com")?;
client.login("you@example.com", "…").await?;
client.check_compatible().await?; // same TFHE-rs release and integer type

let (secret, server) = fhe::generate_keys();
let key = client.upload_key(fhe::server_key_bytes(&server)?).await?;
let (a, b) = (fhe::encrypt(&secret, 300)?, fhe::encrypt(&secret, 300)?);
let result = client.compute(&key.id, Operation::Multiply, &a, &b, timeout).await?;
assert_eq!(fhe::decrypt(&secret, &result)?, 24464); // 90000 mod 65536
```

Submissions carry an `Idempotency-Key` and are retried with it after a network error
or a full queue, so a job is never created (or charged) twice.

The `heaas` command-line tool does the same from a shell:

```sh
cargo install --path sdk           # or: cargo run -p heaas-sdk --release -- …
export HEAAS_URL=https://heaas.example.com HEAAS_EMAIL=you@example.com  # password is prompted
heaas keygen                       # heaas-client.key (secret, mode 0600) + heaas-server.key
heaas upload-key                   # prints the key id
heaas run --key-id <id> --op multiply 300 300    # 24464
# Step by step:
heaas encrypt 300 -o a.ct && heaas encrypt 7 -o b.ct
job=$(heaas submit --key-id <id> --op subtract a.ct b.ct)
heaas wait "$job" && heaas result "$job" -o r.ct && heaas decrypt r.ct   # 293
```

`heaas login` prints an access token for `HEAAS_TOKEN`; `heaas keys`, `heaas jobs` and
`heaas params` list keys, jobs and the server's parameters.

### Endpoints

| Method & path (under `/api/v1`) | Auth | Purpose |
|---|---|---|
| `GET /he/params` | — | Scheme, TFHE-rs version, integer type, operations, size limits |
| `POST /auth/register`, `POST /auth/login` | — | Account and session: `{token, expires_in, user}` plus an `HttpOnly` refresh cookie. `token` is a bearer token (15 minutes by default); `POST /auth/refresh` (with the cookie) renews it |
| `POST /keys` | Bearer | Body: `safe_serialize`d `CompressedServerKey` (`application/octet-stream`). Returns `201 {id, sha256, size_bytes, created_at}`. `409` when you already have the maximum number of keys |
| `GET /keys`, `DELETE /keys/{id}` | Bearer | List or remove your keys |
| `POST /compute/jobs` | Bearer | `{"key_id", "operation", "inputs": [b64, b64]}` (standard base64 of `safe_serialize`d `FheUint16`). Optional `Idempotency-Key` header. Returns `202` + `Location` and the job |
| `GET /compute/jobs/{id}` | Bearer | Job metadata. `status` is `pending`, `processing`, `completed` or `failed` (`error_message` set) |
| `GET /compute/jobs/{id}/result` | Bearer | The encrypted result (`application/octet-stream`, a `safe_serialize`d `FheUint16`). `409` until the job has completed |
| `GET /compute/jobs?limit=&cursor=` | Bearer | Your jobs, newest first: `{data, next_cursor}` (metadata only, `limit` 1–100, default 20) |
| `DELETE /compute/jobs/{id}` | Bearer | Deletes a job that is not running, with its ciphertexts (`204`; `409` while it runs) |

Jobs are durable: they are queued in the database, their ciphertexts are kept on
disk, and a fixed pool of workers runs them. A job interrupted by a restart runs
again; internal errors are retried (3 attempts, exponential backoff); a job
running longer than `JOB_TIMEOUT_SECS` fails. Finished jobs and their
ciphertexts are deleted after `JOB_RETENTION_DAYS`.

Each accepted job counts against a daily quota (default 100, resets at midnight
UTC; `429` with `Retry-After` when exceeded). Polling, listing and fetching
results are free. Resending a submission with the same `Idempotency-Key` returns
the original job (`Idempotent-Replayed: true`) and is not charged again; the same
key with a different request is rejected with `422`. When you already have
`MAX_ACTIVE_JOBS_PER_USER` jobs waiting or running you get `429`, and when the
whole queue is full `503`; both carry `Retry-After` and are not charged.

---

## Development

Requirements: Rust ≥ 1.91.1, Node.js 22 and pnpm 10.

```sh
# Backend: http://127.0.0.1:8080 (the repository root is a Cargo workspace:
# backend, core and sdk)
JWT_SECRET=dev-secret-at-least-32-bytes-long cargo run -p he-backend

# Frontend: http://localhost:3000/heaas (proxies /api to the backend)
cd frontend
pnpm install
pnpm dev
```

Without SMTP settings the backend logs email verification links instead of sending
them.

| Check | Command |
|---|---|
| Rust lint, tests (backend, core, SDK, CLI, OpenAPI drift) | `cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace` |
| Regenerate `docs/api/openapi.json` | `UPDATE_OPENAPI=1 cargo test -p he-backend openapi` |
| Supply chain | `cargo deny check` (workspace), `pnpm audit` (frontend) |
| Frontend types, unit tests | `pnpm check && pnpm test` |
| Browser tests (real TFHE WASM, mocked API) | `pnpm test:e2e` |
| Full stack (real backend, real browser TFHE) | `cargo build -p he-backend`, then `pnpm test:e2e:fullstack` |

Backend tests include end-to-end runs over HTTP, where the test plays the client:
it generates the keys and encrypts and decrypts, while the server only receives the
evaluation key and ciphertexts. One of them drives a real HTTP server through the SDK. CI (`.github/workflows/ci.yml`) runs all of the above.

### Configuration (backend)

Every setting is checked at startup. An invalid value (a typo, a number outside its
range, a client id without its secret) stops the server with exit code 2 and a list of
every problem found. Settings never fall back silently to a default. An empty value
counts as unset.

| Variable | Default | |
|---|---|---|
| `JWT_SECRET` | — (required, ≥ 32 bytes) | Secret from which token-signing and OAuth-state keys are derived (e.g. `openssl rand -base64 48`) |
| `DATABASE_URL` | `sqlite://./he_saas.db` | SQLite database |
| `KEY_STORE_DIR` | `./data/keys` | Uploaded server keys (~60 MB each) |
| `SERVER_ADDR` | `127.0.0.1:8080` | Listen address (`host:port`) |
| `MAX_SERVER_KEY_BYTES` | 80 MiB | Largest accepted key upload (1 MiB – 1 GiB) |
| `MAX_KEYS_PER_USER` | 2 | Server keys per account (1–100) |
| `KEY_CACHE_CAPACITY` | 2 | Decompressed keys kept in RAM, ~180 MB each (1–64) |
| `DAILY_COMPUTE_QUOTA` | 100 | Jobs per user per UTC day |
| `JOB_STORE_DIR` | `./data/jobs` | Job ciphertexts (inputs and results, ~132 KB each) |
| `HE_WORKERS` | 2 | Jobs evaluated at once (each TFHE operation already uses every core) |
| `JOB_TIMEOUT_SECS` | 300 | A job running longer fails |
| `MAX_JOB_ATTEMPTS` | 3 | Attempts per job before an internal error is final |
| `MAX_QUEUED_JOBS` | 1000 | Waiting + running jobs before submissions get `503` |
| `MAX_ACTIVE_JOBS_PER_USER` | 10 | Waiting + running jobs per user before submissions get `429` |
| `JOB_RETENTION_DAYS` | 7 | Finished jobs and their ciphertexts are deleted after this |
| `APP_BASE_URL` | — (required; debug builds: `http://localhost:3000`) | Public URL of the site; its origin may use the API and the session cookie, and email links and OAuth callbacks point to it |
| `ALLOWED_ORIGINS` | — (debug builds: `localhost:3000`, `:5173`) | Further browser origins allowed to call the API |
| `TRUSTED_PROXIES` | — | Comma-separated CIDRs of reverse proxies whose `X-Forwarded-For` is believed. Without it the TCP peer is the client, so behind nginx every user would share one rate-limit bucket |
| `COOKIE_SECURE` | `true` | `Secure` session cookies (HTTPS only; browsers also accept them on `http://localhost`) |
| `LOG_FORMAT` | `json` (debug builds: `pretty`) | Log output format, see [Observability](#observability) |
| `METRICS_TOKEN` | — | Enables `GET /metrics` with this bearer token (≥ 32 bytes) |
| `LOG_EMAIL_LINKS` | debug builds only | Without SMTP, log verification and reset links (they are credentials) |
| `ACCESS_TOKEN_TTL_SECS` | 900 | Access token lifetime (60–3600; they cannot be revoked) |
| `SESSION_TTL_DAYS` | 30 | How long a sign-in lasts (refresh cookie; 1–365) |
| `VERIFY_LINK_TTL_HOURS` | 24 | Email verification links (1–168) |
| `RESET_LINK_TTL_MINUTES` | 60 | Password reset links (5–1440) |
| `RATE_LIMIT_AUTH_PER_MINUTE` | 30 | `/api/v1/auth` requests per client IP |
| `RATE_LIMIT_LOGINS_PER_EMAIL` | 5 | Sign-in attempts per address per 15 minutes |
| `RATE_LIMIT_EMAILS_PER_IP_PER_HOUR` | 10 | Register / resend / forgot-password requests per client IP |
| `RATE_LIMIT_EMAILS_PER_ADDRESS_PER_HOUR` | 3 | Emails sent to one address (further ones are skipped silently) |
| `SMTP_HOST` | — | SMTP relay; without it no email is sent |
| `SMTP_TLS` | `starttls` | `starttls` (required STARTTLS), `implicit` (TLS from the start) or `none` (local relays only) |
| `SMTP_PORT` | 587 / 465 / 25 | Defaults to the port of the `SMTP_TLS` mode |
| `SMTP_USER`, `SMTP_PASS` | — | Relay credentials (both or neither) |
| `FROM_EMAIL` | — (required with `SMTP_HOST`) | Sender, e.g. `HEaaS <noreply@example.com>` |
| `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET` | — | OAuth sign-in (both of a pair or neither). Callback URLs: `<APP_BASE_URL>/api/v1/auth/google/callback`, `…/github/callback` |

### Deployment

`docker-compose.yml` builds and runs both services, published on `127.0.0.1` only:

```sh
cp .env.example .env   # or write .env: JWT_SECRET, APP_BASE_URL, SMTP_*, …
docker compose up -d --build
docker compose ps      # both "healthy"
```

- **Backend image:** built with cargo-chef (dependencies cached in their own layer)
  on a distroless base pinned by digest. It has no shell or package manager and runs
  as uid 65532. Its `HEALTHCHECK` runs `he-backend healthcheck`, which probes the
  readiness endpoint.
- **Frontend image:** the SvelteKit production build behind `frontend/server.js`, as
  the `node` user, with its own `HEALTHCHECK`. It starts only once the backend is
  healthy.
- **Hardening:** both containers have a read-only root filesystem, a `tmpfs` `/tmp`,
  no Linux capabilities (`cap_drop: ALL`) and `no-new-privileges`.
- **State:** everything lives in the named volume `heaas-data`, mounted at `/data`:
  the database, users' server keys and job ciphertexts.
- **Shutdown:** on `SIGTERM` the backend stops accepting requests and gives running
  jobs up to 30 seconds to finish (compose waits 40). Anything cut off is requeued
  at the next start.

nginx (`nginx-heaas.conf`) is the only public entry point. It terminates TLS (set
your certificate paths and `server_name`), sends HSTS, redirects HTTP to HTTPS,
serves the app under `/heaas/` and the API under `/api/`, and accepts request bodies
up to 96 MB for key uploads. Sessions use `Secure` cookies, so the site must be
served over HTTPS. Compose sets `TRUSTED_PROXIES` to cover nginx on the host and
the Docker networks; adjust it if your proxies live elsewhere.

TFHE's WebAssembly build uses shared memory, so **every** frontend response must be
sent with `Cross-Origin-Opener-Policy: same-origin` and
`Cross-Origin-Embedder-Policy: require-corp`. `frontend/server.js` (production) and
the Vite dev/preview servers do this. Keep it in place if you put another proxy in
front.

### Observability

**Logs.** Logs go to stdout as JSON lines (`LOG_FORMAT=json`, the default in release
builds; `pretty` for reading by eye), filtered by `RUST_LOG` (default `info`). Each
request gets an id: the caller's `X-Request-Id` if it is sane (≤ 64 characters of
`A-Z a-z 0-9 - _ . :`), else a new UUID. The id is returned in `X-Request-Id`, and every
line logged while handling the request carries it as `span.request_id`. Each request
logs one line with method, route pattern, status and latency. Jobs log with their
`job_id`, operation and attempt.

**Health.**

| Endpoint | Meaning |
|---|---|
| `GET /api/v1/health` | Liveness: the process answers |
| `GET /api/v1/health/ready` | Readiness: the database answers, the key and job stores accept new files, and every job worker is running. `200 {"status":"ready","checks":{…}}`, or `503` with the error envelope plus `checks` naming what failed |

**Metrics.** Set `METRICS_TOKEN` (≥ 32 bytes) to enable `GET /metrics` in the
Prometheus text format. Without the token the endpoint is `404`. nginx does not proxy
it, so scrape the backend directly:

```yaml
scrape_configs:
  - job_name: heaas
    authorization: { credentials: "<METRICS_TOKEN>" }
    static_configs: [{ targets: ["127.0.0.1:8080"] }]
```

| Metric | |
|---|---|
| `heaas_http_requests_total{method,route,status}`, `heaas_http_request_duration_seconds{method,route}` | Requests by route *pattern* (`/api/v1/compute/jobs/{id}`), never by concrete path |
| `heaas_jobs{status}`, `heaas_server_keys` | Queue depth and stored keys, sampled at each scrape |
| `heaas_job_wait_seconds{operation}` | Submission to start of an attempt |
| `heaas_job_evaluation_seconds{operation}` | Homomorphic evaluation time, key loading included |
| `heaas_jobs_finished_total{operation,outcome}` | Attempts that `completed`, were `rejected` (bad input), `retried`, `failed` or `timed_out` |
| `heaas_key_cache_lookups_total{result}` | Decompressed-key cache `hit`s and `miss`es (a miss costs ~0.5 s) |
| `heaas_workers_alive`, `heaas_workers_expected` | Job workers running and started |
| `heaas_build_info{version,tfhe_version}` | Always 1 |

### Backups

`./backup.sh` (as root, e.g. daily from cron) has the running backend write a backup
into `BACKUP_DIR` (default `/var/backups/heaas`, mounted in the container at
`/backups`). It then packs it as `heaas_<UTC time>.tar.gz` (mode `0600`) and deletes
archives older than `KEEP_DAYS` (default 7).

A backup holds:
- `he_saas.db`: a consistent SQLite snapshot (`VACUUM INTO`), taken while the server
  runs;
- `keys/`: users' server keys, needed to run their queued jobs;
- `jobs/`: job ciphertexts, including results not yet fetched.

None of these contain a secret key. Outside Docker, run `he-backend backup <new
directory>` with the server's environment.

**Restore:** stop the stack, then unpack the archive into the volume, owned by uid
65532. The archive contains a directory named after it, so `--strip-components=1`
puts its contents straight into `/data`:

```sh
docker compose down
docker run --rm -v heaas-data:/data -v /var/backups/heaas:/b:ro debian:bookworm-slim \
  sh -c 'rm -rf /data/* && tar -xzf /b/heaas_<time>.tar.gz -C /data --strip-components=1 && chown -R 65532:65532 /data'
docker compose up -d
```

**Upgrading from the `./data` bind mount** (before this release): with the stack
stopped, copy the old files into the volume once:

```sh
docker compose down
docker volume create heaas-data
docker run --rm -v heaas-data:/data -v "$PWD/data":/old:ro debian:bookworm-slim \
  sh -c 'cp -a /old/. /data/ && chown -R 65532:65532 /data'
docker compose up -d
```

## Licensing

TFHE-rs is distributed under BSD-3-Clause-Clear, which grants no patent rights.
Zama states that TFHE-rs is free for development, research, prototyping and
experimentation, and that **commercial use requires Zama's patent licence**. Obtain
that licence before running this service commercially.

This repository has no licence file yet. Until its owner adds one, no licence to
use, copy or modify the code is granted.
