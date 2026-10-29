# Self-hosting

How to run the HE Engine on your own server: deployment, configuration, monitoring and
backups. For development setup and the checks a change must pass, see
[CONTRIBUTING.md](../CONTRIBUTING.md).

## Deployment

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

## Configuration

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
| `FROM_EMAIL` | — (required with `SMTP_HOST`) | Sender, e.g. `HE Engine <noreply@example.com>` |
| `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET` | — | OAuth sign-in (both of a pair or neither). Callback URLs: `<APP_BASE_URL>/api/v1/auth/google/callback`, `…/github/callback` |

## Observability

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

## Backups

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
