# Using the API

The API lives under `/api/v1` and is described by an OpenAPI 3.1 document, served at
`GET /api/v1/openapi.json` and committed at [`docs/api/openapi.json`](api/openapi.json)
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

## Rust SDK and `heaas` CLI

[`sdk/`](../sdk) is a Rust client (`heaas-sdk`) built on the same `heaas-core` crate as
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

## Endpoints

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

## The API step by step

These examples show the raw HTTP exchanges (paths under `/api/v1`). Clients in
languages other than Rust must use **TFHE-rs 1.8.2** with `ConfigBuilder::default()`
and serialize keys and ciphertexts with `tfhe::safe_serialization::safe_serialize`.

### Authentication

`POST /api/v1/auth/login` with `{"email", "password"}` returns `{"token", "expires_in", "user"}`
and sets a refresh cookie (`heaas_refresh`). Send `Authorization: Bearer <token>` on
every request below. Tokens last 15 minutes (`expires_in` seconds). To renew one,
`POST /api/v1/auth/refresh` with the cookie (keep a cookie jar in your HTTP client),
or simply sign in again. Each refresh replaces the cookie; reusing an old one ends
the session.

### Parameters

`GET /api/v1/he/params` (no authentication) returns the scheme, the TFHE-rs version, the
integer type, the supported operations and the size limits. Check it before you
generate keys.

### Register a server key

```
POST /api/v1/keys
Content-Type: application/octet-stream
<body: safe_serialize(CompressedServerKey::new(&client_key))>

201 Created
{ "id": "8e521fee-…", "sha256": "…", "size_bytes": 60228265, "created_at": "…" }
```

`GET /api/v1/keys` lists your keys. `DELETE /api/v1/keys/{id}` removes one (`204`).

### Submit a job

```
POST /api/v1/compute/jobs
Idempotency-Key: 5b0c…            (optional, recommended)
{ "key_id": "8e521fee-…", "operation": "multiply", "inputs": ["<base64>", "<base64>"] }

202 Accepted
Location: /api/v1/compute/jobs/3f2a…
{ "id": "3f2a…", "status": "pending", "operation": "multiply", "key_id": "8e521fee-…",
  "attempts": 0, "error_message": null, "input_bytes": 264202, "result_bytes": null,
  "created_at": "…", "started_at": null, "finished_at": null }
```

Each input is the standard base64 of a `safe_serialize`d `FheUint16` encrypted with
the client key that belongs to `key_id`. `operation` is one of `add`, `subtract`,
`multiply`, `min` or `max`.

**Idempotency.** If a submission fails with a network error, resend it with the same
`Idempotency-Key` (any unique string of up to 255 visible ASCII characters, such as a
UUID). You get the original job back, marked `Idempotent-Replayed: true`, instead of
a second job, and you are not charged twice.

### Get the result

Poll `GET /api/v1/compute/jobs/{id}` until `status` is `completed` or `failed`. Then
`GET /api/v1/compute/jobs/{id}/result` returns the encrypted result as raw bytes
(`application/octet-stream`): `safe_deserialize` it as `FheUint16` and decrypt it with
your client key. If `status` is `failed`, `error_message` says why.

Jobs survive server restarts, and the server retries a job itself if it hits an
internal error. `attempts` shows how many times it has been started.

### List and delete jobs

`GET /api/v1/compute/jobs` lists your jobs, newest first, 20 at a time (`?limit=` up to
100). When `next_cursor` is not null, pass it as `?cursor=` for the next page.
`DELETE /api/v1/compute/jobs/{id}` deletes a finished or waiting job and its ciphertexts.
Finished jobs are deleted automatically after 7 days (the operator can change this),
so fetch results before then.

### Quotas and limits

Each accepted job counts against a daily quota (100 by default, reset at midnight
UTC). Checking status, listing jobs and fetching results do not count. You can have
up to 10 jobs waiting or running at once. Responses that ask you to slow down carry a
`Retry-After` header with the number of seconds to wait, and refused submissions are
not charged.
