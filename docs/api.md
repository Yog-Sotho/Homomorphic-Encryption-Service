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

Other types, plain operands, sums and proven inputs go through `submit_job` /
`compute_job` with a `CreateJobRequest`, and `fhe::encrypt_as`, `fhe::decrypt_as` and
`fhe::prove`:

```rust
use heaas_sdk::{api::CreateJobRequest, encode, IntegerType};

// Proofs need the public key uploaded for the key, and the server's CRS.
let public_key = fhe::public_key(&secret);
client.upload_public_key(&key.id, fhe::public_key_bytes(&public_key)?).await?;
let list = fhe::prove(&public_key, &client.crs().await?, &key.id, IntegerType::I32, &[-5, 12, 30])?;
let request = CreateJobRequest {
    key_id: key.id.clone(),
    operation: Operation::Sum,
    integer_type: IntegerType::I32,
    inputs: vec![],
    proven_inputs: Some(encode(&list)),
    scalar: None,
};
let (job, result) = client.compute_job(&request, timeout).await?;
println!("{}", fhe::decrypt_as(&secret, job.result_type, &result)?); // 37
```

Programs come from expressions with `parse_expression` (the same parser the CLI uses);
`submit_batch` queues several requests at once:

```rust
use heaas_sdk::parse_expression;

let compiled = parse_expression("(a + b) * 3 < c ? a : b")?;
let request = CreateJobRequest {
    key_id: key.id.clone(),
    operation: Operation::Program,
    integer_type: IntegerType::I16,
    inputs: [5, 7, 100].iter().map(|&v| Ok(encode(&fhe::encrypt_as(&secret, IntegerType::I16, v)?))).collect::<heaas_sdk::Result<_>>()?,
    proven_inputs: None,
    scalar: None,
    program: Some(compiled.program),
};
let jobs = client.submit_batch(&[request.clone(), request]).await?; // both, or neither
```

Submissions carry an `Idempotency-Key` and are retried with it after a network error
or a full queue, so a job is never created (or charged) twice.

The `heaas` command-line tool does the same from a shell:

```sh
cargo install --path sdk           # or: cargo run -p heaas-sdk --release -- …
export HEAAS_URL=https://heaas.example.com HEAAS_EMAIL=you@example.com  # password is prompted
heaas keygen                       # heaas-client.key (secret, mode 0600), heaas-server.key, heaas-public.key
heaas upload-key                   # uploads the server and public keys; prints the key id
heaas run --key-id <id> --op multiply 300 300               # 24464
heaas run --key-id <id> --op lt --type i32 -- -5 3           # true
heaas run --key-id <id> --op add --type u64 --scalar 10 5    # 15 (10 is sent unencrypted)
heaas run --key-id <id> --op sum --type u8 --prove 200 100 1 # 45, with proven inputs
heaas run --key-id <id> --type i16 --expr "(a + b) * 3 < c ? a - b : b - a" 5 7 100   # -2
# Step by step:
heaas encrypt 300 -o a.ct && heaas encrypt 7 -o b.ct
job=$(heaas submit --key-id <id> --op subtract a.ct b.ct)
heaas wait "$job" && heaas result "$job" -o r.ct && heaas decrypt r.ct   # 293
# A comparison's result is a boolean: heaas decrypt --type bool r.ct
# Proven inputs: heaas prove --key-id <id> --type u8 -o list.bin 1 2 3
#                heaas submit --key-id <id> --op sum --type u8 --proven list.bin
```

`heaas login` prints an access token for `HEAAS_TOKEN`; `heaas keys`, `heaas jobs` and
`heaas params` list keys, jobs and the server's parameters.

## Endpoints

| Method & path (under `/api/v1`) | Auth | Purpose |
|---|---|---|
| `GET /he/params` | — | Scheme, TFHE-rs version, integer types, operations, size limits, and `proofs` (the CRS hash and proof limits) |
| `GET /he/crs` | — | The CRS proven inputs are made against (`application/octet-stream`, ~2 MB, with an `ETag`) |
| `POST /auth/register`, `POST /auth/login` | — | Account and session: `{token, expires_in, user}` plus an `HttpOnly` refresh cookie. `token` is a bearer token (15 minutes by default); `POST /auth/refresh` (with the cookie) renews it |
| `POST /keys` | Bearer | Body: `safe_serialize`d `CompressedServerKey` (`application/octet-stream`). Returns `201 {id, sha256, size_bytes, created_at, supports_proofs, has_public_key}`. `409` when you already have the maximum number of keys |
| `PUT /keys/{id}/public-key` | Bearer | Body: `safe_serialize`d `CompactPublicKey` made from the same client key. Needed for proven inputs; `422` for keys made before 0.5 |
| `GET /keys`, `DELETE /keys/{id}` | Bearer | List or remove your keys |
| `POST /compute/jobs` | Bearer | `{"key_id", "operation", "integer_type", "inputs": [b64, …]}`, or `"proven_inputs": b64` instead of `inputs`, optionally `"scalar"`, and `"program"` for `operation: "program"` (see [Submit a job](#submit-a-job) and [Programs](#programs)). Optional `Idempotency-Key` header. Returns `202` + `Location` and the job |
| `POST /compute/jobs/batch` | Bearer | `{"jobs": [job, …]}`: 1 to `max_batch_jobs` (16) jobs as above, queued together or not at all (`202 {"jobs": [...]}`, in order). One bad job refuses the batch (`400 "Job 2: …"`); not enough quota or room refuses it too, charging nothing. An `Idempotency-Key` covers the whole batch |
| `GET /compute/jobs/{id}` | Bearer | Job metadata. `status` is `pending`, `processing`, `completed` or `failed` (`error_message` set); `result_type` says how to decrypt the result |
| `GET /compute/jobs/{id}/result` | Bearer | The encrypted result (`application/octet-stream`, a `safe_serialize`d ciphertext of the job's `result_type`). `409` until the job has completed |
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
plus `use_dedicated_compact_public_key_parameters((PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128))`, and serialize keys and
ciphertexts with `tfhe::safe_serialization::safe_serialize`. (Keys made with
`ConfigBuilder::default()` alone are accepted too, but cannot take proven inputs.)

### Authentication

`POST /api/v1/auth/login` with `{"email", "password"}` returns `{"token", "expires_in", "user"}`
and sets a refresh cookie (`heaas_refresh`). Send `Authorization: Bearer <token>` on
every request below. Tokens last 15 minutes (`expires_in` seconds). To renew one,
`POST /api/v1/auth/refresh` with the cookie (keep a cookie jar in your HTTP client),
or simply sign in again. Each refresh replaces the cookie; reusing an old one ends
the session.

### Parameters

`GET /api/v1/he/params` (no authentication) returns the scheme, the TFHE-rs version, the
integer types, the supported operations, the size limits and `proofs`. Check it
before you generate keys.

### Register a server key

```
POST /api/v1/keys
Content-Type: application/octet-stream
<body: safe_serialize(CompressedServerKey::new(&client_key))>

201 Created
{ "id": "8e521fee-…", "sha256": "…", "size_bytes": 60228265, "created_at": "…" }
```

Then attach the public key, for proven inputs:

```
PUT /api/v1/keys/8e521fee-…/public-key
Content-Type: application/octet-stream
<body: safe_serialize(CompactPublicKey::new(&client_key))>

200 OK
{ "id": "8e521fee-…", …, "supports_proofs": true, "has_public_key": true }
```

Keep that public key: proofs must be made with the one you uploaded.

`GET /api/v1/keys` lists your keys. `DELETE /api/v1/keys/{id}` removes one (`204`).

### Submit a job

```
POST /api/v1/compute/jobs
Idempotency-Key: 5b0c…            (optional, recommended)
{ "key_id": "8e521fee-…", "operation": "multiply", "inputs": ["<base64>", "<base64>"] }

202 Accepted
Location: /api/v1/compute/jobs/3f2a…
{ "id": "3f2a…", "status": "pending", "operation": "multiply", "integer_type": "u16",
  "result_type": "u16", "input_count": 2, "proven": false, "scalar": null, "key_id": "8e521fee-…",
  "attempts": 0, "error_message": null, "input_bytes": 264202, "result_bytes": null,
  "created_at": "…", "started_at": null, "finished_at": null }
```

- `integer_type` is `u8`, `u16` (the default), `u32`, `u64`, `i8`, `i16`, `i32` or `i64`.
  Each input is the standard base64 of a `safe_serialize`d ciphertext of that type
  (`FheUint16`, `FheInt32`, …) encrypted with the client key that belongs to `key_id`.
- `operation` is `add`, `subtract`, `multiply` (wrapping), `min`, `max`, a comparison
  (`eq`, `ne`, `lt`, `le`, `gt`, `ge`, whose result is an `FheBool`) or `sum`.
- Binary operations take two inputs, or one input and a `scalar`: a decimal string
  in the type's range, used as the right-hand operand in the clear. `sum` takes 2 to
  `max_inputs` (16) inputs and no scalar. All inputs together are limited to
  `max_job_input_bytes`.
- **Proven inputs.** Instead of `inputs`, send `proven_inputs`: one
  `ProvenCompactCiphertextList` holding every input, encrypted under the key's public
  key and proven with `build_with_proof_packed` against the CRS from `GET /he/crs`,
  with metadata `he-engine/proof/v1/<key_id>` (`proofs.metadata_prefix` plus the key
  id). The server rejects malformed lists at submission and lists whose proof does
  not verify when the job runs.

```
{ "key_id": "8e521fee-…", "operation": "lt", "integer_type": "i32",
  "inputs": ["<base64>"], "scalar": "-4" }
```

**Idempotency.** If a submission fails with a network error, resend it with the same
`Idempotency-Key` (any unique string of up to 255 visible ASCII characters, such as a
UUID). You get the original job back, marked `Idempotent-Replayed: true`, instead of
a second job, and you are not charged twice.

### Programs

`"operation": "program"` runs the request's `program`: a list of steps, each an
operation on job inputs (`{"input": 0}`), results of earlier steps (`{"step": 1}`)
or plaintext constants (`{"const": "-3"}`). The last step is the result; its type is
the job's `result_type`.

```
{ "key_id": "8e521fee-…", "operation": "program", "integer_type": "i16",
  "inputs": ["<a>", "<b>", "<c>"],
  "program": { "steps": [
    { "op": "add",      "args": [{ "input": 0 }, { "input": 1 }] },
    { "op": "multiply", "args": [{ "step": 0 }, { "const": "3" }] },
    { "op": "lt",       "args": [{ "step": 1 }, { "input": 2 }] },
    { "op": "subtract", "args": [{ "input": 0 }, { "input": 1 }] },
    { "op": "subtract", "args": [{ "input": 1 }, { "input": 0 }] },
    { "op": "select",   "args": [{ "step": 2 }, { "step": 3 }, { "step": 4 }] }
  ] } }
```

Step operations: `add`, `subtract`, `multiply`, `divide`, `remainder`, `min`, `max`
and the comparisons (`eq` … `ge`) take two arguments, the second encrypted or a
constant; `and`, `or`, `xor` work on two integers (bitwise) or two booleans; `not`
takes one of either; `neg` and `abs` (signed types) one integer; `shl`, `shr`,
`rotl`, `rotr` an integer and a constant from 0 to bits − 1; `select` a boolean and
two encrypted integers. The first argument is always encrypted. Programs have 1 to
`max_program_steps` (64) steps; the server checks them before queuing and answers
`400` with the step at fault. [How it works](how-it-works.md#programs) gives the
semantics, and `heaas_core::parse_expression` (Rust) or
`frontend/src/lib/fhe/program.ts` compile the expression syntax into steps.

### Get the result

Poll `GET /api/v1/compute/jobs/{id}` until `status` is `completed` or `failed`. Then
`GET /api/v1/compute/jobs/{id}/result` returns the encrypted result as raw bytes
(`application/octet-stream`): `safe_deserialize` it as the job's `result_type`
(`FheUint16` for `u16`, `FheBool` for `bool`, …) and decrypt it with your client key.
If `status` is `failed`, `error_message` says why.

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
