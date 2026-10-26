<div align="center">
<img src="./he-saas-logo.svg" alt="HEaaS Logo" width="400"/>
</div>

# HEaaS user guide

HEaaS lets you run arithmetic on numbers it never sees. Your device encrypts them, the
service computes on the encrypted values, and only your device can decrypt the result.

This guide covers the web dashboard and the API. For how the system works and what it
does and does not protect, see the [README](README.md#what-the-server-can-and-cannot-learn).

---

## 1. Your keys

HEaaS uses two keys, both generated on your device:

| Key | Size | Where it lives | What it can do |
|---|---|---|---|
| **Client key** (secret) | ~31 KB | Only on your device (in the dashboard, this browser's storage) | Encrypt and decrypt |
| **Server key** (evaluation key) | ~60 MB | Uploaded to HEaaS | Compute on your ciphertexts, but **not** decrypt them |

The service never receives your client key, so it cannot read your data.

**Keep your client key safe.** In the dashboard it is stored only in the browser you
generated it in. Clearing that browser's site data deletes it, and anything encrypted
under it can then no longer be decrypted. Another browser or device cannot use it.

Each account can register up to 2 server keys (the operator can change this).

## 2. Using the dashboard

1. **Create an account** and verify your email address through the link sent to you.
2. **Sign in** and open the dashboard.
3. **Generate a key.** Choose **Generate encryption key**. Your browser creates the key
   pair in a few seconds, then uploads the ~60 MB server key. When the key shows
   **Ready**, you can compute.
4. **Compute.** Choose an operation, enter two whole numbers between 0 and 65535, and
   choose **Run**. The dashboard shows each step:
   - *Encrypting in your browser*
   - *Sending ciphertexts* (two encrypted values, ~260 KB in total)
   - *Server computing on encrypted data*
   - *Decrypting in your browser*
5. **Read the result.** The result is decrypted in your browser and compared with the
   value the dashboard expected. **Matches expected** confirms the round trip.

Operations: **Add**, **Subtract**, **Multiply**, **Min**, **Max**. Values are unsigned
16-bit integers, so add, subtract and multiply wrap around modulo 65536. For example,
300 × 300 = 90000, which wraps to 24464, and 3 − 10 wraps to 65529.

**Keys from another browser.** If you registered keys elsewhere, the dashboard lists
them under *key(s) registered from another browser*. It cannot use them because it
does not have their client keys. Delete them there if you need room for a new key.

## 3. Using the API

Use the API to encrypt on your own systems. The complete flow, as a small Rust
program, is in [`backend/examples/client.rs`](backend/examples/client.rs). Your client
must use **TFHE-rs 1.8.2** with `ConfigBuilder::default()`, and serialize keys and
ciphertexts with `tfhe::safe_serialization::safe_serialize`.

### Authentication

`POST /api/auth/login` with `{"email", "password"}` returns `{"token", "refresh_token", "user"}`.
Send `Authorization: Bearer <token>` on every request below. Tokens last one hour;
renew them with `POST /api/auth/refresh` and `{"refresh_token"}`.

### Parameters

`GET /api/he/params` (no authentication) returns the scheme, the TFHE-rs version, the
integer type, the supported operations and the size limits. Check it before you
generate keys.

### Register a server key

```
POST /api/keys
Content-Type: application/octet-stream
<body: safe_serialize(CompressedServerKey::new(&client_key))>

201 Created
{ "id": "8e521fee-…", "sha256": "…", "size_bytes": 60228265, "created_at": "…" }
```

`GET /api/keys` lists your keys. `DELETE /api/keys/{id}` removes one (`204`).

### Submit a job

```
POST /api/compute/jobs
Idempotency-Key: 5b0c…            (optional, recommended)
{ "key_id": "8e521fee-…", "operation": "multiply", "inputs": ["<base64>", "<base64>"] }

202 Accepted
Location: /api/compute/jobs/3f2a…
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

Poll `GET /api/compute/jobs/{id}` until `status` is `completed` or `failed`. Then
`GET /api/compute/jobs/{id}/result` returns the encrypted result as raw bytes
(`application/octet-stream`): `safe_deserialize` it as `FheUint16` and decrypt it with
your client key. If `status` is `failed`, `error_message` says why.

Jobs survive server restarts, and the server retries a job itself if it hits an
internal error. `attempts` shows how many times it has been started.

### List and delete jobs

`GET /api/compute/jobs` lists your jobs, newest first, 20 at a time (`?limit=` up to
100). When `next_cursor` is not null, pass it as `?cursor=` for the next page.
`DELETE /api/compute/jobs/{id}` deletes a finished or waiting job and its ciphertexts.
Finished jobs are deleted automatically after 7 days (the operator can change this),
so fetch results before then.

### Quotas and limits

Each accepted job counts against a daily quota (100 by default, reset at midnight
UTC). Checking status, listing jobs and fetching results do not count. You can have
up to 10 jobs waiting or running at once. Responses that ask you to slow down carry a
`Retry-After` header with the number of seconds to wait, and refused submissions are
not charged.

## 4. Troubleshooting

| What you see | Why | What to do |
|---|---|---|
| "In-browser encryption needs a cross-origin isolated page" | The browser or the deployment does not allow `SharedArrayBuffer`, which TFHE's WebAssembly needs | Use a current Chrome, Edge, Firefox or Safari. Operators: serve the frontend with the COOP/COEP headers described in the README |
| `409` "You already have 2 server keys" | Your account has reached its key limit | Delete a key you no longer use |
| `400` "Not a compressed server key for this service's parameters" | The key was made with different parameters or a different TFHE-rs release | Generate it with TFHE-rs 1.8.2 and `ConfigBuilder::default()` |
| `413 Payload Too Large` | The upload is over the size limit | Upload only the compressed server key, never the full server key |
| Job `failed`: "Input 1 is not a valid FheUint16 ciphertext for this key" | The input is not an `FheUint16`, is corrupted, or was made with other parameters | Encrypt with the client key that belongs to `key_id` and `safe_serialize` the result |
| `404` "Server key not found" | The key id is wrong, deleted, or belongs to another account | List your keys with `GET /api/keys` |
| `429` "Daily compute quota … reached" | You submitted the maximum number of jobs today | Wait until midnight UTC (`Retry-After` says how long) |
| `429` "You have N jobs waiting or running" | Too many of your jobs are unfinished | Wait for some to finish, then resubmit |
| `503` "The job queue is full" | The service is busy | Retry after the `Retry-After` seconds |
| `422` "This Idempotency-Key was already used for a different request" | You reused a key for a new request | Use a new key for each new job |
| `409` on `…/result` | The job has not completed | Poll the job until `status` is `completed` |
| Job `failed`: "Timed out after N seconds" | The computation took longer than the server allows | Contact the operator |
| The decrypted value is meaningless | You decrypted with a different client key than the one the inputs were encrypted with | Use the client key that matches the job's `key_id` |

## 5. FAQ

**Can HEaaS read my numbers?**
No. It has only your server key, which cannot decrypt. It does see metadata: when you
submit jobs, which operation each uses and how many you run.

**Can I check that the server computed correctly?**
Not cryptographically: TFHE does not prove correctness. The dashboard compares each
result with the value it expected, which catches errors for the values you test.

**What if I lose my client key?**
Nothing encrypted under it can be decrypted any more, by you or anyone else. Generate
a new key; the old server key can be deleted.

**Which numbers are supported?**
Unsigned 16-bit integers (0–65535) with add, subtract, multiply (all mod 65536), min
and max.
