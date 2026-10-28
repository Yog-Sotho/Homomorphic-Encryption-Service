<div align="center">
<img src="./he-saas-logo.svg" alt="HEaaS Logo" width="400"/>
</div>

# HEaaS user guide

HEaaS lets you run arithmetic on numbers it never sees. Your device encrypts them, the
service computes on the encrypted values, and only your device can decrypt the result.

This guide covers the web dashboard and the API. For how the system works and what it
does and does not protect, see the [README](README.md#what-the-server-can-and-cannot-learn)
and [SECURITY.md](SECURITY.md); the exact cryptographic parameters are in
[`docs/parameters.md`](docs/parameters.md).

---

## 1. Your keys

HEaaS uses two keys, both generated on your device:

| Key | Size | Where it lives | What it can do |
|---|---|---|---|
| **Client key** (secret) | ~31 KB | Only on your device (in the dashboard, this browser's storage, encrypted with your passphrase) | Encrypt and decrypt |
| **Server key** (evaluation key) | ~60 MB | Uploaded to HEaaS | Compute on your ciphertexts, but **not** decrypt them |

The service never receives your client key, so it cannot read your data.

**Your passphrase protects your client key.** In the dashboard the key is stored only
in the browser you generated it in, encrypted with a passphrase you choose. You enter
the passphrase once per tab to unlock the key. Nobody can reset a forgotten
passphrase, not even the operator.

**Back up your key.** On the **Keys** page, **Export backup** downloads the encrypted
key as a file. With that file and the passphrase you can **Import backup** in another
browser or after clearing this one. Without either, the key and everything encrypted
under it is lost.

Each account can register up to 2 server keys (the operator can change this).

## 2. Using the dashboard

1. **Create an account** and verify your email address through the link sent to you.
2. **Sign in.**
3. **Create a key.** On **Keys**, choose a passphrase (at least 10 characters), enter
   it twice and choose **Generate encryption key**. Your browser creates the key pair
   in a few seconds, then uploads the ~60 MB server key. Choose **Export backup** and
   keep the file somewhere safe. On the **Dashboard** the key now shows **Ready**.
   After a reload, enter the passphrase there to unlock it again.
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

**Past jobs.** **Jobs** lists your computations, newest first. Completed results can
be decrypted there while their key is unlocked; finished jobs are deleted after a few
days.

**Keys from another browser.** The **Keys** page marks keys whose client key is not in
this browser as *Not in this browser*. Use **Import backup** with the exported file
and its passphrase, or delete the key if you need room for a new one.

## 3. Using the API

Use the API to encrypt on your own systems. Every path below is under `/api/v1`
(the older unversioned `/api/...` paths still work but are deprecated). The full
description is the OpenAPI document at `GET /api/v1/openapi.json`.

**From Rust or a shell**, use the SDK and the `heaas` command-line tool in
[`sdk/`](sdk). They generate your keys locally, check that the server is compatible,
and retry safely:

```sh
export HEAAS_URL=https://<your HEaaS site> HEAAS_EMAIL=you@example.com
heaas keygen         # heaas-client.key is your secret key: keep it (and a backup) safe
heaas upload-key     # prints the key id
heaas run --key-id <key id> --op multiply 300 300    # prints 24464
```

**From other languages**, your client must use **TFHE-rs 1.8.2** with
`ConfigBuilder::default()`, and serialize keys and ciphertexts with
`tfhe::safe_serialization::safe_serialize`.

### Errors

Every error response has the same body:

```json
{ "error": { "code": "not_found", "message": "Job not found" } }
```

Branch on `code` (for example `unauthorized`, `not_found`, `conflict`,
`payload_too_large`, `unprocessable`, `rate_limited`, `unavailable`) and show `message`
to people. A malformed JSON body is `400`, a body of the wrong type `415`, one that is
too large `413`, and a well-formed body with an invalid value (such as an unknown
`operation`) `422`.

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

## 4. Troubleshooting

| What you see | Why | What to do |
|---|---|---|
| "In-browser encryption needs a cross-origin isolated page" | The browser or the deployment does not allow `SharedArrayBuffer`, which TFHE's WebAssembly needs | Use a current Chrome, Edge, Firefox or Safari. Operators: serve the frontend with the COOP/COEP headers described in the README |
| `409` "You already have 2 server keys" | Your account has reached its key limit | Delete a key you no longer use |
| `400` "Not a compressed server key for this service's parameters" | The key was made with different parameters or a different TFHE-rs release | Generate it with TFHE-rs 1.8.2 and `ConfigBuilder::default()` |
| `413 Payload Too Large` | The upload is over the size limit | Upload only the compressed server key, never the full server key |
| Job `failed`: "Input 1 is not a valid FheUint16 ciphertext for this key" | The input is not an `FheUint16`, is corrupted, or was made with other parameters | Encrypt with the client key that belongs to `key_id` and `safe_serialize` the result |
| `404` "Server key not found" | The key id is wrong, deleted, or belongs to another account | List your keys with `GET /api/v1/keys` (or `heaas keys`) |
| `429` "Too many sign-in attempts for this account" | Several failed sign-ins in a short time | Wait the `Retry-After` seconds, or reset your password |
| Verification or reset link says "Invalid or expired" | Links work once; verification links last 24 hours and reset links 1 hour (unless the operator changed this; the email says how long) | Request a new one from the sign-in page |
| "For your security, sign in again" when deleting a Google/GitHub account | Deleting an account without a password needs a fresh sign-in | Sign out, sign in again, then delete within 5 minutes |
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

**What if I lose my client key or forget its passphrase?**
Import your backup file if you have one (it needs the same passphrase). Otherwise
nothing encrypted under the key can be decrypted any more, by you or anyone else.
Generate a new key; the old server key can be deleted.

**Which numbers are supported?**
Unsigned 16-bit integers (0–65535) with add, subtract, multiply (all mod 65536), min
and max.
