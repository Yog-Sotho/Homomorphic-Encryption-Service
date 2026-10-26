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

> **Status:** working end to end, under active hardening. See
> [`docs/project/codebase_audit.md`](docs/project/codebase_audit.md) and the
> [remediation plan](docs/project/remediation_plan.md) for what is still to come.

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
 4. fetch encrypted result  ◀───────────────────── returns a ciphertext
 5. decrypt locally
```

- **Client key** (~31 KB): generated on your device, used to encrypt and decrypt.
  It is never uploaded. In the dashboard it stays in the browser's IndexedDB.
- **Compressed server key** (~60 MB): an evaluation key derived from the client key.
  It lets the server compute on your ciphertexts but not decrypt them. You register
  it once with `POST /api/keys`; the server checks it against its parameters.
- **Ciphertexts** (~132 KB each): `FheUint16` values. Arithmetic wraps modulo 2¹⁶.

### Parameters

| | |
|---|---|
| Scheme | TFHE (CGGI), TFHE-rs **1.8.2** (pinned; clients must use the same release) |
| Configuration | `ConfigBuilder::default()`: TFHE-rs default parameters (`PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128`, failure probability ≤ 2⁻¹²⁸) |
| Integer type | `FheUint16` (0–65535) |
| Operations | `add`, `subtract`, `multiply` (mod 65536), `min`, `max` |
| Live values | `GET /api/he/params` |

Uploaded keys and ciphertexts are deserialized with TFHE-rs's size-limited,
conformance-checked `safe_deserialize_conformant`, so keys made with other
parameters and malformed or foreign ciphertexts are rejected, not computed on.

### What the server can and cannot learn

The server **cannot** decrypt inputs or results: it only ever holds evaluation keys.

It **does** see metadata: your account, when you submit jobs, which operation each
job uses, ciphertext sizes and how many jobs you run.

Know these limits too:

- **Results are not verifiable.** A dishonest or compromised server could return a
  wrong ciphertext. TFHE alone does not prove that a computation was done correctly.
- **The dashboard trusts its own JavaScript.** The browser code that generates and
  stores your key is served by the operator. If you don't want to trust that code,
  use your own client, such as [`backend/examples/client.rs`](backend/examples/client.rs).
- **The client key in the browser is not backed up.** It is stored unencrypted in this
  browser's IndexedDB. Clearing site data loses it, and anything encrypted under it
  can then no longer be decrypted. (Passphrase-protected storage and export are planned.)

---

## Using the dashboard

1. Register and verify your email, then sign in.
2. On the dashboard, choose **Generate encryption key**. Your browser creates the key
   pair (a few seconds) and uploads the ~60 MB evaluation key.
3. Choose an operation, enter two numbers and choose **Run**. The browser encrypts
   them, the server computes on the ciphertexts, and the browser decrypts the result
   and checks it against the expected value.

The dashboard needs a browser with WebAssembly, Web Workers and `SharedArrayBuffer`,
and it must be served cross-origin isolated (see [Deployment](#deployment)).

## Using the API

All endpoints are under `/api`. The full client flow is in
[`backend/examples/client.rs`](backend/examples/client.rs), which CI compiles:

```sh
HEAAS_URL=http://localhost:8080 HEAAS_EMAIL=you@example.com HEAAS_PASSWORD='…' \
  cargo run --release --manifest-path backend/Cargo.toml --example client -- 300 300
# registered server key 8e52…
# 300 × 300 mod 65536 = 24464
```

| Method & path | Auth | Purpose |
|---|---|---|
| `GET /api/he/params` | — | Scheme, TFHE-rs version, integer type, operations, size limits |
| `POST /api/auth/register`, `POST /api/auth/login` | — | Account and bearer token (`token`, valid 1 h; refresh with `POST /api/auth/refresh`) |
| `POST /api/keys` | Bearer | Body: `safe_serialize`d `CompressedServerKey` (`application/octet-stream`). Returns `201 {id, sha256, size_bytes, created_at}`. `409` when you already have the maximum number of keys |
| `GET /api/keys`, `DELETE /api/keys/{id}` | Bearer | List or remove your keys |
| `POST /api/compute/jobs` | Bearer | `{"key_id", "operation", "inputs": [b64, b64]}` (standard base64 of `safe_serialize`d `FheUint16`). Returns `202 {id, status}` |
| `GET /api/compute/jobs/{id}` | Bearer | `status` is `pending`, `processing`, `completed` (`result_b64` set) or `failed` (`error_message` set) |

Each submitted job counts against a daily quota (default 100, resets at midnight
UTC, `429` when exceeded). Polling and listing are free.

---

## Development

Requirements: Rust ≥ 1.91.1, Node.js 22 and pnpm 10.

```sh
# Backend: http://127.0.0.1:8080
cd backend
JWT_SECRET=dev-secret-at-least-32-bytes-long cargo run

# Frontend: http://localhost:3000/heaas (proxies /api to the backend)
cd frontend
pnpm install
pnpm dev
```

Without SMTP settings the backend logs email verification links instead of sending
them.

| Check | Command |
|---|---|
| Backend lint, tests | `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test` |
| Supply chain | `cargo deny check` (backend), `pnpm audit` (frontend) |
| Frontend types, unit tests | `pnpm check && pnpm test` |
| Browser tests (real TFHE WASM, mocked API) | `pnpm test:e2e` |
| Full stack (real backend, real browser TFHE) | `cargo build` in `backend/`, then `pnpm test:e2e:fullstack` |

Backend tests include end-to-end runs over HTTP, where the test plays the client:
it generates the keys and encrypts and decrypts, while the server only receives the
evaluation key and ciphertexts. CI (`.github/workflows/ci.yml`) runs all of the above.

### Configuration (backend)

| Variable | Default | |
|---|---|---|
| `JWT_SECRET` | — (required) | Token signing secret |
| `DATABASE_URL` | `sqlite://./he_saas.db` | SQLite database |
| `KEY_STORE_DIR` | `./data/keys` | Uploaded server keys (~60 MB each) |
| `MAX_SERVER_KEY_BYTES` | 80 MiB | Largest accepted key upload |
| `MAX_KEYS_PER_USER` | 2 | Server keys per account |
| `KEY_CACHE_CAPACITY` | 2 | Decompressed keys kept in RAM (~180 MB each) |
| `DAILY_COMPUTE_QUOTA` | 100 | Jobs per user per UTC day |
| `ALLOWED_ORIGINS` | — (required in release builds) | CORS origins |
| `APP_BASE_URL`, `SMTP_*`, `FROM_EMAIL`, `GOOGLE_*`, `GITHUB_*` | | Email and OAuth |

### Deployment

`docker-compose.yml` runs the backend and the frontend. nginx (`nginx-heaas.conf`)
serves the app under `/heaas/` and the API under `/api/`, and accepts request bodies
up to 96 MB for key uploads.

TFHE's WebAssembly build uses shared memory, so **every** frontend response must be
sent with `Cross-Origin-Opener-Policy: same-origin` and
`Cross-Origin-Embedder-Policy: require-corp`. `frontend/server.js` (production) and
the Vite dev/preview servers do this. Keep it in place if you put another proxy in
front.

## Licensing

TFHE-rs is distributed under BSD-3-Clause-Clear, which grants no patent rights.
Zama states that TFHE-rs is free for development, research, prototyping and
experimentation, and that **commercial use requires Zama's patent licence**. Obtain
that licence before running this service commercially.
