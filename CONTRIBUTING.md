# Contributing

## Layout

| Path | What |
|---|---|
| `backend/` | `he-backend`: the actix-web server, job workers, migrations |
| `core/` | `heaas-core`: TFHE parameters, operations and API types shared by server and clients |
| `sdk/` | `heaas-sdk` Rust client and the `heaas` CLI |
| `frontend/` | SvelteKit dashboard; TFHE-rs WebAssembly in a Web Worker |
| `docs/` | Generated OpenAPI document and parameter sheet; audit and plan |

## Setup

Rust ≥ 1.91.1 (TFHE-rs 1.8 needs it), Node.js 22, pnpm 10. Dependencies are
compiled with optimisations even in debug builds (TFHE-rs is unusably slow
otherwise), so the first build takes a while.

```sh
JWT_SECRET=dev-secret-at-least-32-bytes-long cargo run -p he-backend   # :8080
cd frontend && pnpm install && pnpm dev                                # :3000/heaas
```

Without SMTP settings, debug builds log email verification and reset links instead
of sending them.

## Before you open a pull request

CI runs all of these; run them locally first.

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace            # includes the OpenAPI and parameter-sheet drift checks
cargo deny check                  # advisories, licences, bans, sources

cd frontend
pnpm check && pnpm test && pnpm build
pnpm test:e2e                     # real TFHE WASM, mocked API, axe accessibility
cargo build -p he-backend && pnpm test:e2e:fullstack   # real backend
```

Generated files are regenerated, never edited by hand:

- `docs/api/openapi.json`: `UPDATE_OPENAPI=1 cargo test -p he-backend openapi`
- `docs/parameters.md`: `UPDATE_DOCS=1 cargo test -p heaas-core`

## Conventions

- **TFHE-rs is pinned** to one release in `Cargo.toml` and `frontend/package.json`
  (a test checks they match `TFHE_VERSION`). Upgrade both together.
- **Every API error** is an `AppError` and leaves as the error envelope. New
  endpoints carry a `#[utoipa::path]` annotation and are listed in
  `backend/src/api/openapi.rs`. A test fails if a documented route is not served.
- **Configuration** is read only in `backend/src/config.rs`, with a range for
  every number. Invalid values are errors, never silent defaults.
- **Logging** goes through `tracing`; never log tokens, passwords, keys or
  ciphertexts.
- **Database changes** are new files in `backend/migrations/`; never edit an
  applied migration.
- Tests come with the change. Never skip or disable a test to get CI green.
- Commit messages say what changed and why. Add user-visible changes to
  `CHANGELOG.md` under a new version heading.
