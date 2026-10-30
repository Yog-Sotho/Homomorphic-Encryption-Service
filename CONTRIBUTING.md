# Contributing

Thanks for helping. Everyone taking part follows the [code of conduct](CODE_OF_CONDUCT.md).

## Ways to contribute

- **Questions and ideas:** [GitHub Discussions](https://github.com/Yog-Sotho/Homomorphic-Encryption-Service/discussions).
- **Bugs and feature requests:** an [issue](https://github.com/Yog-Sotho/Homomorphic-Encryption-Service/issues/new/choose), with the matching form.
  For anything larger than a small fix, open an issue first so the approach can be
  agreed before you write the code.
- **Security problems:** never in public; see [SECURITY.md](SECURITY.md).
- **Pull requests:** fork, branch from `master`, and open the pull request against
  `master`. Its template lists the checks below. CI must be green and the
  maintainer reviews every change (see `.github/CODEOWNERS`).

By contributing you agree that your contribution is licensed under the project's
[MIT licence](LICENSE).

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
cargo llvm-cov --workspace --fail-under-lines 88   # coverage floor (needs cargo-llvm-cov)

cd frontend
pnpm check && pnpm test:coverage && pnpm build
pnpm test:e2e                     # real TFHE WASM, mocked API, axe accessibility
cargo build -p he-backend && pnpm test:e2e:fullstack   # real backend
```

Property tests (`proptest`) run a few cases each in the normal suite. The `heavy_*`
tests are `#[ignore]`d: every type, 64-bit multiplications and proofs. A scheduled
workflow runs them; locally:

```sh
HEAAS_PROPTEST_CASES=16 cargo test --release -p he-backend -- --ignored
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
  `CHANGELOG.md` under `## [Unreleased]`.

## Documentation site

The guides in `docs/` are published at
<https://yog-sotho.github.io/Homomorphic-Encryption-Service/> by
`.github/workflows/docs.yml` on every push to `master`. Preview it locally:

```sh
pip install -r requirements-docs.txt
npx @redocly/cli@1.34.5 build-docs docs/api/openapi.json -o docs/api/reference.html
mkdocs serve            # http://127.0.0.1:8000; CI builds with --strict, so broken links fail
```

Links from `docs/` to files outside it (`SECURITY.md`, `sdk/`) must be full GitHub
URLs, so they work both on GitHub and on the site.

## Releases

1. Move the `## [Unreleased]` notes in `CHANGELOG.md` under `## [X.Y.Z] - YYYY-MM-DD`.
2. Set `version` in `Cargo.toml` (`[workspace.package]`) and `frontend/package.json`
   to `X.Y.Z`, then regenerate `docs/api/openapi.json`.
3. Merge to `master`, then tag that commit `vX.Y.Z` and push the tag.
   `.github/workflows/release.yml` checks the versions, builds the binaries and container
   images, signs them, and publishes the GitHub release with the changelog section as
   its notes.
