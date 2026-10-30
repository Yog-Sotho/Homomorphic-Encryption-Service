## What and why

<!-- What does this change, and why? Link the issue it closes, if any. -->

## How it was tested

<!-- The checks you ran (see CONTRIBUTING.md) and any manual testing. -->

## Checklist

- [ ] `cargo fmt`, `cargo clippy -D warnings` and `cargo test --workspace` pass
- [ ] Frontend: `pnpm check`, `pnpm test` and the e2e tests pass (if the frontend changed)
- [ ] Generated files are regenerated, not edited (`docs/api/openapi.json`, `docs/parameters.md`)
- [ ] Docs and `CHANGELOG.md` (Unreleased) are updated for user-visible changes
- [ ] Nothing new reaches the server in plaintext, or the PR says what and why
