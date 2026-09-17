# Contributing

Crate name: `logcatdigest`. Repository: `logcatdigest`.

Bug reports and feature ideas: use the GitHub issue templates. Pull requests
are welcome for tests, docs, parser/redaction fixes, and API work that stays
within the crate’s scope (threadtime → redacted clustered snapshot; no adb or
HTTP client).

This project follows the [Rust Code of Conduct](CODE_OF_CONDUCT.md).

## Quality gate

Match CI before opening a PR (`RUSTFLAGS` / `RUSTDOCFLAGS` are `-D warnings`):

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
cargo test --doc
cargo doc --no-deps --all-features --document-private-items
```

MSRV is **1.80** (`rust-version` in `Cargo.toml`). CI also runs tests on that
toolchain. Do not raise MSRV without a reason in the PR.

## Code

- Parser, redaction, fingerprint, and group changes need a test (fixture-driven
  when the input is multi-line logcat).
- Keep the crate free of adb child processes and HTTP clients. New runtime deps
  need an issue first.
- Do not claim PII-safe output; redaction stays best-effort regex.
- User-visible API or behavior changes: a `[Unreleased]` note in `CHANGELOG.md`.

## Release

Tag `vX.Y.Z` must match `Cargo.toml`. Pushing that tag creates a GitHub Release
whose notes are the matching `CHANGELOG.md` section. Publish to crates.io by
hand when ready; do not put a crates.io token in GitHub Actions.

1. `Cargo.toml` version is `X.Y.Z`.
2. Move `[Unreleased]` items into `## [X.Y.Z] - YYYY-MM-DD` in `CHANGELOG.md`.
3. `cargo publish --dry-run`, then `cargo publish` (manual; not in CI).
4. `git tag vX.Y.Z && git push origin vX.Y.Z`
