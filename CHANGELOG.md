# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `build_snapshot_from_events` so callers can compose
  parse → filter → fold (redact) → fingerprint/cluster in one linear path.
- Community and packaging polish: CONTRIBUTING, CODE_OF_CONDUCT, SECURITY,
  GitHub Actions CI/release workflows, and issue templates.
- Deny missing docs on the public API; field-level rustdoc on exported types.

### Changed

- README and `examples/pipeline` show the composed digest path end-to-end.
- Removed `digest_threadtime`; use parse + `build_snapshot` or fold +
  `build_snapshot_from_events` instead.

## [0.1.0] - 2026-09-17

### Added

- First release: parse `adb logcat -v threadtime` lines into `LogLine`.
- Noise-stable fingerprints and best-effort secret redaction (not PII-safe).
- Fold fatal/ANR stacks by PID into events; cluster, pin high-severity shapes,
  and trim to a ~6 KB JSON budget.
- `Snapshot` / `digest_key()` for Chat Completions user-message payloads.
- Example `snapshot` and crash/ANR fixture tests.
