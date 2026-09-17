# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `ContentType` (`Fatal` / `Anr` / `Crash`) and `LogLevel` filter enums.
- `SnapshotOptions` optional filters: `content_types`, `levels`, `tags`, `contains`.
- `Snapshot::from_logcat_lines` accepts raw threadtime strings; `Snapshot::is_empty`.
- Optional `device_label` / `device_model` on the builder (empty when omitted).
- Community and packaging polish: CONTRIBUTING, CODE_OF_CONDUCT, SECURITY,
  GitHub Actions CI/release workflows, and issue templates.
- Deny missing docs on the public API; field-level rustdoc on exported types.

### Changed

- Public mental model is filters → `Snapshot` → skip if empty; pipeline internals
  (`IndexedLogLine`, `GroupedEvent`, parse/redact/fingerprint helpers) are crate-private.
- Default levels are Error + Fatal (replaces `errors_only`).
- Builder methods renamed: `.device_label` / `.device_model` (no typestate).
- Type renamed `SnapshotOpts` → `SnapshotOptions` (and `SnapshotOptionsBuilder`).

### Removed

- Public exports of parse/group/fingerprint helpers and `Snapshot::from_events`.
- Free helpers `digest_threadtime`, `build_snapshot`, `generate_device_label`.

## [0.1.0] - 2026-09-17

### Added

- First release: parse `adb logcat -v threadtime` lines into `LogLine`.
- Noise-stable fingerprints and best-effort secret redaction (not PII-safe).
- Fold fatal/ANR stacks by PID into events; cluster, pin high-severity shapes,
  and trim to a ~6 KB JSON budget.
- `Snapshot` / `digest_key()` for Chat Completions user-message payloads.
- Example `snapshot` and crash/ANR fixture tests.
