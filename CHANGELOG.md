# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `SnapshotOpts::builder` typestate API (required label/model; optional
  errors_only / max_clusters).
- `Snapshot::from_lines` / `from_events` as the digest entry points.
- `DeviceLabel` / `DeviceModel` newtypes (`DeviceLabel::new`,
  `From<(&str, &str)>`, `DeviceModel::new` / `From<&str>`).
- Rename pipeline types: `IndexedLogLine` / `GroupedEvent` /
  `GroupedEventList::group_from_indexed_log_lines` (was Insight* / fold_*).
- Community and packaging polish: CONTRIBUTING, CODE_OF_CONDUCT, SECURITY,
  GitHub Actions CI/release workflows, and issue templates.
- Deny missing docs on the public API; field-level rustdoc on exported types.

### Changed

- README and examples show the composed digest path end-to-end.
- Removed free helpers `digest_threadtime`, `build_snapshot`,
  `build_snapshot_from_events`, and `generate_device_label`.

## [0.1.0] - 2026-09-17

### Added

- First release: parse `adb logcat -v threadtime` lines into `LogLine`.
- Noise-stable fingerprints and best-effort secret redaction (not PII-safe).
- Fold fatal/ANR stacks by PID into events; cluster, pin high-severity shapes,
  and trim to a ~6 KB JSON budget.
- `Snapshot` / `digest_key()` for Chat Completions user-message payloads.
- Example `snapshot` and crash/ANR fixture tests.
