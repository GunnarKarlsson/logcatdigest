# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-09-17

### Added

- First release: parse `adb logcat -v threadtime` lines into `LogLine`.
- Noise-stable fingerprints and best-effort secret redaction (not PII-safe).
- Fold fatal/ANR stacks by PID into events; cluster, pin high-severity shapes,
  and trim to a ~6 KB JSON budget.
- `Snapshot` / `digest_key()` for Chat Completions user-message payloads.
- Example `snapshot` and crash/ANR fixture tests.
