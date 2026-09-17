# logcatdigest

[![Crates.io](https://img.shields.io/crates/v/logcatdigest.svg)](https://crates.io/crates/logcatdigest)
[![Docs.rs](https://docs.rs/logcatdigest/badge.svg)](https://docs.rs/logcatdigest)
[![MSRV](https://img.shields.io/badge/MSRV-1.80+-blue.svg)](https://blog.rust-lang.org/2024/07/25/Rust-1.80.0/)
[![Rust](https://img.shields.io/badge/Rust-edition%202021-orange.svg)](https://doc.rust-lang.org/edition-guide/rust-2021/index.html)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/GunnarKarlsson/logcatdigest/actions/workflows/ci.yml/badge.svg)](https://github.com/GunnarKarlsson/logcatdigest/actions)

Turn Android **logcat** into a **redacted, clustered JSON snapshot** ready for a
Chat Completions `messages[].content` field.

## Problem

You cannot usefully stream raw logcat into a Chat Completions API:

- **Volume** — minutes of `adb logcat -v threadtime` are tens of thousands of
  lines; most are `I`/`D`/`W` chatter that burns tokens without helping diagnosis.
- **Duplication** — the same crash or network failure retries dozens of times
  with only counters, paths, or PIDs changing. The model sees noise, not a bug.
- **Secrets** — messages often embed tokens, emails, IPs, and `password=`-style
  assignments that must not leave the device or land in a provider prompt.
- **Structure** — fatal/ANR stacks span many lines; a line-oriented dump loses
  the event boundary the model needs.
- **Change detection** — without a stable digest you re-query the model on every
  poll even when the error mix is unchanged.

## Solution

Filter to errors, fold stacks (redacting sample lines), fingerprint noisy text so
identical bugs hash the same, and consolidate matching errors into a small JSON
**snapshot** (≤8 clusters, ~6 KB). Use `digest_key()` to call the model only when
the mix changes.

No adb child process. No HTTP client. You own I/O and the system prompt.

## Install

```bash
cargo add logcatdigest
```

```toml
[dependencies]
logcatdigest = "0.1"
```

## Quick start

One path: parse → filter → fold (redact) → fingerprint/cluster → gate the API call.

```rust
use logcatdigest::{
    build_snapshot_from_events, fold_lines_to_events, generate_device_label,
    parse_threadtime, InsightLine, SnapshotOpts,
};

fn main() {
    let raw = r#"
09-17 12:01:03.120  2144  2144 E AndroidRuntime: FATAL EXCEPTION: main
09-17 12:01:03.120  2144  2144 E AndroidRuntime: java.lang.NullPointerException: boom
09-17 12:01:03.120  2144  2144 E AndroidRuntime: 	at com.app.MainActivity.onCreate(MainActivity.kt:42)
09-17 12:01:04.001  2144  2201 E OkHttp: failed 3 times at /data/app/foo token=sk-secret
09-17 12:01:04.050  2144  2201 E OkHttp: failed 9 times at /data/app/bar
"#;

    let opts = SnapshotOpts {
        device_label: generate_device_label("Pixel 8", "emulator-5554"),
        device_model: "Pixel 8".into(),
        ..SnapshotOpts::default() // errors_only, max_clusters = 8
    };

    // 1. Parse threadtime logcat
    let lines: Vec<_> = raw.lines().filter_map(parse_threadtime).collect();

    // 2. Filter to E/F, then fold stacks (sample lines are redacted on each event)
    let insight: Vec<_> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| !opts.errors_only || l.is_error_level())
        .map(|(i, l)| InsightLine::from((i, l)))
        .collect();
    let events = fold_lines_to_events(&insight);

    // 3. Fingerprint + consolidate identical errors → Chat Completions snapshot
    let snap = build_snapshot_from_events(&events, opts);
    let json = snap.to_pretty_json();
    let key = snap.digest_key();

    // 4. Gate the API: skip empty digests; re-query only when the mix changes
    let previous_key = ""; // last key you persisted from a prior poll
    if !snap.clusters.is_empty()
        && (key != previous_key || snap.has_new_high_severity(previous_key))
    {
        // POST `json` as messages[].content — keep the system prompt in your app
        println!("{json}");
        println!("digest_key={key}");
    }
}
```

Runnable examples:

```text
cargo run --example pipeline   # fixtures → composed parse/fold/snapshot path
cargo run --example snapshot   # small inline log → parse + build_snapshot
```

## What it does

1. **Parse** `adb logcat -v threadtime` → `LogLine` (no UI wrapping).
2. **Filter** to `E`/`F` when `errors_only` (default).
3. **Fold** multi-line fatal/ANR stacks by PID → events; **redact** secrets into
   `InsightEvent::samples`.
4. **Fingerprint** after collapsing hex, paths, and numbers so the same bug
   hashes the same across runs.
5. **Cluster** (≤8), pin up to 2 high-severity shapes, trim to ~6 KB JSON.

Regex redaction is **best-effort**. It will miss some secrets and can clobber
benign IDs. Do not claim PII-safe output.

## Key API components

| Item | Role |
|---|---|
| `parse_threadtime` / `LogLine` | Parse one threadtime line |
| `fold_lines_to_events` | Fold stacks; redact samples onto events |
| `build_snapshot` | Parsed `LogLine`s → `Snapshot` |
| `build_snapshot_from_events` | Fingerprint + cluster events → `Snapshot` |
| `generate_device_label` | `{model}:{sha256(serial)[..8]}` |
| `Snapshot::to_pretty_json` / `digest_key` | LLM payload + change detection |
| `redact` / `fingerprint` | Also available for custom pipelines |

Full types: [docs.rs/logcatdigest](https://docs.rs/logcatdigest).

## Non-goals

- Spawning `adb` or talking to any LLM HTTP API.
- Guaranteeing PII-safe or secret-free output (redaction is best-effort).
- Parsing every historical logcat format — threadtime is the supported input.

## MSRV

Rust **1.80** (edition 2021).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). This project follows the
[Rust Code of Conduct](CODE_OF_CONDUCT.md).

Security reports: [SECURITY.md](SECURITY.md).

## License

MIT
