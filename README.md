# logcatdigest

[![Crates.io](https://img.shields.io/crates/v/logcatdigest.svg)](https://crates.io/crates/logcatdigest)
[![Docs.rs](https://docs.rs/logcatdigest/badge.svg)](https://docs.rs/logcatdigest)
[![MSRV](https://img.shields.io/badge/MSRV-1.80+-blue.svg)](https://blog.rust-lang.org/2024/07/25/Rust-1.80.0/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Turn Android **logcat** into a **redacted, clustered JSON snapshot** ready for a
Chat Completions `messages[].content` field.

**Before:** hundreds of raw `E`/`F` threadtime lines (crashes, ANRs, noisy
retries, tokens in messages).

**After:** ≤8 clusters with stable fingerprints, redacted samples, and a
`digest_key()` so you only re-query the model when the error mix changes.

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

```rust
use logcatdigest::{digest_threadtime, generate_device_label, SnapshotOpts};

fn main() {
    let raw = r#"
09-17 12:01:03.120  2144  2144 E AndroidRuntime: FATAL EXCEPTION: main
09-17 12:01:03.120  2144  2144 E AndroidRuntime: java.lang.NullPointerException: boom
09-17 12:01:03.120  2144  2144 E AndroidRuntime: 	at com.app.MainActivity.onCreate(MainActivity.kt:42)
09-17 12:01:04.001  2144  2201 E OkHttp: failed 3 times at /data/app/foo token=sk-secret
"#;

    let snap = digest_threadtime(
        raw.lines(),
        SnapshotOpts {
            device_label: generate_device_label("Pixel 8", "emulator-5554"),
            device_model: "Pixel 8".into(),
            ..SnapshotOpts::default()
        },
    );

    println!("{}", snap.to_pretty_json());
    // POST snap.to_pretty_json() as the user message. Keep the prompt in the app.
}
```

```bash
cargo run --example snapshot
```

## What it does

1. **Parse** `adb logcat -v threadtime` → `LogLine` (no UI wrapping).
2. **Fold** multi-line fatal/ANR stacks by PID → events.
3. **Redact** MACs, Bearer/JWT-ish blobs, emails, `password=`/`api_key=`
   assignments, IPv4, long digit runs — leave short numbers and paths.
4. **Fingerprint** after collapsing hex, paths, and numbers so the same bug
   hashes the same across runs.
5. **Cluster** (≤8), pin up to 2 high-severity shapes, trim to ~6 KB JSON.

Regex redaction is **best-effort**. It will miss some secrets and can clobber
benign IDs. Do not claim PII-safe output.

## API sketch

| Item | Role |
|---|---|
| `parse_threadtime` / `LogLine` | Parse one threadtime line |
| `redact` / `fingerprint` | Secret strip + noise-stable hash |
| `generate_device_label` | `{model}:{sha256(serial)[..8]}` |
| `build_snapshot` / `digest_threadtime` | Lines → `Snapshot` |
| `Snapshot::to_pretty_json` / `digest_key` | LLM payload + change detection |

## License

MIT
