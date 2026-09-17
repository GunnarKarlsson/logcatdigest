//! Turn Android logcat into a redacted, clustered snapshot for Chat Completions.
//!
//! Crate name: `logcatdigest`. Repository: `logcatdigest`.
//!
//! Parse `adb logcat -v threadtime` lines, fold fatal/ANR stacks, redact secrets,
//! fingerprint noisy messages, and emit a JSON budget suitable as a user message.
//! This crate does not spawn adb or call any HTTP API — you own I/O and the
//! system prompt.
//!
//! See `examples/snapshot.rs` and `examples/pipeline.rs`.
//!
//! # Example
//!
//! ```
//! use logcatdigest::{digest_threadtime, generate_device_label, SnapshotOpts};
//!
//! let raw = "09-17 12:01:03.120  2144  2144 E OkHttp: failed 3 times token=sk-secret";
//! let snap = digest_threadtime(
//!     [raw],
//!     SnapshotOpts {
//!         device_label: generate_device_label("Pixel 8", "emulator-5554"),
//!         device_model: "Pixel 8".into(),
//!         ..SnapshotOpts::default()
//!     },
//! );
//! assert!(!snap.clusters.is_empty());
//! let _ = snap.to_pretty_json();
//! ```

#![deny(missing_docs)]
#![warn(rust_2018_idioms, missing_debug_implementations)]

mod event;
mod fingerprint;
mod parse;
mod reduce;
mod severity;
mod snapshot;

pub use event::{fold_lines_to_events, is_stack_head_message, InsightEvent, InsightLine};
pub use fingerprint::{fingerprint, generate_device_label, generate_fingerprint, redact};
pub use parse::{parse_threadtime, LogLine};
pub use severity::is_high_severity;
pub use snapshot::{build_snapshot, Cluster, Snapshot, SnapshotOpts};

/// Parse threadtime lines and build an LLM-ready snapshot.
pub fn digest_threadtime<'a>(
    lines: impl IntoIterator<Item = &'a str>,
    opts: SnapshotOpts,
) -> Snapshot {
    let parsed: Vec<LogLine> = lines.into_iter().filter_map(parse_threadtime).collect();
    build_snapshot(&parsed, opts)
}
