//! Turn Android logcat into a redacted, clustered snapshot for Chat Completions.
//!
//! Crate name: `logcatdigest`. Repository: `logcatdigest`.
//!
//! Pipeline: parse threadtime → filter errors → fold stacks (redact samples) →
//! fingerprint and cluster identical bugs → JSON snapshot for
//! `messages[].content`. This crate does not spawn adb or call any HTTP API —
//! you own I/O and the system prompt.
//!
//! See `examples/pipeline.rs` for the composed path.
//!
//! # Example
//!
//! ```
//! use logcatdigest::{
//!     fold_lines_to_events, parse_threadtime, InsightLine, Snapshot, SnapshotOpts,
//! };
//!
//! let raw = "09-17 12:01:03.120  2144  2144 E OkHttp: failed 3 times token=sk-secret";
//! let opts = SnapshotOpts::builder()
//!     .label(("Pixel 8", "emulator-5554"))
//!     .model("Pixel 8")
//!     .build();
//! let lines: Vec<_> = [raw].into_iter().filter_map(parse_threadtime).collect();
//! let insight: Vec<_> = lines
//!     .iter()
//!     .enumerate()
//!     .filter(|(_, l)| l.is_error_level())
//!     .map(|(i, l)| InsightLine::from((i, l)))
//!     .collect();
//! let events = fold_lines_to_events(&insight);
//! let snap = Snapshot::from_events(&events, opts);
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
pub use fingerprint::{fingerprint, generate_fingerprint, redact, DeviceLabel, DeviceModel};
pub use parse::{parse_threadtime, LogLine};
pub use severity::is_high_severity;
pub use snapshot::{Cluster, Snapshot, SnapshotOpts, SnapshotOptsBuilder};
