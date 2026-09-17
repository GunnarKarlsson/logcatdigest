//! Turn Android logcat into a redacted, clustered snapshot for Chat Completions.
//!
//! Crate name: `logcatdigest`. Repository: `logcatdigest`.
//!
//! Filter raw logcat lines into a JSON snapshot for `messages[].content`.
//! This crate does not spawn adb or call any HTTP API — you own I/O and the
//! system prompt.
//!
//! # Example
//!
//! ```
//! use logcatdigest::{ContentType, LogLevel, Snapshot, SnapshotOptions};
//!
//! let raw = "09-17 12:01:03.120  2144  2144 E AndroidRuntime: FATAL EXCEPTION: main";
//! let opts = SnapshotOptions::builder()
//!     .device_label(("Pixel 8", "emulator-5554"))
//!     .device_model("Pixel 8")
//!     .content_types([ContentType::Fatal, ContentType::Anr, ContentType::Crash])
//!     .levels([LogLevel::Error, LogLevel::Fatal])
//!     .tags(["AndroidRuntime"])
//!     .contains("Exception")
//!     .max_clusters(8)
//!     .build();
//! let snap = Snapshot::from_logcat_lines([raw], opts);
//! assert!(!snap.is_empty());
//! let _ = snap.to_pretty_json();
//! ```

#![deny(missing_docs)]
#![warn(rust_2018_idioms, missing_debug_implementations)]

mod content;
mod event;
mod fingerprint;
mod parse;
mod reduce;
mod severity;
mod snapshot;

pub use content::{ContentType, LogLevel};
pub use fingerprint::{DeviceLabel, DeviceModel};
pub use snapshot::{Cluster, Snapshot, SnapshotOptions, SnapshotOptionsBuilder};
