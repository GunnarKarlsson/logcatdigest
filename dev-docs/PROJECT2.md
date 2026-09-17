Dev:

Show me how a project repo would be structured via dir diagram and source files, and show suggested source code for the project. Keep it concise and focused.

Grok:

A small library crate: parse threadtime, redact, fingerprint, fold stacks, emit a JSON snapshot. No adb, no HTTP.

```
logcat-digest/
├── Cargo.toml
├── README.md
├── LICENSE
├── CHANGELOG.md
├── examples/
│   └── snapshot.rs
├── tests/
│   ├── fixtures/
│   │   └── crash_anr.threadtime
│   └── snapshot.rs
└── src/
    ├── lib.rs
    ├── parse.rs
    ├── fingerprint.rs
    ├── event.rs
    ├── reduce.rs
    └── snapshot.rs
```

## Cargo.toml

```toml
[package]
name = "logcat-digest"
version = "0.1.0"
edition = "2021"
rust-version = "1.80"
license = "MIT"
description = "Turn Android logcat into a redacted, clustered snapshot for Chat Completions."
repository = "https://github.com/GunnarKarlsson/logcat-digest"
keywords = ["android", "logcat", "adb", "llm"]
categories = ["parser-implementations", "development-tools"]

[dependencies]
regex = "1"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
sha2 = "0.10"

[dev-dependencies]
```

## src/lib.rs

```rust
mod event;
mod fingerprint;
mod parse;
mod reduce;
mod snapshot;

pub use event::{fold_lines_to_events, InsightEvent, InsightLine};
pub use fingerprint::{fingerprint, generate_device_label, redact};
pub use parse::{parse_threadtime, LogLine};
pub use snapshot::{build_snapshot, Cluster, Snapshot, SnapshotOpts};

/// Parse threadtime lines and build an LLM-ready snapshot.
pub fn digest_threadtime<'a>(
    lines: impl IntoIterator<Item = &'a str>,
    opts: SnapshotOpts,
) -> Snapshot {
    let parsed: Vec<LogLine> = lines.into_iter().filter_map(parse_threadtime).collect();
    build_snapshot(&parsed, opts)
}
```

## src/parse.rs

```rust
use regex::Regex;
use std::sync::LazyLock;

static LINE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?x)
        ^(\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3})\s+
        (\d+)\s+(\d+)\s+
        ([VDIWEF])\s+
        ([^:]+):\s+
        (.*)$",
    )
    .unwrap()
});

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogLine {
    pub timestamp: String,
    pub pid: u32,
    pub tid: u32,
    pub level: char,
    pub tag: String,
    pub message: String,
}

pub fn parse_threadtime(line: &str) -> Option<LogLine> {
    let c = LINE.captures(line.trim_end())?;
    Some(LogLine {
        timestamp: c[1].to_string(),
        pid: c[2].parse().ok()?,
        tid: c[3].parse().ok()?,
        level: c[4].chars().next()?,
        tag: c[5].trim().to_string(),
        message: c[6].trim().to_string(),
    })
}

impl LogLine {
    pub fn is_error_level(&self) -> bool {
        matches!(self.level, 'E' | 'F')
    }
}
```

## src/fingerprint.rs

Keep the logic you already have. Public names only:

```rust
use regex::Regex;
use sha2::{Digest, Sha256};
use std::sync::LazyLock;

static NOISE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?x) 0x[0-9a-fA-F]+ | /[^\s]+ | \b\d+\b").unwrap()
});

static SECRET_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?x)
        (?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}
      | Bearer\s+\S+
      | eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+
      | [A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}
      | (?i:\b(?:password|passwd|pwd|token|api[_-]?key|authorization)\s*[=:]\s*\S+)
      | \b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b
      | \b\d{10,15}\b",
    )
    .unwrap()
});

pub fn fingerprint(tag: &str, message: &str) -> String {
    let collapsed = NOISE_RE.replace_all(message, "#");
    let mut h = Sha256::new();
    h.update(tag.as_bytes());
    h.update(b"|");
    h.update(collapsed.as_bytes());
    format!("{:x}", h.finalize())[..16].to_string()
}

pub fn redact(message: &str) -> String {
    SECRET_RE.replace_all(message, "#").into_owned()
}

pub fn generate_device_label(model: &str, serial: &str) -> String {
    let mut h = Sha256::new();
    h.update(serial.as_bytes());
    let hex = format!("{:x}", h.finalize());
    let model: String = model
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    format!("{model}:{}", &hex[..8])
}
```

## src/event.rs

Input uses line index / optional timestamp string, not `Instant`, so files work.

```rust
use crate::fingerprint::redact;
use crate::parse::LogLine;

#[derive(Debug, Clone)]
pub struct InsightLine {
    pub index: usize,
    pub pid: u32,
    pub level: char,
    pub tag: String,
    pub message: String,
}

impl From<(usize, &LogLine)> for InsightLine {
    fn from((index, line): (usize, &LogLine)) -> Self {
        Self {
            index,
            pid: line.pid,
            level: line.level,
            tag: line.tag.clone(),
            message: line.message.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct InsightEvent {
    pub index: usize,
    pub pid: u32,
    pub level: char,
    pub tag: String,
    pub headline: String,
    pub samples: Vec<String>,
}

pub fn is_stack_head(level: char, message: &str) -> bool {
    let m = message.to_ascii_lowercase();
    level == 'F'
        || m.contains("fatal exception")
        || m.contains("anr in")
        || m.contains("fatal signal")
}

pub fn fold_lines_to_events(lines: &[InsightLine]) -> Vec<InsightEvent> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let line = &lines[i];
        if is_stack_head(line.level, &line.message) {
            let mut samples = vec![redact(&line.message)];
            let mut j = i + 1;
            while j < lines.len()
                && samples.len() < 32
                && lines[j].pid == line.pid
                && !is_stack_head(lines[j].level, &lines[j].message)
                && is_cont(&lines[j])
            {
                samples.push(redact(&lines[j].message));
                j += 1;
            }
            out.push(InsightEvent {
                index: line.index,
                pid: line.pid,
                level: line.level,
                tag: line.tag.clone(),
                headline: line.message.clone(),
                samples,
            });
            i = j;
        } else {
            out.push(InsightEvent {
                index: line.index,
                pid: line.pid,
                level: line.level,
                tag: line.tag.clone(),
                headline: line.message.clone(),
                samples: vec![redact(&line.message)],
            });
            i += 1;
        }
    }
    out
}

fn is_cont(line: &InsightLine) -> bool {
    let m = line.message.trim_start();
    m.starts_with("at ")
        || m.to_ascii_lowercase().starts_with("caused by:")
        || matches!(line.tag.as_str(), "AndroidRuntime" | "ActivityManager")
}
```

## src/snapshot.rs

```rust
use serde::Serialize;

use crate::event::{fold_lines_to_events, InsightLine};
use crate::fingerprint::fingerprint;
use crate::parse::LogLine;
use crate::reduce::{absorb, retain_clusters};

#[derive(Debug, Clone)]
pub struct SnapshotOpts {
    pub device_label: String,
    pub device_model: String,
    pub errors_only: bool,
    pub max_clusters: usize,
}

impl Default for SnapshotOpts {
    fn default() -> Self {
        Self {
            device_label: "unknown:00000000".into(),
            device_model: "unknown".into(),
            errors_only: true,
            max_clusters: 8,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Cluster {
    pub fingerprint: String,
    pub tag: String,
    pub level: char,
    pub count: u32,
    pub samples: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Snapshot {
    pub device_label: String,
    pub device_model: String,
    pub levels: Vec<&'static str>,
    pub clusters: Vec<Cluster>,
}

impl Snapshot {
    pub fn to_pretty_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("snapshot serializes")
    }

    pub fn digest_key(&self) -> String {
        self.clusters
            .iter()
            .map(|c| format!("{}:{}", c.fingerprint, c.count.saturating_div(5)))
            .collect::<Vec<_>>()
            .join("|")
    }
}

pub fn build_snapshot(lines: &[LogLine], opts: SnapshotOpts) -> Snapshot {
    let insight: Vec<InsightLine> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| !opts.errors_only || l.is_error_level())
        .map(|(i, l)| InsightLine::from((i, l)))
        .collect();

    let events = fold_lines_to_events(&insight);
    let mut clusters = absorb(&events);
    retain_clusters(&mut clusters, opts.max_clusters);

    Snapshot {
        device_label: opts.device_label,
        device_model: opts.device_model,
        levels: if opts.errors_only {
            vec!["E", "F"]
        } else {
            vec!["V", "D", "I", "W", "E", "F"]
        },
        clusters,
    }
}
```

## src/reduce.rs

```rust
use std::collections::HashMap;

use crate::event::InsightEvent;
use crate::fingerprint::fingerprint;
use crate::snapshot::Cluster;

pub fn absorb(events: &[InsightEvent]) -> Vec<Cluster> {
    let mut map: HashMap<String, Cluster> = HashMap::new();
    for e in events {
        let fp = fingerprint(&e.tag, &e.headline);
        let c = map.entry(fp.clone()).or_insert_with(|| Cluster {
            fingerprint: fp,
            tag: e.tag.clone(),
            level: e.level,
            count: 0,
            samples: Vec::new(),
        });
        c.count += 1;
        if e.samples.len() > c.samples.len() {
            c.samples = e.samples.clone();
        }
    }
    map.into_values().collect()
}

pub fn retain_clusters(clusters: &mut Vec<Cluster>, max: usize) {
    clusters.sort_by(|a, b| b.count.cmp(&a.count).then(a.tag.cmp(&b.tag)));
    let mut high: Vec<Cluster> = Vec::new();
    let mut rest: Vec<Cluster> = Vec::new();
    for c in clusters.drain(..) {
        if is_high(&c) && high.len() < 2 {
            high.push(c);
        } else {
            rest.push(c);
        }
    }
    high.extend(rest.into_iter().take(max.saturating_sub(high.len())));
    *clusters = high;
}

fn is_high(c: &Cluster) -> bool {
    c.level == 'F' || c.tag == "AndroidRuntime" || c.samples.iter().any(|s| {
        let m = s.to_ascii_lowercase();
        m.contains("fatal exception") || m.contains("anr in")
    })
}
```

## examples/snapshot.rs

```rust
use logcat-digest::{digest_threadtime, generate_device_label, SnapshotOpts};

fn main() {
    let raw = r#"
09-17 12:01:03.120  2144  2144 E AndroidRuntime: FATAL EXCEPTION: main
09-17 12:01:03.120  2144  2144 E AndroidRuntime: java.lang.NullPointerException: boom
09-17 12:01:03.120  2144  2144 E AndroidRuntime:    at com.app.MainActivity.onCreate(MainActivity.kt:42)
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

## How the dashboard uses it

```toml
# crates/android-dashboard/Cargo.toml
logcat-digest = "0.1"
```

```rust
let lines = pane.insight_lines(); // already parsed
let snap = logcat_digest::build_snapshot(&lines, opts);
if snap.digest_key() != last_key {
    client.complete(&snap.to_pretty_json())?;
}
```

Leave `ureq`, cooldowns, and the system prompt in `ai-insight`. This crate only produces the user-message JSON.