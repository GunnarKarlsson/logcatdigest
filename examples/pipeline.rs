//! End-to-end digest: raw threadtime logcat → Chat Completions payload.
//!
//! One path: filter → Snapshot → gate the model call.
//! Fixtures in `fixtures/` (shared with `tests/pipeline.rs`).
//!
//! ```bash
//! cargo run --example pipeline
//! ```

use logcatdigest::{ContentType, LogLevel, Snapshot, SnapshotOpts};

fn main() {
    // Every builder method listed. Empty content_types / tags = no extra filter;
    // empty contains matches all text (omit `.contains` when unused).
    let opts = SnapshotOpts::builder()
        .device_label(("Pixel 8", "emulator-5554"))
        .device_model("Pixel 8")
        .content_types(Vec::<ContentType>::new())
        .levels([LogLevel::Error, LogLevel::Fatal])
        .tags(Vec::<String>::new())
        .contains("")
        .max_clusters(8)
        .build();

    let scenarios = [
        (
            "1) errors only",
            include_str!("../fixtures/errors.threadtime"),
        ),
        (
            "2) errors + panics",
            include_str!("../fixtures/errors_and_panics.threadtime"),
        ),
        (
            "3) panics only",
            include_str!("../fixtures/panics.threadtime"),
        ),
        (
            "4) clean (no E/F)",
            include_str!("../fixtures/clean.threadtime"),
        ),
    ];

    let mut previous_key = String::new();
    for (name, raw) in scenarios {
        println!("\n{}", "=".repeat(72));
        println!("{name}");
        println!("{}\n", "=".repeat(72));

        let snap = Snapshot::from_logcat_lines(raw.lines(), opts.clone());
        println!(
            "snap:   {} cluster(s) empty={} digest_key={:?}",
            snap.clusters.len(),
            snap.is_empty(),
            snap.digest_key()
        );
        for c in &snap.clusters {
            println!(
                "        - [{}] {} count={} fp={} sample={}",
                c.level,
                c.tag,
                c.count,
                &c.fingerprint[..8.min(c.fingerprint.len())],
                truncate(c.samples.first().map(String::as_str).unwrap_or(""), 48)
            );
        }

        let should_call = decide_whether_to_call_api(&snap, &previous_key);
        print_api_ready(&snap, &previous_key, should_call);
        previous_key = snap.digest_key();
    }
}

/// Gate the AI call: skip empty digests; re-query when the mix or a new fatal shape appears.
fn decide_whether_to_call_api(snap: &Snapshot, previous_key: &str) -> bool {
    if snap.is_empty() {
        return false;
    }
    let key = snap.digest_key();
    key != previous_key || snap.has_new_high_severity(previous_key)
}

fn print_api_ready(snap: &Snapshot, previous_key: &str, should_call: bool) {
    println!();
    println!("--- Chat Completions user message (to_pretty_json) ---");
    if snap.is_empty() {
        println!("(empty snapshot — nothing to send; nothing matched the filters)");
    } else {
        println!("{}", snap.to_pretty_json());
    }
    println!();
    println!(
        "api gate: previous_key={previous_key:?} new_high={} → {}",
        snap.has_new_high_severity(previous_key),
        if should_call {
            "POST snapshot JSON as messages[].content"
        } else {
            "skip model call"
        }
    );
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let cut: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{cut}…")
    }
}
