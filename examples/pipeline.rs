//! End-to-end digest: raw threadtime logcat → Chat Completions payload.
//!
//! One linear path: parse → filter → fold (redact) → fingerprint/cluster →
//! gate the model call. Fixtures in `fixtures/` (shared with `tests/pipeline.rs`).
//!
//! ```bash
//! cargo run --example pipeline
//! ```

use logcatdigest::{
    build_snapshot_from_events, fold_lines_to_events, generate_device_label, parse_threadtime,
    InsightLine, LogLine, Snapshot, SnapshotOpts,
};

fn main() {
    let opts = SnapshotOpts {
        device_label: generate_device_label("Pixel 8", "emulator-5554"),
        device_model: "Pixel 8".into(),
        ..SnapshotOpts::default()
    };

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

        let snap = run_pipeline(raw, opts.clone());
        let should_call = decide_whether_to_call_api(&snap, &previous_key);
        print_api_ready(&snap, &previous_key, should_call);

        previous_key = snap.digest_key();
    }
}

/// Parse → filter → fold (redact samples) → fingerprint/cluster → Snapshot.
fn run_pipeline(raw: &str, opts: SnapshotOpts) -> Snapshot {
    // 1. Parse threadtime (UI wrapping / non-matching lines dropped)
    let parsed: Vec<LogLine> = raw.lines().filter_map(parse_threadtime).collect();
    let dropped = raw.lines().filter(|l| !l.trim().is_empty()).count() - parsed.len();
    println!(
        "parse:  {} threadtime lines ({} non-matching dropped)",
        parsed.len(),
        dropped
    );

    // 2. Filter to E/F when errors_only (default)
    let insight: Vec<InsightLine> = parsed
        .iter()
        .enumerate()
        .filter(|(_, l)| !opts.errors_only || l.is_error_level())
        .map(|(i, l)| InsightLine::from((i, l)))
        .collect();
    println!(
        "filter: {} kept for digest (errors_only={})",
        insight.len(),
        opts.errors_only
    );

    // 3. Fold fatal/ANR stacks; sample lines are redacted here
    let events = fold_lines_to_events(&insight);
    println!("fold:   {} events (stacks collapsed; samples redacted)", events.len());
    for ev in &events {
        let sample = ev.samples.first().map(String::as_str).unwrap_or("");
        println!(
            "        - [{}] {} high_severity={} sample={}",
            ev.level,
            ev.tag,
            ev.is_high_severity(),
            truncate(sample, 56)
        );
    }

    // 4. Fingerprint identical bugs and consolidate into a budgeted snapshot
    let snap = build_snapshot_from_events(&events, opts);
    println!(
        "snap:   {} cluster(s) digest_key={:?}",
        snap.clusters.len(),
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

    snap
}

/// Gate the AI call: skip empty digests; re-query when the mix or a new fatal shape appears.
fn decide_whether_to_call_api(snap: &Snapshot, previous_key: &str) -> bool {
    if snap.clusters.is_empty() {
        return false;
    }
    let key = snap.digest_key();
    key != previous_key || snap.has_new_high_severity(previous_key)
}

fn print_api_ready(snap: &Snapshot, previous_key: &str, should_call: bool) {
    println!();
    println!("--- Chat Completions user message (to_pretty_json) ---");
    if snap.clusters.is_empty() {
        println!("(empty snapshot — nothing to send; log was clean under errors_only)");
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
