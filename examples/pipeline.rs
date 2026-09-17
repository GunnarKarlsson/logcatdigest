//! End-to-end digest pipeline: raw threadtime logcat → Chat Completions payload.
//!
//! Walks every major stage (parse → fold → redact → fingerprint → snapshot) on
//! four log mixes: ordinary errors, errors + panics, panics only, and clean.
//! Fixtures live in `fixtures/` (shared with `tests/pipeline.rs`).
//!
//! ```bash
//! cargo run --example pipeline
//! ```

use logcatdigest::{
    digest_threadtime, fingerprint, fold_lines_to_events, generate_device_label, parse_threadtime,
    redact, InsightLine, LogLine, Snapshot, SnapshotOpts,
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

/// Run every major pipeline stage and print a short trace, then return the snapshot.
fn run_pipeline(raw: &str, opts: SnapshotOpts) -> Snapshot {
    // --- parse ---
    let parsed: Vec<LogLine> = raw.lines().filter_map(parse_threadtime).collect();
    let dropped = raw.lines().filter(|l| !l.trim().is_empty()).count() - parsed.len();
    println!(
        "parse: {} threadtime lines ({} non-matching dropped)",
        parsed.len(),
        dropped
    );

    let errorish: Vec<&LogLine> = parsed
        .iter()
        .filter(|l| !opts.errors_only || l.is_error_level())
        .collect();
    println!(
        "filter: {} kept for digest (errors_only={})",
        errorish.len(),
        opts.errors_only
    );

    // --- fold fatal/ANR stacks ---
    let insight: Vec<InsightLine> = errorish
        .iter()
        .enumerate()
        .map(|(i, l)| InsightLine::from((i, *l)))
        .collect();
    let events = fold_lines_to_events(&insight);
    println!("fold:   {} events (stacks collapsed by PID)", events.len());
    for ev in &events {
        println!(
            "        - [{}] {} {} high_severity={} samples={}",
            ev.level,
            ev.tag,
            truncate(&ev.headline, 56),
            ev.is_high_severity(),
            ev.samples.len()
        );
    }

    // --- redact + fingerprint (prefer a line that actually carries secrets) ---
    let demo = events
        .iter()
        .find(|ev| redact(&ev.headline) != ev.headline)
        .or_else(|| events.first());
    if let Some(ev) = demo {
        let redacted = redact(&ev.headline);
        let fp = fingerprint(&ev.tag, &ev.headline);
        println!(
            "redact: {} → {}",
            truncate(&ev.headline, 48),
            truncate(&redacted, 48)
        );
        println!("finger: {fp}");
    }

    // --- snapshot (cluster + pin + JSON budget) ---
    let snap = digest_threadtime(raw.lines(), opts);
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
