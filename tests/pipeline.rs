//! Pipeline scenarios matching `examples/pipeline.rs`: errors, errors+panics,
//! panics, and clean — from raw threadtime through an AI-ready snapshot.
//!
//! Shared logcat fixtures: `fixtures/*.threadtime`.

use logcatdigest::{
    fold_lines_to_events, is_high_severity, parse_threadtime, InsightLine, Snapshot, SnapshotOpts,
};

fn opts() -> SnapshotOpts {
    SnapshotOpts::builder()
        .label(("Pixel 8", "emulator-5554"))
        .model("Pixel 8")
        .build()
}

fn digest(raw: &str) -> Snapshot {
    let lines: Vec<_> = raw.lines().filter_map(parse_threadtime).collect();
    Snapshot::from_lines(&lines, opts())
}

fn fold_error_events(raw: &str) -> Vec<logcatdigest::InsightEvent> {
    let parsed: Vec<_> = raw.lines().filter_map(parse_threadtime).collect();
    let insight: Vec<InsightLine> = parsed
        .iter()
        .filter(|l| l.is_error_level())
        .enumerate()
        .map(|(i, l)| InsightLine::from((i, l)))
        .collect();
    fold_lines_to_events(&insight)
}

fn cluster_is_high(c: &logcatdigest::Cluster) -> bool {
    let sample = c.samples.first().map(String::as_str).unwrap_or("");
    is_high_severity(c.level, &c.tag, sample)
}

fn should_call_api(snap: &Snapshot, previous_key: &str) -> bool {
    if snap.clusters.is_empty() {
        return false;
    }
    let key = snap.digest_key();
    key != previous_key || snap.has_new_high_severity(previous_key)
}

fn assert_noise_excluded(snap: &Snapshot) {
    for tag in ["chatty", "OpenGLRenderer", "TrafficStats", "Zygote", "art"] {
        assert!(
            !snap.clusters.iter().any(|c| c.tag == tag),
            "{tag} noise must be excluded when errors_only"
        );
    }
}

fn assert_api_payload(snap: &Snapshot) {
    let json = snap.to_pretty_json();
    assert!(json.contains("\"device_model\": \"Pixel 8\""));
    assert!(json.contains("\"fingerprint\""));
    assert!(json.contains("\"clusters\""));
    assert!(!snap.digest_key().is_empty());
}

#[test]
fn errors_only_clusters_ordinary_failures() {
    let raw = include_str!("../fixtures/errors.threadtime");
    let events = fold_error_events(raw);
    assert!(
        events.iter().all(|e| !e.is_high_severity()),
        "errors fixture must not contain FATAL/ANR/panic shapes"
    );

    let snap = digest(raw);
    assert_noise_excluded(&snap);

    let okhttp_total: u32 = snap
        .clusters
        .iter()
        .filter(|c| c.tag == "OkHttp")
        .map(|c| c.count)
        .sum();
    assert_eq!(okhttp_total, 3, "three OkHttp E lines kept");
    assert!(
        snap.clusters
            .iter()
            .any(|c| c.tag == "OkHttp" && c.count == 2),
        "api host failures should share a fingerprint"
    );
    assert!(snap.clusters.iter().any(|c| c.tag == "SQLiteLog"));

    let system = snap
        .clusters
        .iter()
        .find(|c| c.tag == "System")
        .expect("System cluster");
    let sample = &system.samples[0];
    assert!(
        !sample.contains("a@b.com")
            && !sample.contains("10.0.0.1")
            && !sample.contains("sk-secret"),
        "secrets must be redacted: {sample}"
    );

    assert!(snap.clusters.iter().all(|c| !cluster_is_high(c)));
    assert_api_payload(&snap);
    assert!(should_call_api(&snap, ""));
    assert!(!snap.has_new_high_severity(""));
}

#[test]
fn errors_and_panics_folds_stacks_and_keeps_errors() {
    let raw = include_str!("../fixtures/errors_and_panics.threadtime");
    let events = fold_error_events(raw);
    assert!(
        events
            .iter()
            .any(|e| e.tag == "AndroidRuntime" && e.samples.len() > 1),
        "FATAL stack should fold to one multi-sample event"
    );
    assert!(
        events
            .iter()
            .any(|e| e.tag == "ActivityManager" && e.is_high_severity()),
        "ANR should fold as high-severity"
    );
    assert!(
        events
            .iter()
            .any(|e| e.tag == "OkHttp" && !e.is_high_severity()),
        "ordinary errors remain beside panics"
    );

    let snap = digest(raw);
    assert_noise_excluded(&snap);

    let runtime = snap
        .clusters
        .iter()
        .find(|c| c.tag == "AndroidRuntime")
        .expect("AndroidRuntime cluster");
    assert!(runtime.samples.len() > 1);
    assert!(cluster_is_high(runtime));

    assert!(snap
        .clusters
        .iter()
        .any(|c| c.tag == "ActivityManager" && c.samples.iter().any(|s| s.contains("ANR"))));
    assert!(snap.clusters.iter().any(|c| c.tag == "OkHttp"));
    assert!(snap.clusters.iter().any(|c| c.tag == "System"));

    let system = snap
        .clusters
        .iter()
        .find(|c| c.tag == "System")
        .expect("System cluster");
    assert!(
        !system.samples[0].contains("hunter2") && !system.samples[0].contains("a@b.com"),
        "password/email redacted: {}",
        system.samples[0]
    );

    assert_api_payload(&snap);
    assert!(snap.has_new_high_severity(""));
    assert!(should_call_api(&snap, ""));
}

#[test]
fn panics_only_high_severity_clusters() {
    let raw = include_str!("../fixtures/panics.threadtime");
    let events = fold_error_events(raw);
    assert!(
        !events.is_empty() && events.iter().all(|e| e.is_high_severity()),
        "panics fixture should only keep high-severity E/F events"
    );
    assert!(
        events
            .iter()
            .any(|e| e.tag == "AndroidRuntime" && e.samples.len() > 1),
        "FATAL stack folds"
    );
    assert!(
        events.iter().any(|e| e.tag == "DEBUG" && e.level == 'F'),
        "native Fatal signal kept"
    );
    assert!(
        events.iter().any(|e| e.tag == "ActivityManager"),
        "ANR kept"
    );

    let snap = digest(raw);
    assert_noise_excluded(&snap);
    assert!(!snap.clusters.is_empty());
    assert!(
        snap.clusters.iter().all(cluster_is_high),
        "every cluster should be high-severity"
    );
    assert!(!snap.clusters.iter().any(|c| c.tag == "OkHttp"));
    assert_api_payload(&snap);
    assert!(snap.has_new_high_severity(""));
}

#[test]
fn clean_yields_empty_snapshot_and_skips_api() {
    let raw = include_str!("../fixtures/clean.threadtime");
    let parsed: Vec<_> = raw.lines().filter_map(parse_threadtime).collect();
    assert!(
        !parsed.is_empty(),
        "clean fixture still has parseable lines"
    );
    assert!(
        parsed.iter().all(|l| !l.is_error_level()),
        "clean fixture must have no E/F lines"
    );

    let snap = digest(raw);
    assert!(snap.clusters.is_empty());
    assert_eq!(snap.digest_key(), "");
    assert_eq!(snap.levels, ["E", "F"]);
    assert!(!should_call_api(&snap, ""));
    assert!(!should_call_api(&snap, "deadbeef:0"));

    let json = snap.to_pretty_json();
    assert!(json.contains("\"clusters\": []"));
}

#[test]
fn api_gate_across_scenario_sequence() {
    let errors = digest(include_str!("../fixtures/errors.threadtime"));
    let mixed = digest(include_str!("../fixtures/errors_and_panics.threadtime"));
    let panics = digest(include_str!("../fixtures/panics.threadtime"));
    let clean = digest(include_str!("../fixtures/clean.threadtime"));

    assert!(should_call_api(&errors, ""));
    assert!(should_call_api(&mixed, &errors.digest_key()));
    assert!(
        mixed.has_new_high_severity(&errors.digest_key()),
        "FATAL AndroidRuntime is new vs errors-only digest"
    );
    assert!(should_call_api(&panics, &mixed.digest_key()));
    assert!(!should_call_api(&clean, &panics.digest_key()));

    // Unchanged mix → skip re-query.
    assert!(!should_call_api(&errors, &errors.digest_key()));
}
