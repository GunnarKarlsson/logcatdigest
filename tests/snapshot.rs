use logcat_digest::{digest_threadtime, generate_device_label, SnapshotOpts};

#[test]
fn fixture_crash_anr_snapshot() {
    let raw = include_str!("fixtures/crash_anr.threadtime");
    let snap = digest_threadtime(
        raw.lines(),
        SnapshotOpts {
            device_label: generate_device_label("Pixel 8", "emulator-5554"),
            device_model: "Pixel 8".into(),
            ..SnapshotOpts::default()
        },
    );

    assert!(
        snap.clusters
            .iter()
            .any(|c| c.tag == "AndroidRuntime" && c.samples.len() > 1),
        "fatal stack should fold into one multi-sample cluster"
    );
    assert!(
        snap.clusters
            .iter()
            .any(|c| c.tag == "ActivityManager" && c.samples.iter().any(|s| s.contains("ANR"))),
        "ANR should appear as a cluster"
    );

    let okhttp = snap
        .clusters
        .iter()
        .find(|c| c.tag == "OkHttp")
        .expect("OkHttp cluster");
    assert_eq!(
        okhttp.count, 2,
        "noise-collapsed OkHttp failures share a fingerprint"
    );

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
        "email, IPv4, and tokens must be redacted: {sample}"
    );

    assert!(
        !snap.clusters.iter().any(|c| c.tag == "chatty"),
        "info lines excluded when errors_only"
    );
    assert!(snap.clusters.len() <= 8);
    assert!(!snap.digest_key().is_empty());

    let json = snap.to_pretty_json();
    assert!(json.contains("\"device_model\": \"Pixel 8\""));
    assert!(json.contains("\"fingerprint\""));
}
