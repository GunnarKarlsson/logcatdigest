//! Small inline log → fully configured `SnapshotOpts` → JSON snapshot.
//!
//! ```bash
//! cargo run --example snapshot
//! ```

use logcatdigest::{ContentType, LogLevel, Snapshot, SnapshotOpts};

fn main() {
    let raw = r#"
09-17 12:01:03.120  2144  2144 E AndroidRuntime: FATAL EXCEPTION: main
09-17 12:01:03.120  2144  2144 E AndroidRuntime: java.lang.NullPointerException: boom
09-17 12:01:03.120  2144  2144 E AndroidRuntime: 	at com.app.MainActivity.onCreate(MainActivity.kt:42)
09-17 12:01:04.001  2144  2201 E OkHttp: failed 3 times at /data/app/foo token=sk-secret
"#;

    let opts = SnapshotOpts::builder()
        .device_label(("Pixel 8", "emulator-5554"))
        .device_model("Pixel 8")
        .content_types([ContentType::Fatal, ContentType::Anr, ContentType::Crash])
        .levels([LogLevel::Error, LogLevel::Fatal])
        .tags(["AndroidRuntime", "OkHttp"])
        .contains("Exception")
        .max_clusters(8)
        .build();

    let snap = Snapshot::from_logcat_lines(raw.lines(), opts);

    if snap.is_empty() {
        println!("nothing matched");
        return;
    }
    println!("{}", snap.to_pretty_json());
    println!("digest_key={}", snap.digest_key());
}
