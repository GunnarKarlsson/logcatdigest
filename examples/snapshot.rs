use logcatdigest::{parse_threadtime, Snapshot, SnapshotOpts};

fn main() {
    let raw = r#"
09-17 12:01:03.120  2144  2144 E AndroidRuntime: FATAL EXCEPTION: main
09-17 12:01:03.120  2144  2144 E AndroidRuntime: java.lang.NullPointerException: boom
09-17 12:01:03.120  2144  2144 E AndroidRuntime: 	at com.app.MainActivity.onCreate(MainActivity.kt:42)
09-17 12:01:04.001  2144  2201 E OkHttp: failed 3 times at /data/app/foo token=sk-secret
"#;

    let lines: Vec<_> = raw.lines().filter_map(parse_threadtime).collect();
    let snap = Snapshot::from_lines(
        &lines,
        SnapshotOpts::builder()
            .label(("Pixel 8", "emulator-5554"))
            .model("Pixel 8")
            .build(),
    );

    println!("{}", snap.to_pretty_json());
    println!("digest_key={}", snap.digest_key());
}
