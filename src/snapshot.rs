//! Build a serializable LLM-ready snapshot from parsed log lines.

use serde::Serialize;

use crate::event::{fold_lines_to_events, InsightLine};
use crate::parse::LogLine;
use crate::reduce::{absorb, retain_clusters, trim_to_json_budget};

const DIGEST_COUNT_BUCKET: u32 = 5;

/// Options for [`build_snapshot`] / [`crate::digest_threadtime`].
#[derive(Debug, Clone)]
pub struct SnapshotOpts {
    pub device_label: String,
    pub device_model: String,
    /// When true, only Error and Fatal lines are included.
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

/// One error shape: fingerprint, counts, and redacted samples.
#[derive(Debug, Clone, Serialize)]
pub struct Cluster {
    pub fingerprint: String,
    pub tag: String,
    pub level: char,
    pub count: u32,
    pub samples: Vec<String>,
}

/// Reduced digest of log lines for one device.
#[derive(Debug, Clone, Serialize)]
pub struct Snapshot {
    pub device_label: String,
    pub device_model: String,
    pub levels: Vec<&'static str>,
    pub clusters: Vec<Cluster>,
}

impl Snapshot {
    /// Pretty-printed JSON suitable as a Chat Completions user message.
    pub fn to_pretty_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("snapshot serializes")
    }

    /// Short change-detection key: `fingerprint:{count / 5}` pairs joined by `|`.
    pub fn digest_key(&self) -> String {
        self.clusters
            .iter()
            .map(|cluster| {
                format!(
                    "{}:{}",
                    cluster.fingerprint,
                    cluster.count / DIGEST_COUNT_BUCKET
                )
            })
            .collect::<Vec<_>>()
            .join("|")
    }

    /// True if any fatal or AndroidRuntime cluster fingerprint is absent from `previous_key`.
    pub fn has_new_high_severity(&self, previous_key: &str) -> bool {
        self.clusters.iter().any(|cluster| {
            (cluster.level == 'F' || cluster.tag == "AndroidRuntime")
                && !previous_key.contains(cluster.fingerprint.as_str())
        })
    }
}

/// Build a snapshot from already-parsed log lines.
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
    trim_to_json_budget(&mut clusters);

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::parse_threadtime;

    fn line(level: char, tag: &str, message: &str) -> LogLine {
        LogLine {
            timestamp: "09-17 12:00:00.000".into(),
            pid: 1,
            tid: 1,
            level,
            tag: tag.into(),
            message: message.into(),
        }
    }

    fn line_pid(pid: u32, level: char, tag: &str, message: &str) -> LogLine {
        LogLine {
            pid,
            ..line(level, tag, message)
        }
    }

    #[test]
    fn empty_snapshot() {
        let snap = build_snapshot(&[], SnapshotOpts::default());
        assert!(snap.clusters.is_empty());
        assert_eq!(snap.levels, ["E", "F"]);
    }

    #[test]
    fn clusters_same_fingerprint() {
        let lines = [
            line('E', "OkHttp", "failed host 1"),
            line('E', "OkHttp", "failed host 2"),
            line('E', "OkHttp", "failed host 3"),
            line('E', "System", "disk full"),
        ];
        let snap = build_snapshot(&lines, SnapshotOpts::default());
        assert_eq!(snap.clusters.len(), 2);
        assert_eq!(snap.clusters[0].tag, "OkHttp");
        assert_eq!(snap.clusters[0].count, 3);
        assert_eq!(snap.clusters[1].tag, "System");
        assert_eq!(snap.clusters[1].count, 1);
    }

    #[test]
    fn ignores_info_when_errors_only() {
        let lines = [
            line('I', "OkHttp", "ok"),
            line('F', "AndroidRuntime", "FATAL EXCEPTION"),
        ];
        let snap = build_snapshot(&lines, SnapshotOpts::default());
        assert_eq!(snap.clusters.len(), 1);
        assert_eq!(snap.clusters[0].tag, "AndroidRuntime");
    }

    #[test]
    fn samples_are_redacted() {
        let lines = [line(
            'E',
            "AndroidRuntime",
            "token Bearer secret.jwt password=s3cret",
        )];
        let snap = build_snapshot(&lines, SnapshotOpts::default());
        assert!(!snap.clusters[0].samples[0].contains("secret.jwt"));
        assert!(!snap.clusters[0].samples[0].contains("s3cret"));
    }

    #[test]
    fn digest_key_stable_for_same_count_bucket() {
        let a = [
            line('E', "OkHttp", "failed host 1"),
            line('E', "OkHttp", "failed host 2"),
            line('E', "OkHttp", "failed host 3"),
        ];
        let b = [
            line('E', "OkHttp", "failed host 1"),
            line('E', "OkHttp", "failed host 2"),
            line('E', "OkHttp", "failed host 3"),
            line('E', "OkHttp", "failed host 4"),
        ];
        let snap_a = build_snapshot(&a, SnapshotOpts::default());
        let snap_b = build_snapshot(&b, SnapshotOpts::default());
        assert_eq!(snap_a.digest_key(), snap_b.digest_key());
    }

    #[test]
    fn digest_key_changes_for_new_fingerprint() {
        let a = [line('E', "OkHttp", "failed host")];
        let b = [
            line('E', "OkHttp", "failed host"),
            line('F', "AndroidRuntime", "FATAL EXCEPTION"),
        ];
        let snap_a = build_snapshot(&a, SnapshotOpts::default());
        let snap_b = build_snapshot(&b, SnapshotOpts::default());
        assert_ne!(snap_a.digest_key(), snap_b.digest_key());
        assert!(snap_b.has_new_high_severity(&snap_a.digest_key()));
    }

    #[test]
    fn fatal_stack_is_one_cluster_beside_other_errors() {
        let mut lines = Vec::new();
        for i in 0..8 {
            for _ in 0..3 {
                lines.push(line('E', "OkHttp", &format!("failed host {i}")));
            }
        }
        let pid = 3178;
        lines.push(line_pid(
            pid,
            'E',
            "AndroidRuntime",
            "FATAL EXCEPTION: main",
        ));
        lines.push(line_pid(
            pid,
            'E',
            "AndroidRuntime",
            "Process: com.android.settings, PID: 3178",
        ));
        lines.push(line_pid(
            pid,
            'E',
            "AndroidRuntime",
            "at android.app.ActivityThread.main(ActivityThread.java:1)",
        ));
        let snap = build_snapshot(&lines, SnapshotOpts::default());
        let runtime = snap
            .clusters
            .iter()
            .filter(|c| c.tag == "AndroidRuntime")
            .count();
        assert_eq!(runtime, 1, "stack should fold to one cluster");
        assert!(snap.clusters.iter().any(|c| c.tag == "OkHttp"));
        assert!(snap.clusters.len() <= 8);
    }

    #[test]
    fn parse_then_build_roundtrip() {
        let raw = "09-17 12:01:04.001  2144  2201 E OkHttp: failed 3 times at /data/app/foo";
        let parsed = parse_threadtime(raw).unwrap();
        let snap = build_snapshot(&[parsed], SnapshotOpts::default());
        assert_eq!(snap.clusters.len(), 1);
        assert_eq!(snap.clusters[0].tag, "OkHttp");
    }
}
