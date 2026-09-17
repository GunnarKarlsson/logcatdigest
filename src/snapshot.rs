//! Build a serializable LLM-ready snapshot from parsed log lines.

use serde::Serialize;

use crate::event::{fold_lines_to_events, InsightEvent, InsightLine};
use crate::fingerprint::{DeviceLabel, DeviceModel};
use crate::parse::LogLine;
use crate::reduce::{absorb, retain_clusters, trim_to_json_budget};

const DIGEST_COUNT_BUCKET: u32 = 5;
const DEFAULT_MAX_CLUSTERS: usize = 8;

/// Options for [`Snapshot::from_lines`] / [`Snapshot::from_events`].
#[derive(Debug, Clone)]
pub struct SnapshotOpts {
    /// Non-reversible device id from [`DeviceLabel::new`].
    pub device_label: DeviceLabel,
    /// Human-readable model stored on the snapshot.
    pub device_model: DeviceModel,
    /// When true, only Error and Fatal lines are included.
    pub errors_only: bool,
    /// Soft cap on retained clusters (high-severity shapes are pinned first).
    pub max_clusters: usize,
}

impl SnapshotOpts {
    /// Start a typestate builder; [`SnapshotOptsBuilder::build`] requires label and model.
    pub fn builder() -> SnapshotOptsBuilder<(), ()> {
        SnapshotOptsBuilder {
            label: (),
            model: (),
            errors_only: true,
            max_clusters: DEFAULT_MAX_CLUSTERS,
        }
    }
}

impl Default for SnapshotOpts {
    fn default() -> Self {
        Self {
            device_label: DeviceLabel::default(),
            device_model: DeviceModel::default(),
            errors_only: true,
            max_clusters: DEFAULT_MAX_CLUSTERS,
        }
    }
}

/// Typestate builder for [`SnapshotOpts`]. Missing label or model is a compile error.
#[derive(Debug, Clone)]
pub struct SnapshotOptsBuilder<L, M> {
    label: L,
    model: M,
    errors_only: bool,
    max_clusters: usize,
}

impl<L, M> SnapshotOptsBuilder<L, M> {
    /// Include only Error/Fatal lines when `true` (the default).
    pub fn errors_only(mut self, errors_only: bool) -> Self {
        self.errors_only = errors_only;
        self
    }

    /// Soft cap on retained clusters (default 8).
    pub fn max_clusters(mut self, max_clusters: usize) -> Self {
        self.max_clusters = max_clusters;
        self
    }
}

impl SnapshotOptsBuilder<(), ()> {
    /// Set the device label (`DeviceLabel` or `(model, serial)`).
    pub fn label(self, label: impl Into<DeviceLabel>) -> SnapshotOptsBuilder<DeviceLabel, ()> {
        SnapshotOptsBuilder {
            label: label.into(),
            model: self.model,
            errors_only: self.errors_only,
            max_clusters: self.max_clusters,
        }
    }

    /// Set the device model (`DeviceModel` or `&str` / `String`).
    pub fn model(self, model: impl Into<DeviceModel>) -> SnapshotOptsBuilder<(), DeviceModel> {
        SnapshotOptsBuilder {
            label: self.label,
            model: model.into(),
            errors_only: self.errors_only,
            max_clusters: self.max_clusters,
        }
    }
}

impl SnapshotOptsBuilder<DeviceLabel, ()> {
    /// Set the device model (`DeviceModel` or `&str` / `String`).
    pub fn model(
        self,
        model: impl Into<DeviceModel>,
    ) -> SnapshotOptsBuilder<DeviceLabel, DeviceModel> {
        SnapshotOptsBuilder {
            label: self.label,
            model: model.into(),
            errors_only: self.errors_only,
            max_clusters: self.max_clusters,
        }
    }
}

impl SnapshotOptsBuilder<(), DeviceModel> {
    /// Set the device label (`DeviceLabel` or `(model, serial)`).
    pub fn label(
        self,
        label: impl Into<DeviceLabel>,
    ) -> SnapshotOptsBuilder<DeviceLabel, DeviceModel> {
        SnapshotOptsBuilder {
            label: label.into(),
            model: self.model,
            errors_only: self.errors_only,
            max_clusters: self.max_clusters,
        }
    }
}

impl SnapshotOptsBuilder<DeviceLabel, DeviceModel> {
    /// Finish the builder into [`SnapshotOpts`].
    pub fn build(self) -> SnapshotOpts {
        SnapshotOpts {
            device_label: self.label,
            device_model: self.model,
            errors_only: self.errors_only,
            max_clusters: self.max_clusters,
        }
    }
}

/// One error shape: fingerprint, counts, and redacted samples.
#[derive(Debug, Clone, Serialize)]
pub struct Cluster {
    /// Noise-stable hex fingerprint for this shape.
    pub fingerprint: String,
    /// Representative log tag.
    pub tag: String,
    /// Representative priority letter.
    pub level: char,
    /// How many events folded into this cluster.
    pub count: u32,
    /// Redacted sample messages (stacks may span several lines).
    pub samples: Vec<String>,
}

/// Reduced digest of log lines for one device.
#[derive(Debug, Clone, Serialize)]
pub struct Snapshot {
    /// Non-reversible device label.
    pub device_label: DeviceLabel,
    /// Human-readable device model.
    pub device_model: DeviceModel,
    /// Priority letters included in this digest (`E`/`F` when errors-only).
    pub levels: Vec<&'static str>,
    /// Budgeted clusters, high-severity shapes first when pinned.
    pub clusters: Vec<Cluster>,
}

impl Snapshot {
    /// Filter, fold (redact), fingerprint, and cluster already-parsed log lines.
    pub fn from_lines(lines: &[LogLine], opts: SnapshotOpts) -> Self {
        let insight: Vec<InsightLine> = lines
            .iter()
            .enumerate()
            .filter(|(_, l)| !opts.errors_only || l.is_error_level())
            .map(|(i, l)| InsightLine::from((i, l)))
            .collect();

        let events = fold_lines_to_events(&insight);
        Self::from_events(&events, opts)
    }

    /// Fingerprint and consolidate folded events into a Chat Completions snapshot.
    ///
    /// Events should already carry redacted [`InsightEvent::samples`] (as produced by
    /// [`fold_lines_to_events`]). Identical bugs collapse by fingerprint; the result
    /// is pinned/trimmed to the cluster and JSON budgets.
    pub fn from_events(events: &[InsightEvent], opts: SnapshotOpts) -> Self {
        let mut clusters = absorb(events);
        retain_clusters(&mut clusters, opts.max_clusters);
        trim_to_json_budget(&mut clusters);

        Self {
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
        let snap = Snapshot::from_lines(&[], SnapshotOpts::default());
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
        let snap = Snapshot::from_lines(&lines, SnapshotOpts::default());
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
        let snap = Snapshot::from_lines(&lines, SnapshotOpts::default());
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
        let snap = Snapshot::from_lines(&lines, SnapshotOpts::default());
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
        let snap_a = Snapshot::from_lines(&a, SnapshotOpts::default());
        let snap_b = Snapshot::from_lines(&b, SnapshotOpts::default());
        assert_eq!(snap_a.digest_key(), snap_b.digest_key());
    }

    #[test]
    fn digest_key_changes_for_new_fingerprint() {
        let a = [line('E', "OkHttp", "failed host")];
        let b = [
            line('E', "OkHttp", "failed host"),
            line('F', "AndroidRuntime", "FATAL EXCEPTION"),
        ];
        let snap_a = Snapshot::from_lines(&a, SnapshotOpts::default());
        let snap_b = Snapshot::from_lines(&b, SnapshotOpts::default());
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
        let snap = Snapshot::from_lines(&lines, SnapshotOpts::default());
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
        let snap = Snapshot::from_lines(&[parsed], SnapshotOpts::default());
        assert_eq!(snap.clusters.len(), 1);
        assert_eq!(snap.clusters[0].tag, "OkHttp");
    }

    #[test]
    fn builder_requires_label_and_model() {
        let opts = SnapshotOpts::builder()
            .label(("Pixel 8", "emulator-5554"))
            .model("Pixel 8")
            .build();
        assert!(opts.device_label.starts_with("Pixel_8:"));
        assert_eq!(opts.device_model.as_ref(), "Pixel 8");
        assert!(opts.errors_only);
        assert_eq!(opts.max_clusters, 8);
    }
}
