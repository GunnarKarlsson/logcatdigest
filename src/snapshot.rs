//! Build a serializable LLM-ready snapshot from raw logcat lines.

use serde::Serialize;

use crate::content::{ContentType, LogLevel};
use crate::event::{GroupedEvent, GroupedEventList, IndexedLogLine};
use crate::fingerprint::{DeviceLabel, DeviceModel};
use crate::parse::{parse_threadtime, LogLine};
use crate::reduce::{absorb, retain_clusters, trim_to_json_budget};

const DIGEST_COUNT_BUCKET: u32 = 5;
const DEFAULT_MAX_CLUSTERS: usize = 8;

fn default_levels() -> Vec<LogLevel> {
    vec![LogLevel::Error, LogLevel::Fatal]
}

/// Options for [`Snapshot::from_logcat_lines`].
#[derive(Debug, Clone)]
pub struct SnapshotOpts {
    /// Non-reversible device id; empty when unset.
    pub device_label: DeviceLabel,
    /// Human-readable model; empty when unset.
    pub device_model: DeviceModel,
    /// Content shapes to keep; empty means all types.
    pub content_types: Vec<ContentType>,
    /// Priority levels to keep; default Error + Fatal.
    pub levels: Vec<LogLevel>,
    /// Tag allow-list; empty means all tags.
    pub tags: Vec<String>,
    /// Optional substring that must appear in the event text.
    pub contains: Option<String>,
    /// Soft cap on retained clusters (high-severity shapes are pinned first).
    pub max_clusters: usize,
}

impl SnapshotOpts {
    /// Start an optional-field builder. [`SnapshotOptsBuilder::build`] always succeeds.
    pub fn builder() -> SnapshotOptsBuilder {
        SnapshotOptsBuilder::default()
    }

    fn allows_level(&self, level: char) -> bool {
        self.levels.iter().any(|allowed| allowed.as_char() == level)
    }

    fn allows_event(&self, event: &GroupedEvent) -> bool {
        if !self.allows_level(event.level) {
            return false;
        }
        if !self.tags.is_empty() && !self.tags.iter().any(|t| t == &event.tag) {
            return false;
        }
        let blob = event_text(event);
        if let Some(needle) = &self.contains {
            if !blob.contains(needle.as_str()) {
                return false;
            }
        }
        if self.content_types.is_empty() {
            return true;
        }
        self.content_types
            .iter()
            .any(|ct| ct.matches(event.level, &event.tag, &blob))
    }

    fn level_labels(&self) -> Vec<&'static str> {
        self.levels.iter().map(|l| l.as_str()).collect()
    }
}

fn event_text(event: &GroupedEvent) -> String {
    if event.samples.is_empty() {
        event.headline.clone()
    } else {
        event.samples.join("\n")
    }
}

impl Default for SnapshotOpts {
    fn default() -> Self {
        Self {
            device_label: DeviceLabel::default(),
            device_model: DeviceModel::default(),
            content_types: Vec::new(),
            levels: default_levels(),
            tags: Vec::new(),
            contains: None,
            max_clusters: DEFAULT_MAX_CLUSTERS,
        }
    }
}

/// Builder for [`SnapshotOpts`]. Every field is optional.
#[derive(Debug, Clone)]
pub struct SnapshotOptsBuilder {
    device_label: DeviceLabel,
    device_model: DeviceModel,
    content_types: Vec<ContentType>,
    levels: Option<Vec<LogLevel>>,
    tags: Vec<String>,
    contains: Option<String>,
    max_clusters: usize,
}

impl Default for SnapshotOptsBuilder {
    fn default() -> Self {
        Self {
            device_label: DeviceLabel::default(),
            device_model: DeviceModel::default(),
            content_types: Vec::new(),
            levels: None,
            tags: Vec::new(),
            contains: None,
            max_clusters: DEFAULT_MAX_CLUSTERS,
        }
    }
}

impl SnapshotOptsBuilder {
    /// Set the device label (`DeviceLabel` or `(model, serial)`).
    pub fn device_label(mut self, label: impl Into<DeviceLabel>) -> Self {
        self.device_label = label.into();
        self
    }

    /// Set the device model (`DeviceModel` or `&str` / `String`).
    pub fn device_model(mut self, model: impl Into<DeviceModel>) -> Self {
        self.device_model = model.into();
        self
    }

    /// Keep only these content types (OR). Empty / unset means all types.
    pub fn content_types(mut self, types: impl IntoIterator<Item = ContentType>) -> Self {
        self.content_types = types.into_iter().collect();
        self
    }

    /// Keep only these priority levels (OR). Default is Error + Fatal.
    pub fn levels(mut self, levels: impl IntoIterator<Item = LogLevel>) -> Self {
        self.levels = Some(levels.into_iter().collect());
        self
    }

    /// Keep only these tags (OR). Empty means all tags.
    pub fn tags(mut self, tags: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.tags = tags.into_iter().map(Into::into).collect();
        self
    }

    /// Require this substring in the grouped event text (case-sensitive).
    pub fn contains(mut self, needle: impl Into<String>) -> Self {
        self.contains = Some(needle.into());
        self
    }

    /// Soft cap on retained clusters (default 8).
    pub fn max_clusters(mut self, max_clusters: usize) -> Self {
        self.max_clusters = max_clusters;
        self
    }

    /// Finish the builder into [`SnapshotOpts`].
    pub fn build(self) -> SnapshotOpts {
        SnapshotOpts {
            device_label: self.device_label,
            device_model: self.device_model,
            content_types: self.content_types,
            levels: self.levels.unwrap_or_else(default_levels),
            tags: self.tags,
            contains: self.contains,
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
    /// How many events grouped into this cluster.
    pub count: u32,
    /// Redacted sample messages (stacks may span several lines).
    pub samples: Vec<String>,
}

/// Reduced digest of log lines for one device.
#[derive(Debug, Clone, Serialize)]
pub struct Snapshot {
    /// Non-reversible device label (may be empty).
    pub device_label: DeviceLabel,
    /// Human-readable device model (may be empty).
    pub device_model: DeviceModel,
    /// Priority letters selected by the filter.
    pub levels: Vec<&'static str>,
    /// Budgeted clusters, high-severity shapes first when pinned.
    pub clusters: Vec<Cluster>,
}

impl Snapshot {
    /// Parse raw logcat threadtime lines, apply filters, and build a snapshot.
    ///
    /// Non-matching lines are dropped. Empty result means nothing matched the filters.
    pub fn from_logcat_lines(
        lines: impl IntoIterator<Item = impl AsRef<str>>,
        opts: SnapshotOpts,
    ) -> Self {
        let parsed: Vec<LogLine> = lines
            .into_iter()
            .filter_map(|line| parse_threadtime(line.as_ref()))
            .collect();
        Self::from_parsed_lines(&parsed, opts)
    }

    fn from_parsed_lines(lines: &[LogLine], opts: SnapshotOpts) -> Self {
        let indexed: Vec<IndexedLogLine> = lines
            .iter()
            .enumerate()
            .filter(|(_, l)| opts.allows_level(l.level))
            .map(|(i, l)| IndexedLogLine::from((i, l)))
            .collect();

        let events = GroupedEventList::group_from_indexed_log_lines(&indexed);
        let kept: Vec<GroupedEvent> = events
            .iter()
            .filter(|event| opts.allows_event(event))
            .cloned()
            .collect();

        let mut clusters = absorb(&kept);
        retain_clusters(&mut clusters, opts.max_clusters);
        trim_to_json_budget(&mut clusters);

        let levels = opts.level_labels();
        Self {
            device_label: opts.device_label,
            device_model: opts.device_model,
            levels,
            clusters,
        }
    }

    /// True when no clusters remain (nothing to send to the model).
    pub fn is_empty(&self) -> bool {
        self.clusters.is_empty()
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

    fn raw(level: char, tag: &str, message: &str) -> String {
        format!("09-17 12:00:00.000     1     1 {level} {tag}: {message}")
    }

    fn raw_pid(pid: u32, level: char, tag: &str, message: &str) -> String {
        format!("09-17 12:00:00.000  {pid:>5}  {pid:>5} {level} {tag}: {message}")
    }

    #[test]
    fn empty_snapshot() {
        let snap = Snapshot::from_logcat_lines(std::iter::empty::<&str>(), SnapshotOpts::default());
        assert!(snap.is_empty());
        assert_eq!(snap.levels, ["E", "F"]);
    }

    #[test]
    fn clusters_same_fingerprint() {
        let lines = [
            raw('E', "OkHttp", "failed host 1"),
            raw('E', "OkHttp", "failed host 2"),
            raw('E', "OkHttp", "failed host 3"),
            raw('E', "System", "disk full"),
        ];
        let snap =
            Snapshot::from_logcat_lines(lines.iter().map(String::as_str), SnapshotOpts::default());
        assert_eq!(snap.clusters.len(), 2);
        assert_eq!(snap.clusters[0].tag, "OkHttp");
        assert_eq!(snap.clusters[0].count, 3);
        assert_eq!(snap.clusters[1].tag, "System");
        assert_eq!(snap.clusters[1].count, 1);
    }

    #[test]
    fn default_levels_drop_info() {
        let lines = [
            raw('I', "OkHttp", "ok"),
            raw('F', "AndroidRuntime", "FATAL EXCEPTION"),
        ];
        let snap =
            Snapshot::from_logcat_lines(lines.iter().map(String::as_str), SnapshotOpts::default());
        assert_eq!(snap.clusters.len(), 1);
        assert_eq!(snap.clusters[0].tag, "AndroidRuntime");
    }

    #[test]
    fn samples_are_redacted() {
        let lines = [raw(
            'E',
            "AndroidRuntime",
            "token Bearer secret.jwt password=s3cret",
        )];
        let snap =
            Snapshot::from_logcat_lines(lines.iter().map(String::as_str), SnapshotOpts::default());
        assert!(!snap.clusters[0].samples[0].contains("secret.jwt"));
        assert!(!snap.clusters[0].samples[0].contains("s3cret"));
    }

    #[test]
    fn content_type_filter_keeps_anr_only() {
        let lines = [
            raw('E', "OkHttp", "failed host"),
            raw(
                'E',
                "ActivityManager",
                "ANR in com.example.app (com.example.app/.Main)",
            ),
        ];
        let opts = SnapshotOpts::builder()
            .content_types([ContentType::Anr])
            .build();
        let snap = Snapshot::from_logcat_lines(lines.iter().map(String::as_str), opts);
        assert_eq!(snap.clusters.len(), 1);
        assert_eq!(snap.clusters[0].tag, "ActivityManager");
    }

    #[test]
    fn tag_and_contains_filters() {
        let lines = [
            raw('E', "OkHttp", "NullPointerException at foo"),
            raw('E', "System", "NullPointerException at bar"),
            raw('E', "OkHttp", "timeout"),
        ];
        let opts = SnapshotOpts::builder()
            .tags(["OkHttp"])
            .contains("NullPointer")
            .build();
        let snap = Snapshot::from_logcat_lines(lines.iter().map(String::as_str), opts);
        assert_eq!(snap.clusters.len(), 1);
        assert!(snap.clusters[0].samples[0].contains("NullPointer"));
    }

    #[test]
    fn optional_device_fields_default_empty() {
        let opts = SnapshotOpts::builder().build();
        assert!(opts.device_label.is_empty());
        assert!(opts.device_model.is_empty());
        let snap = Snapshot::from_logcat_lines(
            [raw('E', "OkHttp", "boom")].iter().map(String::as_str),
            opts,
        );
        assert!(snap.device_label.is_empty());
        assert!(snap.device_model.is_empty());
    }

    #[test]
    fn digest_key_stable_for_same_count_bucket() {
        let a = [
            raw('E', "OkHttp", "failed host 1"),
            raw('E', "OkHttp", "failed host 2"),
            raw('E', "OkHttp", "failed host 3"),
        ];
        let b = [
            raw('E', "OkHttp", "failed host 1"),
            raw('E', "OkHttp", "failed host 2"),
            raw('E', "OkHttp", "failed host 3"),
            raw('E', "OkHttp", "failed host 4"),
        ];
        let snap_a =
            Snapshot::from_logcat_lines(a.iter().map(String::as_str), SnapshotOpts::default());
        let snap_b =
            Snapshot::from_logcat_lines(b.iter().map(String::as_str), SnapshotOpts::default());
        assert_eq!(snap_a.digest_key(), snap_b.digest_key());
    }

    #[test]
    fn digest_key_changes_for_new_fingerprint() {
        let a = [raw('E', "OkHttp", "failed host")];
        let b = [
            raw('E', "OkHttp", "failed host"),
            raw('F', "AndroidRuntime", "FATAL EXCEPTION"),
        ];
        let snap_a =
            Snapshot::from_logcat_lines(a.iter().map(String::as_str), SnapshotOpts::default());
        let snap_b =
            Snapshot::from_logcat_lines(b.iter().map(String::as_str), SnapshotOpts::default());
        assert_ne!(snap_a.digest_key(), snap_b.digest_key());
        assert!(snap_b.has_new_high_severity(&snap_a.digest_key()));
    }

    #[test]
    fn fatal_stack_is_one_cluster_beside_other_errors() {
        let mut lines = Vec::new();
        for i in 0..8 {
            for _ in 0..3 {
                lines.push(raw('E', "OkHttp", &format!("failed host {i}")));
            }
        }
        let pid = 3178;
        lines.push(raw_pid(pid, 'E', "AndroidRuntime", "FATAL EXCEPTION: main"));
        lines.push(raw_pid(
            pid,
            'E',
            "AndroidRuntime",
            "Process: com.android.settings, PID: 3178",
        ));
        lines.push(raw_pid(
            pid,
            'E',
            "AndroidRuntime",
            "at android.app.ActivityThread.main(ActivityThread.java:1)",
        ));
        let snap =
            Snapshot::from_logcat_lines(lines.iter().map(String::as_str), SnapshotOpts::default());
        let runtime = snap
            .clusters
            .iter()
            .filter(|c| c.tag == "AndroidRuntime")
            .count();
        assert_eq!(runtime, 1, "stack should group to one cluster");
        assert!(snap.clusters.iter().any(|c| c.tag == "OkHttp"));
        assert!(snap.clusters.len() <= 8);
    }

    #[test]
    fn parse_then_build_roundtrip() {
        let raw_line = "09-17 12:01:04.001  2144  2201 E OkHttp: failed 3 times at /data/app/foo";
        let snap = Snapshot::from_logcat_lines([raw_line], SnapshotOpts::default());
        assert_eq!(snap.clusters.len(), 1);
        assert_eq!(snap.clusters[0].tag, "OkHttp");
    }

    #[test]
    fn builder_sets_optional_device_and_filters() {
        let opts = SnapshotOpts::builder()
            .device_label(("Pixel 8", "emulator-5554"))
            .device_model("Pixel 8")
            .content_types([ContentType::Crash])
            .levels([LogLevel::Error, LogLevel::Fatal])
            .build();
        assert!(opts.device_label.starts_with("Pixel_8:"));
        assert_eq!(opts.device_model.as_ref(), "Pixel 8");
        assert_eq!(opts.content_types, [ContentType::Crash]);
        assert_eq!(opts.max_clusters, 8);
    }
}
