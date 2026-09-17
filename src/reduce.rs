//! Cluster events by fingerprint and retain a budgeted top set.

use std::collections::HashMap;

use serde::Serialize;

use crate::event::InsightEvent;
use crate::fingerprint::fingerprint;
use crate::severity::is_high_severity;
use crate::snapshot::Cluster;

pub(crate) const MAX_HIGH_PIN: usize = 2;
pub(crate) const MAX_JSON_BYTES: usize = 6 * 1024;

/// Absorb events into fingerprint clusters.
pub fn absorb(events: &[InsightEvent]) -> Vec<Cluster> {
    let mut map: HashMap<String, Cluster> = HashMap::new();
    for event in events {
        let fp = fingerprint(&event.tag, &event.headline);
        let cluster = map.entry(fp.clone()).or_insert_with(|| Cluster {
            fingerprint: fp,
            tag: event.tag.clone(),
            level: event.level,
            count: 0,
            samples: Vec::new(),
        });
        cluster.count += 1;
        // Prefer the fullest stack/ANR dump; otherwise merge unique samples.
        if event.samples.len() > cluster.samples.len() {
            cluster.samples = event.samples.clone();
        } else {
            for sample in &event.samples {
                if !cluster.samples.contains(sample) {
                    cluster.samples.push(sample.clone());
                }
            }
        }
    }
    map.into_values().collect()
}

/// Sort by count; pin up to [`MAX_HIGH_PIN`] high-severity clusters, then fill by count.
pub fn retain_clusters(clusters: &mut Vec<Cluster>, max: usize) {
    clusters.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.tag.cmp(&b.tag)));
    let mut high = Vec::new();
    let mut rest = Vec::new();
    for cluster in clusters.drain(..) {
        let sample = cluster.samples.first().map(String::as_str).unwrap_or("");
        if is_high_severity(cluster.level, &cluster.tag, sample) && high.len() < MAX_HIGH_PIN {
            high.push(cluster);
        } else {
            rest.push(cluster);
        }
    }
    let room = max.saturating_sub(high.len());
    high.extend(rest.into_iter().take(room));
    *clusters = high;
}

/// Drop lowest-priority clusters until compact JSON fits under [`MAX_JSON_BYTES`].
pub fn trim_to_json_budget(clusters: &mut Vec<Cluster>) {
    while clusters.len() > 1 {
        let Ok(json) = serde_json::to_string(&ClustersLite { clusters }) else {
            break;
        };
        if json.len() <= MAX_JSON_BYTES {
            break;
        }
        clusters.pop();
    }
}

#[derive(Serialize)]
struct ClustersLite<'a> {
    clusters: &'a [Cluster],
}
