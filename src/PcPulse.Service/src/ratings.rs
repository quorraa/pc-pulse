//! Demand bucketing and performance digests for the ratings feature.
//!
//! Two pure functions live here:
//!
//! - [`demand_bucket`]: turns a trailing window of raw system samples plus
//!   the machine's learned baseline sketches into the coarse
//!   [`DemandBucket`] (light/moderate/heavy) a rating is filed under, and the
//!   [`DemandDetail`] that records exactly what fed that verdict.
//! - [`build_digest`]: assembles the compact, redacted, size-bounded
//!   performance digest snapshotted into every rating -- a compacted sibling
//!   of the agent-context evidence bundle (`analysis::build_agent_context`),
//!   reusing its rollup and redaction machinery via `pub(crate)` rather than
//!   duplicating it.
//!
//! Both functions are pure: callers (the pipe handler, in a later task) are
//! responsible for gathering the trailing samples, incidents, and learning
//! state and handing them in. Nothing here touches storage or the clock.

use crate::analysis;
use crate::baselines::MachineBaseline;
use crate::config::Settings;
use crate::models::{
    Alert, AlertQuality, DemandBucket, DemandDetail, HistoryResponse, Severity, Snapshot,
};
use crate::stats::PercentileSketch;
use serde::Serialize;

/// Trailing-window sample count above which a bucket is "sustained" toward a
/// verdict: each sample in the window is classified independently, and the
/// bucket with the most samples wins. Ties are broken toward the more severe
/// bucket -- for demand context that calibrates notification floors, a tied
/// window erring toward "heavy" avoids under-counting demand, which is
/// exactly the deceptive-comfort hazard this feature exists to guard
/// against. Named and tested as `sustained_bucket_uses_the_trailing_window_majority`.
fn majority_bucket(buckets: &[DemandBucket]) -> DemandBucket {
    let (mut light, mut moderate, mut heavy) = (0u32, 0u32, 0u32);
    for bucket in buckets {
        match bucket {
            DemandBucket::Light => light += 1,
            DemandBucket::Moderate => moderate += 1,
            DemandBucket::Heavy => heavy += 1,
        }
    }
    if heavy >= light && heavy >= moderate {
        DemandBucket::Heavy
    } else if moderate >= light {
        DemandBucket::Moderate
    } else {
        DemandBucket::Light
    }
}

/// Percentile threshold (against the machine baseline) at/above which a
/// sample's composite counts as heavy demand. Global Constraints: "heavy >=
/// p90 sustained, moderate >= p50".
const HEAVY_COMPOSITE_PERCENTILE: f64 = 90.0;
const MODERATE_COMPOSITE_PERCENTILE: f64 = 50.0;
/// Tolerance applied to the composite-percentile boundary checks, to absorb
/// floating-point noise from the `f64 -> u64 -> f64` round trip a raw memory
/// reading takes through `SystemMetric.memory_used_bytes` before it can be
/// compared back against a sketch's quantile output. Without it, a reading
/// that is conceptually "exactly at p50" can land a few ulps below it and
/// silently fall into the wrong bucket.
const PERCENTILE_EPSILON: f64 = 1e-6;

/// Pre-learning fallback cutoffs, used only when every channel's percentile
/// is unavailable (baseline sketch hasn't seen 5 samples yet). The spec is
/// silent on the exact values here, so these are the plan's documented
/// choice: fixed, conservative, and only ever active before the machine has
/// learned anything.
const CPU_FALLBACK_HEAVY_PERCENT: f64 = 80.0;
const MEMORY_FALLBACK_HEAVY_PERCENT: f64 = 90.0;
const CPU_FALLBACK_MODERATE_PERCENT: f64 = 50.0;
const MEMORY_FALLBACK_MODERATE_PERCENT: f64 = 70.0;

/// Estimate the percentile rank of `value` against a [`PercentileSketch`]
/// that only exposes value-at-quantile for q in {0.5, 0.95, 0.99}. Returns
/// `None` when the sketch can't yet answer at all (fewer than 5
/// observations) -- the caller degrades that channel out of the composite
/// rather than fabricating a number.
///
/// The estimate is a piecewise-linear interpolation between the three known
/// anchors (with an implicit (0, 0th percentile) anchor below the median,
/// and a flat extrapolation at/after p99): exact at the anchors themselves,
/// approximate in between. That's sufficient here -- the composite only
/// needs to know roughly where a live reading sits relative to what the
/// machine has learned, not a precise rank.
fn percentile_rank(sketch: &PercentileSketch, value: f64) -> Option<f64> {
    let p50 = sketch.quantile(0.5)?;
    // Same underlying observation count feeds all three P2 markers, so once
    // p50 answers, p95/p99 always do too (see `PercentileSketch::quantile`).
    // Guard defensively anyway rather than assuming that invariant forever.
    let p95 = sketch.quantile(0.95).unwrap_or(p50);
    let p99 = sketch.quantile(0.99).unwrap_or(p95);

    if value <= p50 {
        if p50 <= 0.0 {
            return Some(50.0);
        }
        return Some((value / p50 * 50.0).clamp(0.0, 50.0));
    }
    if value <= p95 {
        if (p95 - p50).abs() < f64::EPSILON {
            return Some(95.0);
        }
        return Some(50.0 + (value - p50) / (p95 - p50) * 45.0);
    }
    if value <= p99 {
        if (p99 - p95).abs() < f64::EPSILON {
            return Some(99.0);
        }
        return Some(95.0 + (value - p95) / (p99 - p95) * 4.0);
    }
    Some(99.0)
}

fn memory_occupancy_pct(memory_used_bytes: u64, memory_total_bytes: u64) -> f64 {
    if memory_total_bytes == 0 {
        0.0
    } else {
        memory_used_bytes as f64 / memory_total_bytes as f64 * 100.0
    }
}

/// Classify one sample against the machine baseline, returning both the
/// bucket it falls in and the raw/percentile readings behind that call.
///
/// The machine baseline (`baselines.rs`, Task 1's scope) tracks percentile
/// sketches for memory occupancy and disk latency only -- it has no CPU or
/// IO-rate sketch. So `cpu_percentile` and `io_percentile` are always `None`
/// here: there is no sketch to ask, and this module never fabricates an
/// answer. In practice that leaves memory-occupancy percentile as the only
/// channel that can ever feed the learned composite; CPU/IO only influence
/// the bucket via the pre-learning fixed fallback below. A future baseline
/// task adding CPU/IO sketches would light those channels up without any
/// change to this function's shape.
fn classify_sample(
    sample: &crate::models::SystemMetric,
    machine: &MachineBaseline,
) -> (DemandBucket, DemandDetail) {
    let memory_pct = memory_occupancy_pct(sample.memory_used_bytes, sample.memory_total_bytes);
    let io_bytes_per_sec = sample.disk_read_bytes_per_sec + sample.disk_write_bytes_per_sec;

    let memory_percentile = percentile_rank(&machine.memory_occupancy_pct, memory_pct);
    let disk_percentile = percentile_rank(&machine.disk_latency_ms, sample.disk_latency_ms);
    let cpu_percentile: Option<f64> = None;
    let io_percentile: Option<f64> = None;

    let detail = DemandDetail {
        cpu_percent: sample.cpu_percent,
        cpu_percentile,
        memory_occupancy_pct: memory_pct,
        memory_percentile,
        disk_latency_ms: sample.disk_latency_ms,
        disk_percentile,
        io_bytes_per_sec,
        io_percentile,
    };

    // Composite = max of whichever of {CPU, memory, IO} percentiles are
    // actually available (Global Constraints). Disk latency is recorded in
    // the detail but, per spec, is not itself a composite input.
    let composite = [cpu_percentile, memory_percentile, io_percentile]
        .into_iter()
        .flatten()
        .fold(None::<f64>, |acc, p| Some(acc.map_or(p, |a: f64| a.max(p))));

    let bucket = match composite {
        Some(p) if p >= HEAVY_COMPOSITE_PERCENTILE - PERCENTILE_EPSILON => DemandBucket::Heavy,
        Some(p) if p >= MODERATE_COMPOSITE_PERCENTILE - PERCENTILE_EPSILON => {
            DemandBucket::Moderate
        }
        Some(_) => DemandBucket::Light,
        None => {
            if sample.cpu_percent >= CPU_FALLBACK_HEAVY_PERCENT
                || memory_pct >= MEMORY_FALLBACK_HEAVY_PERCENT
            {
                DemandBucket::Heavy
            } else if sample.cpu_percent >= CPU_FALLBACK_MODERATE_PERCENT
                || memory_pct >= MEMORY_FALLBACK_MODERATE_PERCENT
            {
                DemandBucket::Moderate
            } else {
                DemandBucket::Light
            }
        }
    };

    (bucket, detail)
}

/// Derive the trailing-window demand bucket and detail for a rating.
///
/// `recent` is the trailing window the caller has already selected (Global
/// Constraints: trailing 10 minutes) -- this function stays pure and does
/// not filter by timestamp itself. An empty slice degrades to `Light` with
/// an all-`None`/all-zero detail rather than guessing.
///
/// The bucket is the sustained (majority-of-window) verdict across every
/// sample; the returned detail reflects the most recent sample -- the raw
/// composite inputs "at rating time".
pub fn demand_bucket(
    recent: &[crate::models::SystemMetric],
    machine: &MachineBaseline,
) -> (DemandBucket, DemandDetail) {
    let Some(latest) = recent.last() else {
        return (
            DemandBucket::Light,
            DemandDetail {
                cpu_percent: 0.0,
                cpu_percentile: None,
                memory_occupancy_pct: 0.0,
                memory_percentile: None,
                disk_latency_ms: 0.0,
                disk_percentile: None,
                io_bytes_per_sec: 0.0,
                io_percentile: None,
            },
        );
    };

    let mut buckets = Vec::with_capacity(recent.len());
    for sample in recent {
        let (bucket, _) = classify_sample(sample, machine);
        buckets.push(bucket);
    }
    let bucket = majority_bucket(&buckets);
    let (_, detail) = classify_sample(latest, machine);
    (bucket, detail)
}

// ---------------------------------------------------------------------
// Performance digest
// ---------------------------------------------------------------------

/// Serialized digest size cap (Global Constraints: <= 32 KB). Enforced by
/// `build_digest`, never exceeded.
const DIGEST_MAX_BYTES: usize = 32 * 1024;
/// Top-N processes retained in a digest by pressure score, before any
/// further trimming forced by the size cap.
const DIGEST_MAX_PROCESSES: usize = 20;
/// String-length ladder tried, in order, when the digest is still over cap
/// after dropping process entries. Log-like strings (collector health line,
/// incident kind/fingerprint) are truncated to the first length in this list
/// that brings the digest back under the cap.
const STRING_TRUNCATION_LADDER: [usize; 4] = [500, 200, 80, 20];

/// Compact, redacted, agent-digest-shaped view of one active incident,
/// including its quality scores -- the labeled corpus a future optimization
/// agent will read alongside the (verdict, demand) pair.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct DigestIncident {
    fingerprint: String,
    kind: String,
    severity: Severity,
    quality: AlertQuality,
    notify: bool,
    acknowledged: bool,
}

impl From<&Alert> for DigestIncident {
    fn from(alert: &Alert) -> Self {
        Self {
            fingerprint: alert.fingerprint.clone(),
            kind: alert.kind.clone(),
            severity: alert.severity,
            quality: alert.quality,
            notify: alert.notify,
            acknowledged: alert.acknowledged,
        }
    }
}

/// Everything `build_digest` needs, gathered by the caller so this module
/// stays pure (no storage/clock access).
pub struct DigestSource<'a> {
    /// Trailing-hour system + process history, rolled up the same way the
    /// agent-context evidence bundle is (`analysis::rollup_system` /
    /// `rollup_processes`, reused rather than duplicated).
    pub history: HistoryResponse,
    /// Current snapshot, needed by the process rollup to weight
    /// still-running processes the same way the agent context does.
    pub snapshot: &'a Snapshot,
    pub settings: &'a Settings,
    /// Incidents active at rating time (caller filters to active; this
    /// module does not re-derive that).
    pub incidents: Vec<Alert>,
    pub learning: bool,
    pub learning_percent: Option<u8>,
    /// One-line collector health summary, assembled by the caller from
    /// whatever diagnostic-log/collector status it already has in hand.
    pub collector_health: String,
}

fn compose(
    rollup: &crate::models::AgentSystemRollup,
    processes: &[crate::models::AgentProcessRollup],
    incidents: &[DigestIncident],
    learning: bool,
    learning_percent: Option<u8>,
    collector_health: &str,
) -> serde_json::Value {
    serde_json::json!({
        "systemRollup": rollup,
        "processes": processes,
        "incidents": incidents,
        "learning": learning,
        "learningPercent": learning_percent,
        "collectorHealth": collector_health,
    })
}

fn serialized_len(value: &serde_json::Value) -> usize {
    serde_json::to_vec(value)
        .map(|bytes| bytes.len())
        .unwrap_or(usize::MAX)
}

fn truncate_str(value: &str, max_len: usize) -> String {
    if value.len() <= max_len {
        return value.to_string();
    }
    let mut end = max_len;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &value[..end])
}

/// Assemble the agent-ready performance digest snapshotted into a rating.
///
/// Reuses the analyzer's rollup/redaction machinery (`analysis::rollup_system`,
/// `analysis::rollup_processes`) rather than duplicating it -- the digest is
/// a compacted sibling of the agent-context evidence bundle. Always returns
/// a digest serializing to <= [`DIGEST_MAX_BYTES`]: first by capping (then,
/// if needed, further dropping) process entries, then by truncating
/// log-like strings, then -- only in pathological cases -- by dropping
/// incident entries too. Never emits an over-cap digest.
pub fn build_digest(source: DigestSource<'_>) -> serde_json::Value {
    let rollup = analysis::rollup_system(&source.history);
    let mut processes =
        analysis::rollup_processes(&source.history.processes, source.snapshot, source.settings);
    processes.truncate(DIGEST_MAX_PROCESSES);
    let mut incidents: Vec<DigestIncident> =
        source.incidents.iter().map(DigestIncident::from).collect();
    let mut collector_health = source.collector_health.clone();

    let mut value = compose(
        &rollup,
        &processes,
        &incidents,
        source.learning,
        source.learning_percent,
        &collector_health,
    );

    // 1. Drop process entries (lowest pressure first, since rollup_processes
    // is already sorted descending) until the digest fits or none remain.
    while serialized_len(&value) > DIGEST_MAX_BYTES && !processes.is_empty() {
        processes.pop();
        value = compose(
            &rollup,
            &processes,
            &incidents,
            source.learning,
            source.learning_percent,
            &collector_health,
        );
    }

    // 2. Still over cap: truncate log-like strings progressively.
    if serialized_len(&value) > DIGEST_MAX_BYTES {
        for max_len in STRING_TRUNCATION_LADDER {
            collector_health = truncate_str(&collector_health, max_len);
            for incident in &mut incidents {
                incident.kind = truncate_str(&incident.kind, max_len);
                incident.fingerprint = truncate_str(&incident.fingerprint, max_len);
            }
            value = compose(
                &rollup,
                &processes,
                &incidents,
                source.learning,
                source.learning_percent,
                &collector_health,
            );
            if serialized_len(&value) <= DIGEST_MAX_BYTES {
                break;
            }
        }
    }

    // 3. Last resort (not expected in practice): drop incident entries too.
    while serialized_len(&value) > DIGEST_MAX_BYTES && !incidents.is_empty() {
        incidents.pop();
        value = compose(
            &rollup,
            &processes,
            &incidents,
            source.learning,
            source.learning_percent,
            &collector_health,
        );
    }

    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{AlertQuality, ProcessMetric, Severity, SystemMetric};

    // A large total keeps the `f64 -> u64` byte conversion below below
    // sub-percent precision loss, so a percentage fed in here round-trips
    // back out of `memory_used_bytes / memory_total_bytes * 100` close
    // enough to compare directly against a sketch's `f64` quantile output.
    fn system_sample(cpu_percent: f64, memory_occupancy_pct: f64) -> SystemMetric {
        SystemMetric {
            cpu_percent,
            memory_used_bytes: (memory_occupancy_pct * 10_000_000_000.0) as u64,
            memory_total_bytes: 1_000_000_000_000,
            ..SystemMetric::default()
        }
    }

    fn seeded_memory_baseline() -> MachineBaseline {
        let mut machine = MachineBaseline::new(0);
        // A skewed-but-well-behaved occupancy distribution, same shape as
        // the baselines.rs seeding pattern, so the sketch has a real
        // memory-occupancy median/p95/p99 to test the composite against.
        for i in 0..2_000 {
            let value = (i % 100) as f64;
            machine.observe(&system_sample(0.0, value), 400, i as i64 * 5_000);
        }
        machine
    }

    #[test]
    fn empty_slice_is_light_with_all_none_detail() {
        let machine = MachineBaseline::new(0);
        let (bucket, detail) = demand_bucket(&[], &machine);
        assert_eq!(bucket, DemandBucket::Light);
        assert_eq!(detail.cpu_percentile, None);
        assert_eq!(detail.memory_percentile, None);
        assert_eq!(detail.disk_percentile, None);
        assert_eq!(detail.io_percentile, None);
        assert_eq!(detail.cpu_percent, 0.0);
        assert_eq!(detail.memory_occupancy_pct, 0.0);
    }

    #[test]
    fn composite_exactly_at_p50_is_moderate() {
        let machine = seeded_memory_baseline();
        let p50 = machine.memory_occupancy_pct.quantile(0.5).unwrap();
        let sample = system_sample(0.0, p50);
        let (bucket, detail) = demand_bucket(&[sample], &machine);
        assert_eq!(bucket, DemandBucket::Moderate);
        let percentile = detail.memory_percentile.unwrap();
        assert!(
            (percentile - 50.0).abs() < 1e-6,
            "percentile = {percentile}"
        );
    }

    #[test]
    fn composite_at_or_above_p90_sustained_is_heavy() {
        let machine = seeded_memory_baseline();
        // p95 sits above the p90 threshold, so a window sustained there is
        // unambiguously heavy.
        let p95 = machine.memory_occupancy_pct.quantile(0.95).unwrap();
        let sample = system_sample(0.0, p95);
        let recent = vec![sample; 10];
        let (bucket, detail) = demand_bucket(&recent, &machine);
        assert_eq!(bucket, DemandBucket::Heavy);
        assert!(detail.memory_percentile.unwrap() >= 90.0);
    }

    #[test]
    fn sustained_bucket_uses_the_trailing_window_majority() {
        let machine = seeded_memory_baseline();
        let p95 = machine.memory_occupancy_pct.quantile(0.95).unwrap();
        let heavy_sample = system_sample(0.0, p95);
        let light_sample = system_sample(0.0, 0.0);
        // 6 heavy samples, 4 light samples: heavy is the majority.
        let mut recent = vec![heavy_sample.clone(); 6];
        recent.extend(vec![light_sample.clone(); 4]);
        let (bucket, _) = demand_bucket(&recent, &machine);
        assert_eq!(bucket, DemandBucket::Heavy);

        // Flip it: light is now the majority.
        let mut recent = vec![light_sample; 6];
        recent.extend(vec![heavy_sample; 4]);
        let (bucket, _) = demand_bucket(&recent, &machine);
        assert_eq!(bucket, DemandBucket::Light);
    }

    #[test]
    fn fresh_baseline_degrades_percentiles_to_none_and_falls_back_to_fixed_cutoffs() {
        let machine = MachineBaseline::new(0);

        // CPU >= 80 alone triggers the heavy fallback.
        let (bucket, detail) = demand_bucket(&[system_sample(85.0, 10.0)], &machine);
        assert_eq!(bucket, DemandBucket::Heavy);
        assert_eq!(detail.cpu_percentile, None);
        assert_eq!(detail.memory_percentile, None);

        // Memory >= 90 alone also triggers the heavy fallback.
        let (bucket, _) = demand_bucket(&[system_sample(5.0, 95.0)], &machine);
        assert_eq!(bucket, DemandBucket::Heavy);

        // CPU >= 50 (but < 80) and memory < 70 triggers the moderate fallback.
        let (bucket, _) = demand_bucket(&[system_sample(60.0, 20.0)], &machine);
        assert_eq!(bucket, DemandBucket::Moderate);

        // Memory >= 70 (but < 90) also triggers the moderate fallback.
        let (bucket, _) = demand_bucket(&[system_sample(5.0, 75.0)], &machine);
        assert_eq!(bucket, DemandBucket::Moderate);

        // Below both moderate cutoffs stays light.
        let (bucket, _) = demand_bucket(&[system_sample(10.0, 20.0)], &machine);
        assert_eq!(bucket, DemandBucket::Light);
    }

    fn process_metric(pid: u32, path: String, cpu: f64) -> ProcessMetric {
        ProcessMetric {
            timestamp_ms: 0,
            pid,
            parent_pid: 4,
            name: format!("proc{pid}.exe"),
            executable_path: path,
            cpu_percent: cpu,
            working_set_bytes: 10 * 1024 * 1024,
            private_bytes: 10 * 1024 * 1024,
            handle_count: 20,
            thread_count: 4,
            read_bytes_per_sec: 0.0,
            write_bytes_per_sec: 0.0,
            total_read_bytes: 0,
            total_write_bytes: 0,
            started_at_ms: 0,
            session_id: 1,
            responsive: true,
            has_visible_window: false,
            launch_duration_ms: None,
            is_agent_candidate: false,
        }
    }

    fn incident(kind: &str, notify: bool) -> Alert {
        Alert {
            id: "id".into(),
            kind: kind.into(),
            severity: Severity::Warning,
            first_seen_ms: 1,
            last_seen_ms: 2,
            process_id: None,
            process_name: None,
            title: "t".into(),
            explanation: "e".into(),
            evidence: Vec::new(),
            recommendation: "r".into(),
            acknowledged: false,
            occurrence_count: 1,
            resolved_at_ms: None,
            archived: false,
            fingerprint: format!("{kind}:fp"),
            state: crate::models::IncidentState::Open,
            quality: AlertQuality::default(),
            notify,
            notify_generation: 0,
        }
    }

    #[test]
    fn digest_redacts_user_profile_paths() {
        let snapshot = Snapshot::default();
        let settings = Settings::default();
        let history = HistoryResponse {
            system: Vec::new(),
            processes: vec![process_metric(
                1,
                r"C:\Users\xavier\bin\codex.exe".into(),
                10.0,
            )],
        };
        let digest = build_digest(DigestSource {
            history,
            snapshot: &snapshot,
            settings: &settings,
            incidents: vec![incident("sustainedCpu", true)],
            learning: false,
            learning_percent: None,
            collector_health: "ok".into(),
        });
        let serialized = digest.to_string();
        assert!(
            serialized.contains("%USERPROFILE%"),
            "digest did not redact the profile path: {serialized}"
        );
        assert!(
            !serialized.contains("xavier"),
            "digest leaked the username: {serialized}"
        );
    }

    #[test]
    fn digest_never_exceeds_the_size_cap_under_a_pathological_source() {
        let snapshot = Snapshot::default();
        let settings = Settings::default();
        // 500 processes, each with an abnormally long path, so even after
        // capping to the top 20 by pressure score the digest still starts
        // over budget and the pop/truncate fallbacks must engage.
        let long_path = format!(r"C:\Users\xavier\{}\app.exe", "segment".repeat(200));
        let processes: Vec<ProcessMetric> = (0..500)
            .map(|pid| process_metric(pid, long_path.clone(), (pid % 100) as f64))
            .collect();
        let incidents: Vec<Alert> = (0..50)
            .map(|i| incident(&format!("kind-{i}-{}", "x".repeat(300)), i % 2 == 0))
            .collect();
        let digest = build_digest(DigestSource {
            history: HistoryResponse {
                system: Vec::new(),
                processes,
            },
            snapshot: &snapshot,
            settings: &settings,
            incidents,
            learning: false,
            learning_percent: None,
            collector_health: "x".repeat(10_000),
        });
        let size = serde_json::to_vec(&digest).unwrap().len();
        assert!(
            size <= DIGEST_MAX_BYTES,
            "digest was {size} bytes, over the {DIGEST_MAX_BYTES} cap"
        );
    }
}
