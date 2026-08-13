//! Durable, cross-restart baselines.
//!
//! Two kinds of learned norm live here:
//!
//! - A machine-wide [`MachineBaseline`]: streaming percentile sketches (via
//!   [`crate::stats::PercentileSketch`]) for memory occupancy, DPC rate,
//!   interrupt rate, disk latency, and process count. Its age gates the
//!   notification policy's "learning period".
//! - Per-executable-name baselines ([`ProcessNameBaseline`]), bucketed by
//!   process age, so a freshly launched process is judged against
//!   young-process norms rather than the steady-state norm of a process
//!   that has been running for hours. These reuse the same EWMA
//!   mean/variance shape as `alerting.rs`'s per-instance baselines
//!   ([`RunningStats`], relocated here so both modules can share it).
//!
//! [`BaselineStore`] owns both, plus persistence via `(scope, payload)` rows
//! that `storage::Storage::save_baselines`/`load_baselines` round-trip
//! through the `baselines` SQLite table.

use crate::models::{ProcessMetric, SystemMetric};
use crate::stats::PercentileSketch;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Machine-scope baseline age below which the notification policy floor is
/// raised (only high-confidence Critical incidents notify). See the Global
/// Constraints in the alert-calibration plan.
const LEARNING_PERIOD_MS: i64 = 24 * 3_600_000;

/// Age-bucket boundaries for per-process-name baselines: 0-5 min, 5-60 min,
/// 1 h+.
const YOUNG_BUCKET_MS: i64 = 5 * 60_000;
const WARM_BUCKET_MS: i64 = 60 * 60_000;

/// Top-N executable names retained by [`BaselineStore`]; least-observed
/// names are evicted once the cap is exceeded.
const NAME_CAP: usize = 200;

/// An exponentially weighted running mean/variance. Relocated verbatim from
/// `alerting.rs` (previously private to that module, used for per-instance
/// `ProcessBaseline`s and the collector kernel-pool baseline) so
/// `baselines.rs` can reuse the identical shape for per-name age-bucketed
/// stats. Behavior is unchanged; visibility widened to `pub` (from private)
/// and `Serialize`/`Deserialize` derives added because per-name baselines
/// are persisted -- the in-memory per-instance baselines in `alerting.rs`
/// never serialize one, so this is additive, not a behavior change.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RunningStats {
    samples: u64,
    // `pub(crate)` (rather than accessed only via `mean()`) because
    // `alerting.rs` reads `baseline.cpu.mean` directly in evidence strings;
    // keeping that field access, rather than rewriting call sites to
    // `mean()`, is what keeps this a pure relocation.
    pub(crate) mean: f64,
    variance: f64,
}

impl RunningStats {
    pub fn observe(&mut self, value: f64) {
        // An exponentially weighted baseline follows gradual workload changes without
        // retaining unbounded process history. The first 30 points warm it up.
        self.samples += 1;
        if self.samples == 1 {
            self.mean = value;
            return;
        }
        let alpha = if self.samples < 30 {
            1.0 / self.samples as f64
        } else {
            0.05
        };
        let delta = value - self.mean;
        self.mean += alpha * delta;
        self.variance = (1.0 - alpha) * (self.variance + alpha * delta * delta);
    }

    pub fn deviates(&self, value: f64, sigma: f64, minimum_delta: f64) -> bool {
        if self.samples < 15 {
            return true;
        }
        let deviation = self.variance.max(0.0).sqrt();
        value > self.mean + (sigma * deviation).max(minimum_delta)
    }

    pub fn mean(&self) -> f64 {
        self.mean
    }

    pub fn samples(&self) -> u64 {
        self.samples
    }
}

/// Machine-wide learned baseline: percentile sketches for the signals the
/// notification/quality layer compares live readings against, plus the
/// timestamp used to gate the "learning period".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineBaseline {
    pub memory_occupancy_pct: PercentileSketch,
    pub dpc_rate: PercentileSketch,
    pub interrupt_rate: PercentileSketch,
    pub disk_latency_ms: PercentileSketch,
    pub process_count: PercentileSketch,
    pub started_ms: i64,
}

impl MachineBaseline {
    pub fn new(now_ms: i64) -> Self {
        Self {
            memory_occupancy_pct: PercentileSketch::new(),
            dpc_rate: PercentileSketch::new(),
            interrupt_rate: PercentileSketch::new(),
            disk_latency_ms: PercentileSketch::new(),
            process_count: PercentileSketch::new(),
            started_ms: now_ms,
        }
    }

    /// Feed one sample into every tracked sketch. `now_ms` is accepted for
    /// interface symmetry with [`BaselineStore::observe_process`] but
    /// [`Self::age_ms`]/[`Self::is_learning`] are computed relative to
    /// `started_ms`, fixed at construction, not at observation time.
    pub fn observe(&mut self, system: &SystemMetric, process_count: usize, _now_ms: i64) {
        let occupancy_pct = if system.memory_total_bytes > 0 {
            system.memory_used_bytes as f64 / system.memory_total_bytes as f64 * 100.0
        } else {
            0.0
        };
        self.memory_occupancy_pct.observe(occupancy_pct);
        self.dpc_rate.observe(system.dpc_rate);
        self.interrupt_rate.observe(system.interrupt_rate);
        self.disk_latency_ms.observe(system.disk_latency_ms);
        self.process_count.observe(process_count as f64);
    }

    pub fn age_ms(&self, now_ms: i64) -> i64 {
        (now_ms - self.started_ms).max(0)
    }

    /// True while the machine baseline is still young enough that the
    /// notification policy should demand a higher confidence floor before
    /// notifying (Global Constraints: learning period = age < 24 h).
    pub fn is_learning(&self, now_ms: i64) -> bool {
        self.age_ms(now_ms) < LEARNING_PERIOD_MS
    }
}

/// EWMA mean/variance for one process-age bucket: CPU, working set,
/// handles, threads.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AgeBucketStats {
    pub cpu: RunningStats,
    pub working_set: RunningStats,
    pub handles: RunningStats,
    pub threads: RunningStats,
}

impl AgeBucketStats {
    fn observe(&mut self, metric: &ProcessMetric) {
        self.cpu.observe(metric.cpu_percent);
        self.working_set.observe(metric.working_set_bytes as f64);
        self.handles.observe(metric.handle_count as f64);
        self.threads.observe(metric.thread_count as f64);
    }
}

/// Per-executable-name baseline, keyed by age bucket so a young process
/// (still paging in, warming caches) isn't judged against the norm of a
/// long-lived instance of the same executable.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProcessNameBaseline {
    young: AgeBucketStats,
    warm: AgeBucketStats,
    mature: AgeBucketStats,
    observations: u64,
}

impl ProcessNameBaseline {
    fn bucket_mut(&mut self, age_ms: i64) -> &mut AgeBucketStats {
        if age_ms < YOUNG_BUCKET_MS {
            &mut self.young
        } else if age_ms < WARM_BUCKET_MS {
            &mut self.warm
        } else {
            &mut self.mature
        }
    }

    fn bucket(&self, age_ms: i64) -> &AgeBucketStats {
        if age_ms < YOUNG_BUCKET_MS {
            &self.young
        } else if age_ms < WARM_BUCKET_MS {
            &self.warm
        } else {
            &self.mature
        }
    }

    fn observe(&mut self, age_ms: i64, metric: &ProcessMetric) {
        self.observations += 1;
        self.bucket_mut(age_ms).observe(metric);
    }
}

/// Owns both baseline kinds and their persistence round-trip. `names` is
/// capped at [`NAME_CAP`] distinct executable names, LRU-evicted by
/// observation count once the cap is exceeded (spec: "top ~200 process
/// names by observation count").
#[derive(Debug, Clone)]
pub struct BaselineStore {
    pub machine: MachineBaseline,
    names: HashMap<String, ProcessNameBaseline>,
}

impl BaselineStore {
    pub fn new(now_ms: i64) -> Self {
        Self {
            machine: MachineBaseline::new(now_ms),
            names: HashMap::new(),
        }
    }

    /// Record one process observation against its per-name, age-bucketed
    /// baseline. The age bucket is derived from `now_ms - metric.started_at_ms`.
    pub fn observe_process(&mut self, metric: &ProcessMetric, now_ms: i64) {
        let age_ms = (now_ms - metric.started_at_ms).max(0);
        self.names
            .entry(metric.name.clone())
            .or_default()
            .observe(age_ms, metric);
        if self.names.len() > NAME_CAP {
            self.evict_least_observed();
        }
    }

    fn evict_least_observed(&mut self) {
        if let Some(victim) = self
            .names
            .iter()
            .min_by_key(|(_, baseline)| baseline.observations)
            .map(|(name, _)| name.clone())
        {
            self.names.remove(&victim);
        }
    }

    pub fn name_stats(&self, name: &str, age_ms: i64) -> Option<&AgeBucketStats> {
        self.names.get(name).map(|baseline| baseline.bucket(age_ms))
    }

    pub fn tracked_names(&self) -> usize {
        self.names.len()
    }

    /// Flatten into `(scope, json payload)` rows for `Storage::save_baselines`.
    /// The machine baseline always occupies the `"machine"` scope; each
    /// per-name baseline occupies `"process:{name}"`.
    pub fn to_rows(&self) -> Vec<(String, String)> {
        let mut rows = Vec::with_capacity(self.names.len() + 1);
        if let Ok(payload) = serde_json::to_string(&self.machine) {
            rows.push(("machine".to_string(), payload));
        }
        for (name, baseline) in &self.names {
            if let Ok(payload) = serde_json::to_string(baseline) {
                rows.push((format!("process:{name}"), payload));
            }
        }
        rows
    }

    /// Reconstruct a store from rows loaded via `Storage::load_baselines`.
    /// Unparseable rows are skipped rather than failing the whole load --
    /// baselines are learned norms, not durable records; losing one row is
    /// far better than losing the service on a corrupt/foreign payload.
    pub fn from_rows(rows: Vec<(String, String)>) -> Self {
        let mut store = Self::new(0);
        for (scope, payload) in rows {
            if scope == "machine" {
                if let Ok(machine) = serde_json::from_str(&payload) {
                    store.machine = machine;
                }
            } else if let Some(name) = scope.strip_prefix("process:")
                && let Ok(baseline) = serde_json::from_str(&payload)
            {
                store.names.insert(name.to_string(), baseline);
            }
        }
        store
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Storage;

    fn sample_system_metric(memory_occupancy_pct: f64) -> SystemMetric {
        SystemMetric {
            memory_used_bytes: (memory_occupancy_pct * 10_000.0) as u64,
            memory_total_bytes: 1_000_000,
            ..SystemMetric::default()
        }
    }

    fn proc_metric(name: &str, age_ms: i64, cpu: f64) -> ProcessMetric {
        ProcessMetric {
            timestamp_ms: 0,
            pid: 42,
            parent_pid: 4,
            name: name.to_string(),
            executable_path: String::new(),
            cpu_percent: cpu,
            working_set_bytes: 100 * 1024 * 1024,
            private_bytes: 100 * 1024 * 1024,
            handle_count: 20,
            thread_count: 4,
            read_bytes_per_sec: 0.0,
            write_bytes_per_sec: 0.0,
            total_read_bytes: 0,
            total_write_bytes: 0,
            // Age is derived as `now_ms - started_at_ms`; anchoring
            // started_at_ms at -age_ms keeps the bucket stable across a
            // loop that advances now_ms by a few seconds per iteration
            // (the drift is negligible next to the bucket boundaries).
            started_at_ms: -age_ms,
            session_id: 1,
            responsive: true,
            has_visible_window: false,
            launch_duration_ms: None,
            is_agent_candidate: false,
        }
    }

    #[test]
    fn machine_baseline_learns_and_reports_learning_state() {
        let mut baseline = MachineBaseline::new(0);
        assert!(baseline.is_learning(1_000));
        assert!(!baseline.is_learning(25 * 3_600_000));
        for i in 0..100 {
            baseline.observe(
                &sample_system_metric(50.0 + (i % 10) as f64),
                400,
                i * 5_000,
            );
        }
        let p95 = baseline.memory_occupancy_pct.quantile(0.95).unwrap();
        assert!(p95 > 55.0 && p95 <= 60.0, "p95 = {p95}");
    }

    #[test]
    fn process_baselines_bucket_by_age_and_survive_round_trip() {
        let mut store = BaselineStore::new(0);
        // Young process observations must not pollute the mature bucket.
        for i in 0..30 {
            store.observe_process(&proc_metric("chrome.exe", 60_000, 40.0), i * 5_000);
            store.observe_process(&proc_metric("chrome.exe", 2 * 3_600_000, 5.0), i * 5_000);
        }
        let young = store.name_stats("chrome.exe", 60_000).unwrap();
        let mature = store.name_stats("chrome.exe", 2 * 3_600_000).unwrap();
        assert!(young.cpu.mean() > 30.0);
        assert!(mature.cpu.mean() < 10.0);
        let rows = store.to_rows();
        let back = BaselineStore::from_rows(rows);
        assert!(back.name_stats("chrome.exe", 2 * 3_600_000).is_some());
    }

    #[test]
    fn the_store_caps_tracked_names_at_two_hundred() {
        let mut store = BaselineStore::new(0);
        for n in 0..250 {
            for _ in 0..(n % 5 + 1) {
                store.observe_process(&proc_metric(&format!("app{n}.exe"), 60_000, 1.0), 0);
            }
        }
        assert!(store.tracked_names() <= 200);
    }

    #[test]
    fn baselines_persist_through_sqlite() {
        let dir = std::env::temp_dir().join(format!("pcpulse-baselines-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let storage = Storage::open(&dir.join("test.db")).unwrap();
        let mut store = BaselineStore::new(0);
        store.observe_process(&proc_metric("svc.exe", 60_000, 3.0), 0);
        storage.save_baselines(&store.to_rows(), 1_000).unwrap();
        let loaded = BaselineStore::from_rows(storage.load_baselines().unwrap());
        assert!(loaded.name_stats("svc.exe", 60_000).is_some());
    }
}
