//! Durable, cross-restart baselines.
//!
//! Two kinds of learned norm live here:
//!
//! - A machine-wide [`MachineBaseline`]: streaming percentile sketches (via
//!   [`crate::stats::PercentileSketch`]) for memory occupancy, DPC rate,
//!   interrupt rate, disk latency, and process count. The time it has spent
//!   actually observing gates the notification policy's "learning period".
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

/// How much *observed* time the machine baseline needs before the
/// notification policy stops raising its floor (during learning only
/// high-confidence Critical incidents notify). See the Global Constraints in
/// the alert-calibration plan. `pub(crate)` so the one place that renders a
/// countdown (`runtime.rs`) derives it from this constant instead of
/// re-spelling "24" as a literal.
pub(crate) const LEARNING_PERIOD_MS: i64 = 24 * 3_600_000;

/// The largest amount of observed time a single [`MachineBaseline::observe`]
/// may credit. The collector samples every couple of seconds, so a gap larger
/// than a minute means the machine was *not* being observed -- it was asleep,
/// hibernating, powered off, or the service was stopped. Crediting the raw
/// gap is exactly the bug this cap exists to prevent: a machine watched for an
/// hour and then suspended overnight would wake up with nine hours of
/// "learning" behind one hour of samples, and confidence would be inflated by
/// evidence that was never collected. Capping means such a gap contributes at
/// most one ordinary sample's worth of time.
const MAX_OBSERVED_STEP_MS: i64 = 60_000;

/// Nominal collector sample interval, used only to backfill `observed_ms` for
/// baselines persisted before observed-time learning existed. The real
/// interval is configurable, so this is an estimate -- deliberately on the
/// low side, so the backfill under-credits rather than over-credits time the
/// service cannot prove it spent observing.
const NOMINAL_SAMPLE_INTERVAL_MS: i64 = 2_000;

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
/// accumulated *observed* time that gates the "learning period".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineBaseline {
    pub memory_occupancy_pct: PercentileSketch,
    pub dpc_rate: PercentileSketch,
    pub interrupt_rate: PercentileSketch,
    pub disk_latency_ms: PercentileSketch,
    pub process_count: PercentileSketch,
    /// CPU percent sketch, added for the ratings feature's demand-bucket
    /// composite (`ratings::demand_bucket`). `serde(default)` so a store
    /// persisted before this field existed loads as a fresh, empty sketch
    /// rather than failing to deserialize -- it simply starts learning from
    /// here, same as any other new signal.
    #[serde(default)]
    pub cpu_percent: PercentileSketch,
    /// Disk IO rate sketch (read + write bytes/sec), same ratings-feature
    /// motivation and upgrade behavior as `cpu_percent` above. Network
    /// throughput is deliberately excluded -- the spec's IO composite
    /// channel is disk IO ("CPU pct, memory-occupancy pct, IO pct"), and
    /// `SystemMetric::network_bytes_per_sec` already has its own separate
    /// meaning elsewhere in the codebase (interrupt/DPC root-cause
    /// analysis); conflating the two would blur what "IO" means in a
    /// stored rating.
    #[serde(default)]
    pub io_bytes_per_sec: PercentileSketch,
    /// Wall-clock instant the baseline was first created. Retained for
    /// provenance only: learning is measured in observed time, not wall age,
    /// because a machine that sleeps for nine hours has learned nothing
    /// during them.
    pub started_ms: i64,
    /// Milliseconds actually spent observing, accumulated one capped
    /// inter-sample gap at a time by [`Self::observe`]. Saturates at
    /// [`LEARNING_PERIOD_MS`]; nothing needs to know about observed time
    /// beyond a matured baseline. `serde(default)` so baselines persisted
    /// before this field existed load as zero and are then backfilled by
    /// [`Self::backfill_observed_from_sketches`].
    #[serde(default)]
    pub observed_ms: i64,
    /// Timestamp of the previous [`Self::observe`] call, used to measure the
    /// inter-sample gap. `serde(skip)` rather than persisted: across a
    /// restart the previous sample belongs to a different run, and the gap
    /// between runs is precisely the time that must *not* be credited. `None`
    /// means "no previous sample in this run", so the first observation after
    /// startup only anchors the clock and credits nothing.
    #[serde(skip)]
    last_observed_ms: Option<i64>,
}

impl MachineBaseline {
    pub fn new(now_ms: i64) -> Self {
        Self {
            memory_occupancy_pct: PercentileSketch::new(),
            dpc_rate: PercentileSketch::new(),
            interrupt_rate: PercentileSketch::new(),
            disk_latency_ms: PercentileSketch::new(),
            process_count: PercentileSketch::new(),
            cpu_percent: PercentileSketch::new(),
            io_bytes_per_sec: PercentileSketch::new(),
            started_ms: now_ms,
            observed_ms: 0,
            last_observed_ms: None,
        }
    }

    /// Feed one sample into every tracked sketch and credit the time since
    /// the previous sample -- capped at [`MAX_OBSERVED_STEP_MS`], so a
    /// suspend/resume or a stopped service adds one ordinary step rather than
    /// the whole gap.
    pub fn observe(&mut self, system: &SystemMetric, process_count: usize, now_ms: i64) {
        self.accrue_observed(now_ms);
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
        self.cpu_percent.observe(system.cpu_percent);
        self.io_bytes_per_sec
            .observe(system.disk_read_bytes_per_sec + system.disk_write_bytes_per_sec);
    }

    /// Credit the gap since the previous sample, capped, and re-anchor.
    fn accrue_observed(&mut self, now_ms: i64) {
        if let Some(previous_ms) = self.last_observed_ms {
            let gap_ms = (now_ms - previous_ms).max(0);
            self.observed_ms =
                (self.observed_ms + gap_ms.min(MAX_OBSERVED_STEP_MS)).min(LEARNING_PERIOD_MS);
        }
        self.last_observed_ms = Some(now_ms);
    }

    /// Best-effort backfill for baselines persisted before `observed_ms`
    /// existed. Those stores carry sketches full of real observations but no
    /// record of how long collecting them took, so the count of the
    /// memory-occupancy sketch (fed exactly once per sample, on every sample)
    /// times a nominal sample interval estimates the observation time that
    /// demonstrably happened. It is an estimate, not a measurement -- which is
    /// why the interval is nominal and the result is capped at one learning
    /// period -- but it beats both alternatives: zero would restart a
    /// long-learned machine's learning period, and wall age would credit time
    /// the machine spent switched off. Only applies when `observed_ms` is
    /// zero, so it never overwrites measured time.
    fn backfill_observed_from_sketches(&mut self) {
        if self.observed_ms > 0 {
            return;
        }
        let samples = self.memory_occupancy_pct.count() as i64;
        self.observed_ms = samples
            .saturating_mul(NOMINAL_SAMPLE_INTERVAL_MS)
            .min(LEARNING_PERIOD_MS);
    }

    /// True while the baseline has observed less than a full learning period,
    /// so the notification policy should demand a higher confidence floor
    /// before notifying (Global Constraints: learning period = 24 h of
    /// observation).
    pub fn is_learning(&self) -> bool {
        self.observed_ms < LEARNING_PERIOD_MS
    }

    /// Observed time as a fraction of the learning period, 0-1: the
    /// `baseline_maturity` the quality layer weighs into confidence. It lives
    /// here rather than at the call site so the 24 h period is defined once.
    pub fn maturity(&self) -> f64 {
        (self.observed_ms as f64 / LEARNING_PERIOD_MS as f64).clamp(0.0, 1.0)
    }

    /// Learning progress as a whole percent, floored so it only reads 100
    /// once the period is genuinely complete.
    pub fn learning_progress_pct(&self) -> u8 {
        ((self.maturity() * 100.0).floor() as i64).clamp(0, 100) as u8
    }

    /// Observed time still owed before the baseline matures; zero once it has.
    pub fn learning_remaining_ms(&self) -> i64 {
        (LEARNING_PERIOD_MS - self.observed_ms).max(0)
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
                if let Ok(machine) = serde_json::from_str::<MachineBaseline>(&payload) {
                    store.machine = machine;
                    // A row written before observed-time learning has no
                    // `observed_ms`; estimate it from the evidence it does
                    // carry rather than resetting the machine to unlearned.
                    store.machine.backfill_observed_from_sketches();
                }
            } else if let Some(name) = scope.strip_prefix("process:")
                && let Ok(baseline) = serde_json::from_str(&payload)
            {
                store.names.insert(name.to_string(), baseline);
            }
        }
        store
    }

    /// Rebuild a store from persisted rows, starting a fresh machine baseline
    /// at `now_ms` when nothing was persisted for the machine scope, so
    /// `started_ms` records when this machine actually began learning rather
    /// than the epoch. Maturity itself no longer rides on that timestamp --
    /// it is accumulated observed time -- but an honest `started_ms` keeps the
    /// persisted row self-describing.
    pub fn restore(rows: Vec<(String, String)>, now_ms: i64) -> Self {
        let had_machine = rows.iter().any(|(scope, _)| scope == "machine");
        let mut store = Self::from_rows(rows);
        if !had_machine {
            store.machine = MachineBaseline::new(now_ms);
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
        assert!(baseline.is_learning());
        for i in 0..100 {
            baseline.observe(
                &sample_system_metric(50.0 + (i % 10) as f64),
                400,
                i * 5_000,
            );
        }
        let p95 = baseline.memory_occupancy_pct.quantile(0.95).unwrap();
        assert!(p95 > 55.0 && p95 <= 60.0, "p95 = {p95}");
        // 99 gaps of 5 s each, all under the cap.
        assert_eq!(baseline.observed_ms, 99 * 5_000);
        assert!(baseline.is_learning());
    }

    #[test]
    fn learning_accrues_observed_time_and_a_suspend_adds_only_one_capped_step() {
        let mut baseline = MachineBaseline::new(0);
        let mut now = 0;
        // Two hours of ordinary 2 s samples.
        for _ in 0..3_600 {
            baseline.observe(&sample_system_metric(50.0), 400, now);
            now += 2_000;
        }
        let before_suspend = baseline.observed_ms;
        assert_eq!(before_suspend, 3_599 * 2_000);
        // The machine sleeps for nine hours and wakes up. Wall clock jumped;
        // observed time may not.
        now += 9 * 3_600_000;
        baseline.observe(&sample_system_metric(50.0), 400, now);
        assert_eq!(baseline.observed_ms, before_suspend + 60_000);
        assert!(
            baseline.is_learning(),
            "a machine with ~2 h of samples must still be learning after an overnight sleep"
        );
        assert!(
            baseline.maturity() < 0.1,
            "maturity = {}",
            baseline.maturity()
        );
    }

    #[test]
    fn learning_progress_is_monotone_and_floors_to_whole_percent() {
        let mut baseline = MachineBaseline::new(0);
        assert_eq!(baseline.learning_progress_pct(), 0);
        assert_eq!(baseline.learning_remaining_ms(), LEARNING_PERIOD_MS);
        let mut previous = 0;
        let mut now = 0;
        for _ in 0..4_000 {
            baseline.observe(&sample_system_metric(50.0), 400, now);
            now += 30_000;
            let progress = baseline.learning_progress_pct();
            assert!(progress >= previous, "progress went backwards: {progress}");
            assert!(progress <= 100);
            previous = progress;
        }
        // 4 000 samples 30 s apart is a day and a third of observation.
        assert_eq!(baseline.learning_progress_pct(), 100);
        assert_eq!(baseline.learning_remaining_ms(), 0);
        assert!(!baseline.is_learning());
    }

    #[test]
    fn learning_state_survives_a_restart_and_resumes_where_it_left_off() {
        let mut store = BaselineStore::new(0);
        let mut now = 0;
        // Six hours of 60 s-capped accrual: 360 samples one minute apart.
        for _ in 0..=360 {
            store.machine.observe(&sample_system_metric(50.0), 400, now);
            now += 60_000;
        }
        assert_eq!(store.machine.observed_ms, 360 * 60_000);
        // Persist, shut down, and come back a week later.
        let rows = store.to_rows();
        let restored = BaselineStore::restore(rows, now + 7 * 24 * 3_600_000);
        assert!(restored.machine.is_learning());
        assert_eq!(restored.machine.observed_ms, 360 * 60_000);
        assert_eq!(restored.machine.learning_progress_pct(), 25);
        assert_eq!(restored.machine.learning_remaining_ms(), 18 * 3_600_000);
    }

    #[test]
    fn a_store_persisted_before_observed_time_is_backfilled_from_its_sketches() {
        // A pre-migration machine row: sketches full of observations, no
        // `observed_ms` key at all.
        let mut legacy = MachineBaseline::new(0);
        for i in 0..1_000 {
            legacy.observe(&sample_system_metric(50.0), 400, i * 2_000);
        }
        let mut payload: serde_json::Value = serde_json::to_value(&legacy).unwrap();
        assert!(
            payload
                .as_object_mut()
                .unwrap()
                .remove("observed_ms")
                .is_some(),
            "field name on the wire"
        );
        let rows = vec![("machine".to_string(), payload.to_string())];
        let restored = BaselineStore::restore(rows, 0);
        // 1 000 samples x a nominal 2 s interval.
        assert_eq!(restored.machine.observed_ms, 2_000_000);
        assert!(restored.machine.is_learning());

        // An empty store has nothing to backfill from and stays at zero.
        let empty = BaselineStore::restore(
            vec![(
                "machine".to_string(),
                serde_json::to_string(&MachineBaseline::new(0)).unwrap(),
            )],
            0,
        );
        assert_eq!(empty.machine.observed_ms, 0);
        assert_eq!(empty.machine.learning_progress_pct(), 0);
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
    fn a_machine_with_nothing_persisted_starts_its_learning_period_now() {
        let now_ms = 40 * 24 * 3_600_000;
        // Nothing learned yet: no observed time, so no maturity -- and mere
        // wall-clock passage buys none of it.
        let mut fresh = BaselineStore::restore(Vec::new(), now_ms);
        assert_eq!(fresh.machine.started_ms, now_ms);
        assert!(fresh.machine.is_learning());
        assert!((fresh.machine.maturity() - 0.0).abs() < 1e-9);
        // Twelve hours of observation (60 s-capped steps) is half a period.
        let mut now = now_ms;
        for _ in 0..=720 {
            fresh.machine.observe(&sample_system_metric(50.0), 400, now);
            now += 60_000;
        }
        assert!((fresh.machine.maturity() - 0.5).abs() < 1e-9);
        assert!(fresh.machine.is_learning());
        // A persisted machine row keeps its observed time, so a restart
        // resumes the baseline rather than restarting the learning period.
        let restored = BaselineStore::restore(fresh.to_rows(), now + 30 * 3_600_000);
        assert!((restored.machine.maturity() - 0.5).abs() < 1e-9);
        assert!(restored.machine.is_learning());
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
