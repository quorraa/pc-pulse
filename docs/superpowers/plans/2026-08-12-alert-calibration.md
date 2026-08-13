# Alert Calibration + Hardware Inventory Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace rigid-threshold alert spam with learned per-machine baselines, incident lifecycle (fingerprints, reopen, hysteresis, cooldowns), a quality-gated notification policy, and a vendor-neutral hardware inventory in the evidence bundle.

**Architecture:** All intelligence stays in the collector service. New leaf modules (`stats.rs`, `baselines.rs`, `quality.rs`, `metrics/inventory.rs`) feed the existing `AlertEngine`, which gains persistent fingerprints, quiet-period reopen, and exit-threshold hysteresis. The tray and TUI consume additive fields. Spec: `docs/superpowers/specs/2026-08-12-alert-calibration-design.md` — read it once before your task; it is the authority on intent.

**Tech Stack:** Rust; rusqlite (existing), WMI via raw `windows`-crate COM (existing `WmiThermal` pattern), serde camelCase additive fields.

## Global Constraints

- The collector stays network-free; every new probe is a local WMI/Win32 read.
- All new serde fields are additive camelCase with defaults on BOTH crates; `PROTOCOL_VERSION` stays 1. Pre-upgrade JSON must deserialize to today's behavior (`notify = true`, `notify_generation = 0`, empty fingerprint, state `open`, default quality).
- Missing hardware telemetry never implies missing hardware; every inventory group is `present | unavailable{detail}`, never fabricated.
- Raw telemetry, evidence, and diagnostics are always recorded even when notification is suppressed.
- Constants from the spec, verbatim: quiet period 6 h; exit threshold = 85% of entry; collector tolerance band ×1.15, 10-min sustained path, Critical at ≥ 2× ceiling; growth persistence 30 min; DPC repeatable-verdict ≥ 2 captures or learned-p95 ≥ 15 min + corroboration; handle/thread window 30 min; learning period = machine baseline age < 24 h; notify floors: severity ≥ Warning && persistence ≥ 0.5 && confidence ≥ 0.5 (Critical: confidence ≥ 0.35; learning: Critical && confidence ≥ 0.6); per-name baseline LRU cap 200; baseline persist cadence 5 min. No new TUNE settings.
- Gate for every task: `cargo test --workspace`, `cargo clippy --workspace --all-targets`, fmt scoped to your own hunks only (`cargo fmt -p <crate>` then `git restore` unrelated drift — the repo has known rustfmt churn on ~15 untouched files).
- Commits: plain messages, NO co-author trailer. Service tests live in-module (`#[cfg(test)]`), matching `alerting.rs`.
- Version stays 1.17.1; the release bump is outside this plan.

---

### Task 1: Statistics primitives (`stats.rs`)

**Files:**
- Create: `src/PcPulse.Service/src/stats.rs`
- Modify: `src/PcPulse.Service/src/lib.rs` (add `pub mod stats;`)
- Modify: `src/PcPulse.Service/src/alerting.rs:560-604` (extract the three-segment trend logic to the shared utility; keep the collector-specific wrapper calling it)

**Interfaces:**
- Consumes: nothing (leaf).
- Produces:
  - `pub struct PercentileSketch` — P²-style streaming estimator. `pub fn new() -> Self`, `pub fn observe(&mut self, value: f64)`, `pub fn quantile(&self, q: f64) -> Option<f64>` (None until ≥ 5 observations; q ∈ {0.5, 0.95, 0.99} are the supported markers), `pub fn count(&self) -> u64`. Serde `Serialize + Deserialize` (persisted in baseline payloads).
  - `pub struct TrendPoint { pub at_ms: i64, pub value: f64 }`
  - `pub enum TrendShape { Monotonic { total_growth: f64 }, Plateau, Returning, Inconclusive }`
  - `pub fn classify_trend(points: &[TrendPoint], min_span_ms: i64, min_step: f64) -> TrendShape` — generalization of `collector_working_set_growth`'s three-segment test: split the span into thirds by time; `Monotonic` when each successive third's mean exceeds the prior by ≥ `min_step` ; `Plateau` when the last third's mean is within ±`min_step` of the middle third after earlier growth; `Returning` when the last third's mean has fallen back to within `min_step` of the first third; `Inconclusive` when span < `min_span_ms` or points < 6.

- [ ] **Step 1: Write the failing tests** (`#[cfg(test)]` in `stats.rs`)

```rust
use super::*;

fn series(values: &[f64]) -> Vec<TrendPoint> {
    values
        .iter()
        .enumerate()
        .map(|(i, v)| TrendPoint { at_ms: i as i64 * 60_000, value: *v })
        .collect()
}

#[test]
fn sketch_tracks_quantiles_of_a_known_distribution() {
    let mut sketch = PercentileSketch::new();
    for i in 1..=1000 {
        sketch.observe(f64::from(i));
    }
    let p50 = sketch.quantile(0.5).unwrap();
    let p95 = sketch.quantile(0.95).unwrap();
    let p99 = sketch.quantile(0.99).unwrap();
    assert!((p50 - 500.0).abs() < 25.0, "p50 = {p50}");
    assert!((p95 - 950.0).abs() < 25.0, "p95 = {p95}");
    assert!((p99 - 990.0).abs() < 25.0, "p99 = {p99}");
}

#[test]
fn sketch_has_no_quantiles_before_five_observations() {
    let mut sketch = PercentileSketch::new();
    for i in 0..4 {
        sketch.observe(f64::from(i));
        assert!(sketch.quantile(0.95).is_none());
    }
    sketch.observe(4.0);
    assert!(sketch.quantile(0.95).is_some());
}

#[test]
fn sketch_round_trips_through_serde() {
    let mut sketch = PercentileSketch::new();
    for i in 1..=100 {
        sketch.observe(f64::from(i));
    }
    let json = serde_json::to_string(&sketch).unwrap();
    let back: PercentileSketch = serde_json::from_str(&json).unwrap();
    assert_eq!(back.count(), 100);
    assert!((back.quantile(0.5).unwrap() - sketch.quantile(0.5).unwrap()).abs() < 1e-9);
}

#[test]
fn monotonic_growth_is_classified_as_monotonic() {
    let shape = classify_trend(&series(&[10.0, 12.0, 15.0, 18.0, 22.0, 27.0, 33.0, 40.0, 48.0]), 4 * 60_000, 2.0);
    assert!(matches!(shape, TrendShape::Monotonic { total_growth } if total_growth > 20.0));
}

#[test]
fn burst_then_flat_is_a_plateau_and_burst_then_release_is_returning() {
    let plateau = classify_trend(&series(&[10.0, 11.0, 30.0, 31.0, 30.5, 30.8, 31.0, 30.6, 30.9]), 4 * 60_000, 2.0);
    assert!(matches!(plateau, TrendShape::Plateau));
    let returning = classify_trend(&series(&[10.0, 11.0, 30.0, 31.0, 28.0, 20.0, 14.0, 11.0, 10.5]), 4 * 60_000, 2.0);
    assert!(matches!(returning, TrendShape::Returning));
}

#[test]
fn short_series_are_inconclusive() {
    assert!(matches!(classify_trend(&series(&[1.0, 2.0, 3.0]), 4 * 60_000, 1.0), TrendShape::Inconclusive));
}
```

- [ ] **Step 2: Run, verify failure** — `cargo test -p pcpulse-service stats` → compile error (module missing).
- [ ] **Step 3: Implement** `PercentileSketch` (classic P² with 5 markers per tracked quantile, or a documented simpler variant meeting the test tolerances) and `classify_trend`. Then refactor `collector_working_set_growth` (alerting.rs:560-604) to call `classify_trend` — its existing tests (`alerting.rs:944-960` region) must stay green unmodified.
- [ ] **Step 4: Run** `cargo test -p pcpulse-service` → all green including untouched collector-growth tests.
- [ ] **Step 5: Gate + commit** — `git commit -m "Add streaming percentile sketch and shared trend classification"`

---

### Task 2: Durable baseline store (`baselines.rs`)

**Files:**
- Create: `src/PcPulse.Service/src/baselines.rs`
- Modify: `src/PcPulse.Service/src/lib.rs` (`pub mod baselines;`)
- Modify: `src/PcPulse.Service/src/storage.rs` (new table + load/save helpers)

**Interfaces:**
- Consumes: `stats::PercentileSketch` (Task 1); `models::{SystemMetric, ProcessMetric}`.
- Produces:
  - `pub struct MachineBaseline { pub memory_occupancy_pct: PercentileSketch, pub dpc_rate: PercentileSketch, pub interrupt_rate: PercentileSketch, pub disk_latency_ms: PercentileSketch, pub process_count: PercentileSketch, pub started_ms: i64 }` with `pub fn observe(&mut self, system: &SystemMetric, process_count: usize, now_ms: i64)`, `pub fn age_ms(&self, now_ms: i64) -> i64`, `pub fn is_learning(&self, now_ms: i64) -> bool` (age < 24 h).
  - `pub struct ProcessNameBaseline` — per executable name, three age buckets (`0-5 min`, `5-60 min`, `1 h+`), each an EWMA mean/variance set for cpu, working_set, handles, threads (reuse the `RunningStats` shape — move it from `alerting.rs:16-49` into `baselines.rs` and re-export or import in alerting).
  - `pub struct BaselineStore { pub machine: MachineBaseline, names: HashMap<String, ProcessNameBaseline>, ... }` with `pub fn observe_process(&mut self, metric: &ProcessMetric, now_ms: i64)` (age bucket derived from `now_ms - metric.started_at_ms`), `pub fn name_stats(&self, name: &str, age_ms: i64) -> Option<&AgeBucketStats>`, LRU cap 200 names by observation count, `pub fn to_rows(&self) -> Vec<(String, String)>` / `pub fn from_rows(rows: Vec<(String, String)>) -> Self` for persistence (scope key + JSON payload).
  - storage.rs: `pub fn save_baselines(&self, rows: &[(String, String)], now_ms: i64) -> Result<()>` (upsert), `pub fn load_baselines(&self) -> Result<Vec<(String, String)>>`; table `baselines (scope TEXT PRIMARY KEY, payload TEXT NOT NULL, updated_ms INTEGER NOT NULL)` created in the schema block (`storage.rs:22-76` region) with the same tolerant-migration style as the `archived` column.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn machine_baseline_learns_and_reports_learning_state() {
    let mut baseline = MachineBaseline::new(0);
    assert!(baseline.is_learning(1_000));
    assert!(!baseline.is_learning(25 * 3_600_000));
    for i in 0..100 {
        baseline.observe(&sample_system_metric(50.0 + f64::from(i % 10)), 400, i * 5_000);
    }
    let p95 = baseline.memory_occupancy_pct.quantile(0.95).unwrap();
    assert!(p95 > 55.0 && p95 <= 60.0, "p95 = {p95}");
}

#[test]
fn process_baselines_bucket_by_age_and_survive_round_trip() {
    let mut store = BaselineStore::new(0);
    // Young process observations must not pollute the mature bucket.
    for i in 0..30 {
        store.observe_process(&proc_metric("chrome.exe", /*age*/ 60_000, /*cpu*/ 40.0), i * 5_000);
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
```

(Adapt `sample_system_metric`/`proc_metric` helpers to the real struct fields — read `models.rs` first; `Storage::open` name per the actual constructor in storage.rs.)

- [ ] **Step 2: Run, verify failure.**
- [ ] **Step 3: Implement.** Moving `RunningStats` must keep `alerting.rs` compiling with zero behavior change (pure relocation + import).
- [ ] **Step 4: Run** full `cargo test -p pcpulse-service` — green.
- [ ] **Step 5: Gate + commit** — `git commit -m "Add durable machine and per-process-name baselines"`

---

### Task 3: Alert model extensions

**Files:**
- Modify: `src/PcPulse.Service/src/models.rs:147-169` (Alert struct) and nearby
- Test: in-module tests in `models.rs`

**Interfaces:**
- Consumes: nothing.
- Produces (all additive, camelCase, serde-defaulted — old JSON must parse):
  - `pub enum IncidentState { Open, Reopened, Resolved }` (serde `rename_all = "camelCase"`, default `Open`).
  - On `Alert`: `pub fingerprint: String` (default empty), `pub state: IncidentState` (default Open), `pub quality: AlertQuality` (default), `pub notify: bool` (default **true** — pre-upgrade records behave like today), `pub notify_generation: u32` (default 0).
  - `pub struct AlertQuality { pub confidence: f64, pub persistence: f64, pub corroboration: f64, pub user_impact: f64, pub novelty: f64 }` — `Default` = all 1.0 (an old record is fully trusted; the engine overwrites for live incidents).

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn pre_upgrade_alert_json_gains_compatible_defaults() {
    // A verbatim pre-upgrade payload shape (no fingerprint/state/quality/notify).
    let old = r#"{"id":"abc","kind":"sustainedCpu","severity":"warning",
        "firstSeenMs":1,"lastSeenMs":2,"processId":10,"processName":"x.exe",
        "title":"t","explanation":"e","evidence":[],"recommendation":"r",
        "acknowledged":false,"occurrenceCount":3,"resolvedAtMs":null}"#;
    let alert: Alert = serde_json::from_str(old).unwrap();
    assert!(alert.notify, "old records must behave like today");
    assert_eq!(alert.notify_generation, 0);
    assert_eq!(alert.fingerprint, "");
    assert!(matches!(alert.state, IncidentState::Open));
    assert!((alert.quality.confidence - 1.0).abs() < f64::EPSILON);
}

#[test]
fn new_fields_serialize_as_camel_case() {
    let alert = Alert { fingerprint: "dpcInterrupt".into(), notify: false, notify_generation: 2, ..test_alert() };
    let json = serde_json::to_string(&alert).unwrap();
    assert!(json.contains("\"fingerprint\":\"dpcInterrupt\""));
    assert!(json.contains("\"notifyGeneration\":2"));
    assert!(json.contains("\"state\":\"open\""));
}
```

(Use/extend whatever `test_alert()`-style constructor the models tests already have; create a minimal one if none exists. Check the exact severity serialization — read the existing `Severity` serde attrs first.)

- [ ] **Step 2: Run, verify failure.** Step 3: implement. Step 4: full workspace test — the TUI compiles against the same struct; fix any TUI construction sites with `..Default::default()`-style spreads only if Alert derives Default, otherwise update the few literal constructors (grep `Alert {` in both crates).
- [ ] **Step 5: Gate + commit** — `git commit -m "Extend Alert with incident state, fingerprint, and quality fields"`

---

### Task 4: Hardware inventory

**Files:**
- Create: `src/PcPulse.Service/src/metrics/inventory.rs`
- Modify: `src/PcPulse.Service/src/metrics/mod.rs` (module + construct-once wiring per its `MetricCollector::new` pattern at metrics/mod.rs:24-33)
- Modify: `src/PcPulse.Service/src/models.rs:196-218` (`HardwareMetrics.inventory: Option<HardwareInventory>`)
- Modify: `src/PcPulse.Service/src/metrics/hardware.rs` only if the sampler is the cleaner attach point — implementer's call; state the choice in the report.

**Interfaces:**
- Consumes: the `WmiThermal` COM pattern (hardware.rs:203-309) as reference; models.
- Produces:
  - `pub struct InventoryGroup<T> { pub value: Option<T>, pub detail: String }` — `detail` explains absence or qualifies presence; a successful group has `detail: ""`.
  - `pub struct HardwareInventory { pub cpu: InventoryGroup<CpuInventory>, pub system: InventoryGroup<SystemInventory>, pub bios: InventoryGroup<BiosInventory>, pub memory: InventoryGroup<MemoryInventory>, pub storage: InventoryGroup<Vec<StorageDevice>>, pub gpus: InventoryGroup<Vec<GpuInventory>>, pub collected_at_ms: i64 }`
  - `CpuInventory { manufacturer, brand, physical_cores: u32, logical_processors: u32, base_clock_mhz: Option<u32>, max_clock_mhz: Option<u32> }`; `SystemInventory { manufacturer, model }`; `BiosInventory { version, release_date: Option<String> }`; `MemoryInventory { installed_bytes: u64, module_count: u32, speed_mts: Option<u32> }`; `StorageDevice { model, size_bytes: u64, bus_type: String, media_type: String }` (media_type ∈ "ssd"|"hdd"|"unknown"); `GpuInventory { name, vendor, driver_version: Option<String>, vram_bytes: Option<u64> }` — all camelCase serde.
  - `pub trait InventoryProbe { fn collect(&self) -> HardwareInventory; }` + `pub struct WmiInventoryProbe` (real, connect-once to `root\CIMV2`; storage prefers `root\microsoft\windows\storage` `MSFT_PhysicalDisk`, falls back to `Win32_DiskDrive` with media_type "unknown"). Probe runs once at collector construction on the startup path with one bounded retry; result cached for the process lifetime; a daily re-probe refresh is a simple timestamp check in `collect()`.

- [ ] **Step 1: Write the failing tests** (stub probe; the WMI probe itself is a thin shell verified in the live smoke)

```rust
struct LenovoStub;
impl InventoryProbe for LenovoStub {
    fn collect(&self) -> HardwareInventory {
        HardwareInventory {
            cpu: InventoryGroup::present(CpuInventory {
                manufacturer: "AuthenticAMD".into(),
                brand: "AMD Ryzen 5 PRO 5650GE with Radeon Graphics".into(),
                physical_cores: 6, logical_processors: 12,
                base_clock_mhz: Some(3400), max_clock_mhz: Some(4400),
            }),
            gpus: InventoryGroup::present(vec![GpuInventory {
                name: "AMD Radeon(TM) Graphics".into(), vendor: "Advanced Micro Devices, Inc.".into(),
                driver_version: Some("31.0.21912.14".into()), vram_bytes: None,
            }]),
            memory: InventoryGroup::present(MemoryInventory { installed_bytes: 16 * 1024 * 1024 * 1024, module_count: 2, speed_mts: Some(3200) }),
            storage: InventoryGroup::unavailable("WMI storage namespace query failed: access denied"),
            ..HardwareInventory::empty(0)
        }
    }
}

#[test]
fn inventory_reports_hardware_independent_of_telemetry() {
    // The Lenovo field case: Radeon iGPU EXISTS (inventory) while NVML
    // telemetry is unavailable (gauges). The two must never be conflated.
    let inventory = LenovoStub.collect();
    let gpus = inventory.gpus.value.as_ref().unwrap();
    assert_eq!(gpus.len(), 1);
    assert!(gpus[0].name.contains("Radeon"));
    // Unavailable group keeps its reason and fabricates nothing.
    assert!(inventory.storage.value.is_none());
    assert!(inventory.storage.detail.contains("access denied"));
}

#[test]
fn inventory_rides_the_snapshot_into_the_agent_context() {
    // Attach a stub inventory to HardwareMetrics, build a Snapshot the way
    // runtime does, and assert the agent-context serialization carries it.
    // (Follow analysis.rs's build_agent_context test setup if one exists;
    // otherwise serialize the Snapshot directly and check the JSON path
    // hardware.inventory.cpu.value.brand.)
}
```

(Fill the second test concretely after reading how existing snapshot tests construct fixtures — `models.rs`/`analysis.rs` tests show the pattern. `InventoryGroup::present/unavailable/empty` are small constructors you add.)

- [ ] **Step 2: Run, verify failure.** Step 3: implement structs + stub path + WMI probe (thin, honest per-group error capture; follow `WmiThermal`'s COM init and `ExecQuery` shape; each group's query failure fills `unavailable{detail}` and continues). Step 4: workspace green.
- [ ] **Step 5: Gate + commit** — `git commit -m "Add vendor-neutral hardware inventory to the evidence bundle"`

---

### Task 5: Incident lifecycle in AlertEngine

**Files:**
- Modify: `src/PcPulse.Service/src/alerting.rs` (Candidate gains entry/exit values; engine gains fingerprint persistence, reopen memory, hysteresis)
- Modify: `src/PcPulse.Service/src/storage.rs` (query recent resolved alerts by fingerprint: `pub fn recent_resolved_by_fingerprint(&self, fingerprint: &str, since_ms: i64) -> Result<Option<Alert>>`)
- Modify: `src/PcPulse.Service/src/runtime.rs:322` region (startup force-resolve keeps fingerprints reopen-eligible; pass storage handle into the engine or pre-load reopen memory)

**Interfaces:**
- Consumes: Task 3 fields; storage.
- Produces:
  - `Candidate` gains `pub exit_ratio: f64` (default 0.85) and the engine tracks per-key `below_exit_since: Option<i64>`: an active incident resolves only when its candidate has been absent AND (where the detector supplies values) below `entry × exit_ratio` for ≥ one full sustained window (`required_samples × sample_interval`). Detectors that are purely event-shaped (crash dumps, slow launch) keep absence-resolution.
  - `QUIET_PERIOD_MS: i64 = 6 * 3_600_000`. On resolution: `resolved_memory: HashMap<String, (String /*id*/, i64 /*resolved_at*/, u32 /*occurrences*/, u32 /*notify_generation*/)>`. On a key re-entering within the quiet period: resurrect the same id, `state: Reopened`, `occurrence_count` continues from memory, `first_seen_ms` preserved from the stored record.
  - Engine constructor takes the reopen memory pre-loaded from storage (`Vec<Alert>` of recently resolved) so restarts reattach: `AlertEngine::new(reopen_seed: Vec<Alert>)` (adapt the real constructor signature).
  - Every alert now carries `fingerprint` = the engine key.

- [ ] **Step 1: Write the failing tests** (extend the existing alerting test module; use its established fixtures — read tests at alerting.rs:842+ first and mirror their builder style)

```rust
#[test]
fn a_refire_inside_the_quiet_period_reopens_the_same_incident() {
    // Drive a detector to fire, resolve it, then breach again 10 minutes
    // later: same id, state == Reopened, occurrence_count continued,
    // first_seen_ms preserved.
}

#[test]
fn a_refire_after_the_quiet_period_is_a_new_incident() {
    // Same flow but the second breach comes 7 hours later: new id,
    // state == Open, occurrence_count restarts.
}

#[test]
fn oscillation_around_the_entry_threshold_does_not_flap() {
    // Value alternates 1.02x / 0.95x of entry each sample (above exit
    // ratio 0.85): the incident must stay open the whole time — one id,
    // zero resolutions.
}

#[test]
fn resolution_requires_the_exit_threshold_and_hold_window() {
    // Value drops to 0.80x entry (below exit) and stays: incident
    // resolves only after required_samples further evaluations, not on
    // the first quiet sample.
}

#[test]
fn restart_reattaches_a_persisting_condition_to_its_incident() {
    // Build engine A, fire+persist an alert, resolve via force-resolve
    // (restart semantics), build engine B seeded with the stored resolved
    // alerts, breach again within the quiet period: engine B reopens the
    // stored id rather than minting a new one.
}
```

(These are behavioral skeletons — write them as REAL tests against the actual engine API before implementing; the existing tests show how to feed synthetic `ProcessMetric`/`SystemMetric` cycles. Every assertion named in a comment above must appear as a real assertion.)

- [ ] **Step 2: Run, verify failure.** Step 3: implement engine changes. Step 4: full service suite green — existing detector tests must pass unmodified except where they assert id-freshness across resolution (update those to the new reopen semantics deliberately, one by one, explaining each in the report).
- [ ] **Step 5: Gate + commit** — `git commit -m "Give alerts a persistent fingerprint, reopen memory, and hysteresis"`

---

### Task 6: Quality layer and notification policy

**Files:**
- Create: `src/PcPulse.Service/src/quality.rs`
- Modify: `src/PcPulse.Service/src/lib.rs`; `src/PcPulse.Service/src/alerting.rs` (engine calls the scorer each evaluation); `src/PcPulse.Service/src/runtime.rs` (load `BaselineStore` at startup, feed observations each sample, persist every 5 minutes on the existing maintenance cadence — see the prune timer at runtime.rs:461-464 for the pattern — and on clean shutdown; pass learning state into evaluation)
- Modify: `src/PcPulse.Tui/src/notifier.rs:212-224` (tray filter: unseen `(id, notify_generation)`, `notify == true`)

**Interfaces:**
- Consumes: Tasks 1-3, 5; `BaselineStore` (Task 2).
- Produces:
  - `pub struct QualityInputs<'a> { pub alert: &'a Alert, pub sustained_window_ms: i64, pub breach_duration_ms: i64, pub baseline_maturity: f64 /*0-1 from machine baseline age/24h*/, pub attribution_stable: Option<bool>, pub corroborating_signals: u32, pub user_impact_signals: u32, pub notified_before: bool, pub last_notified_ms: Option<i64> }`
  - `pub fn score(inputs: &QualityInputs) -> AlertQuality` — persistence = `(breach_duration / sustained_window).clamp(0,3)/3`; confidence = weighted mean of baseline_maturity, sample depth, attribution stability (None ⇒ neutral 0.5); corroboration/user_impact = `1 - 0.5^signals`; novelty = 1.0 first time, decaying `0.5^(occurrences_since_last_notify)`.
  - `pub struct NotifyDecision { pub notify: bool, pub bump_generation: bool }`
  - `pub fn decide(alert: &Alert, quality: &AlertQuality, learning: bool, previous: Option<&Alert>) -> NotifyDecision` implementing the spec floors verbatim: notify iff `severity >= Warning && persistence >= 0.5 && confidence >= 0.5` (Critical: `confidence >= 0.35`); learning ⇒ only `Critical && confidence >= 0.6`; renotify (bump_generation on an already-notified incident) only on severity escalation, materially-changed-fingerprint flag (detector-supplied, Task 8), or reopen after a full quiet period.
  - Engine wiring: after candidate evaluation, each active alert gets `quality` + `notify` + conditional `notify_generation` bump. Suppressed alerts still flow to storage/snapshot unchanged.
  - Tray: `poll_alerts` filter becomes `!alert.acknowledged && !alert.archived && alert.notify && seen.insert((alert.id.clone(), alert.notify_generation))`-style — a generation bump re-pops, nothing else does.

- [ ] **Step 1: Write the failing tests** — in `quality.rs`: score monotonicity (more breach duration ⇒ persistence rises to 1.0 at 3× window; two corroborating signals ⇒ 0.75), each decide() floor from the Global Constraints verbatim (six cases: warning-passing, warning-low-confidence-suppressed, critical-low-confidence-passing-at-0.35, learning-warning-suppressed, learning-critical-0.6-passing, renotify-only-on-escalation). In `notifier`-side: a tray-filter unit test if the filter is extractable; otherwise cover via an app-level test asserting the serialized alert's notify/generation fields drive visibility (state the choice).
- [ ] **Step 2: Run, verify failure.** Step 3: implement + wire. Step 4: workspace green.
- [ ] **Step 5: Gate + commit** — `git commit -m "Gate notifications behind incident quality scores"`

---

### Task 7: Collector budget calibration

**Files:**
- Modify: `src/PcPulse.Service/src/alerting.rs:316-394` (collectorBudget + collectorGrowth)

**Interfaces:**
- Consumes: Tasks 1, 5, 6.
- Produces: banded severity for `collectorBudget`: value in `[ceiling, ceiling×1.15)` ⇒ Info candidate (history-only by policy; persistence never reaches Warning floors); `[ceiling×1.15, 2×ceiling)` sustained ⇒ Warning; `≥ 2×ceiling` sustained ⇒ Critical; plus the alternate 10-minute continuous path at bare ceiling ⇒ Warning. Applies to CPU, the 25 MB working-set budget, and the 600-handle budget uniformly. `collectorGrowth` uses `classify_trend` over a 30-minute window: `Monotonic` sustained ⇒ Warning; `Plateau`/`Returning` ⇒ downgrade to Info and auto-resolve eligibility.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn a_hairline_ceiling_crossing_is_informational_never_critical() {
    // The Lenovo field case: ceiling 0.75%, observed 0.769% (in-band).
    // Sustained for many samples: alert exists at Info, notify == false,
    // severity never reaches Critical; telemetry recorded (alert present
    // in evaluation output).
}

#[test]
fn the_band_and_double_ceiling_set_severity() {
    // 0.9% vs 0.75 ceiling (>=1.15x) sustained => Warning.
    // 1.6% vs 0.75 ceiling (>=2x) sustained => Critical.
}

#[test]
fn working_set_oscillation_in_the_steady_range_stays_informational() {
    // WS bouncing 11-16 MB for an hour: at most one incident, Info,
    // notify == false, no reopen churn (single id throughout).
}

#[test]
fn a_thirty_minute_monotonic_climb_upgrades_to_warning_once() {
    // Feed a genuine monotonic WS climb over 30+ min: Warning, notify
    // true exactly once (generation bumps once).
}
```

(Write as real tests with the engine fixtures; every comment line becomes an assertion.)

- [ ] **Steps 2-4:** fail → implement → workspace green (existing collector tests at alerting.rs:842-960 updated only where banding legitimately changes expectations — justify each in the report).
- [ ] **Step 5: Gate + commit** — `git commit -m "Calibrate collector budget alerts with tolerance bands"`

---

### Task 8: DPC/interrupt notification gating

**Files:**
- Modify: `src/PcPulse.Service/src/metrics/interrupts.rs` (expose verdict stability to the engine)
- Modify: `src/PcPulse.Service/src/alerting.rs:448-465` + engine wiring (quality inputs for dpcInterrupt)

**Interfaces:**
- Consumes: the existing verdict machinery (`assess_confidence` interrupts.rs:362-384, `modal_candidate` interrupts.rs:401); machine baseline p95 (Task 2); quality layer (Task 6).
- Produces:
  - `InterruptEngine` exposes `pub fn verdict_state(&self) -> VerdictState` where `pub enum VerdictState { NoCapture, SingleCapture, Repeatable { driver_family: String }, ChangedConfidently { from: String, to: String } }` — `Repeatable` requires the same modal driver family across ≥ 2 successful captures; `ChangedConfidently` only when both old and new verdicts passed the existing confidence gate.
  - Engine: the `dpcInterrupt` candidate's quality inputs set `attribution_stable = Some(matches!(state, Repeatable{..}))`; notification path per spec: `Repeatable` OR (rate ≥ machine p95 for ≥ 15 min AND (corroboration signals ≥ 1 OR user_impact ≥ 0.3)). `ChangedConfidently` sets the materially-changed-fingerprint flag (renotify same id). Title stays `"High DPC or interrupt activity"` regardless of attribution.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn alternating_low_confidence_attribution_is_one_silent_incident() {
    // Simulate captures whose modal candidate flips storage->graphics->
    // network without ever passing the confidence gate: one incident id,
    // stable title, notify == false throughout, evidence still updates.
}

#[test]
fn a_repeatable_driver_family_verdict_notifies_once() {
    // Two successful captures agreeing on the same family: notify flips
    // true, generation bumps once, further agreeing captures do not
    // re-pop.
}

#[test]
fn sustained_p95_with_corroboration_notifies_without_attribution() {
    // No usable captures, but rate above the learned p95 for >= 15 min
    // with correlated disk activity: notify == true.
}

#[test]
fn a_confident_verdict_change_renotifies_the_same_incident() {
    // Repeatable(storage) then later Repeatable(graphics), both confident:
    // same id, generation bumps, state stays open.
}
```

(The interrupts engine has extensive existing tests with stub sessions — reuse its harness (`InterruptEngine<S>` is generic over the session) rather than fighting real ETW. If driving the full engine is disproportionate, test `VerdictState` derivation against recorded capture summaries plus the alerting-side gating separately — but the four behaviors above must each end as real assertions somewhere.)

- [ ] **Steps 2-4:** fail → implement → green.
- [ ] **Step 5: Gate + commit** — `git commit -m "Notify DPC incidents only on repeatable or corroborated evidence"`

---

### Task 9: Handle/thread growth discrimination

**Files:**
- Modify: `src/PcPulse.Service/src/alerting.rs:197-228` (handleGrowth/threadGrowth candidates)

**Interfaces:**
- Consumes: `classify_trend` (Task 1), per-name age-bucketed baselines (Task 2), lifecycle (Task 5), quality (Task 6).
- Produces: entry requires all of — raw delta ≥ setting (unchanged), `classify_trend` over a 30-minute point window = `Monotonic`, and deviation from the process's age-bucketed per-name baseline (where ≥ 15 observations exist; fewer ⇒ baseline gate passes open, matching the existing `deviates()` young-process convention). `Plateau`/`Returning` on an active incident ⇒ silent auto-resolve (notify stays false on the resolution transition); occurrences accumulate on the single incident.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn burst_and_release_never_notifies_but_is_recorded() {
    // The field case: +800 handles over 10 min, plateau, release back.
    // Incident opens (history), notify == false, then auto-resolves
    // silently; occurrence_count reflects the excursion; the alert
    // exists in the evaluation output the whole time.
}

#[test]
fn a_monotonic_leak_against_baseline_notifies_once_and_updates_thereafter() {
    // 30+ min monotonic climb deviating from a mature per-name baseline:
    // notify true once; continued growth updates occurrence_count and
    // last_seen without re-popping (generation stable).
}

#[test]
fn a_known_bursty_process_is_judged_against_its_own_norm() {
    // Train the per-name baseline with regular 500-handle bursts; a new
    // identical burst does NOT open an incident (baseline gate), while
    // the same burst on an unknown name still passes the gate.
}
```

- [ ] **Steps 2-4:** fail → implement → green (existing handle/thread tests updated deliberately where the new gates change expectations; justify each).
- [ ] **Step 5: Gate + commit** — `git commit -m "Distinguish handle and thread leaks from burst-and-release"`

---

### Task 10: TUI incidents surface

**Files:**
- Modify: `src/PcPulse.Tui/src/ui.rs` (Incidents page rows + detail pane; statusline learning tag)
- Modify: `src/PcPulse.Tui/src/app.rs` (expose learning state from snapshot if the service publishes it — add `learning: bool` to `Snapshot` (service models, serde default false) in this task; runtime sets it from the machine baseline)

**Interfaces:**
- Consumes: Task 3 fields on Alert; `Snapshot.learning` (added here).
- Produces: rows show `×N` when `occurrence_count > 1`, last-seen age (existing `format::age`), confidence marker `●○○`/`●●○`/`●●●` (thresholds 0.34/0.67); history-only rows (`notify == false`) render muted with a `history` tag; detail pane lists the five scores, state, first-seen/last-reopened/notification count; statusline shows `learning your machine (Nh left)` while `snapshot.learning`.

- [ ] **Step 1: Write the failing tests** — TestBackend renders (mirror the existing incidents-page tests in ui.rs): (a) a `notify:false` alert renders with the history tag and muted style while a `notify:true` alert keeps standard style; (b) `×12` appears for occurrence_count 12 and the confidence marker matches the score; (c) the statusline carries the learning text when `snapshot.learning`; (d) detail pane shows all five scores formatted.
- [ ] **Steps 2-4:** fail → implement → workspace green (gallery/demo determinism tests must remain untouched — check they don't assert Incidents-row layout that changed; if they do, regenerate expectations deliberately and say so).
- [ ] **Step 5: Gate + commit** — `git commit -m "Surface incident lifecycle and quality on the Incidents page"`

---

### Task 11: Protocol docs, README, final verification

**Files:**
- Modify: `docs/protocol.md` (new Alert fields, IncidentState semantics, Snapshot.learning, hardware inventory)
- Modify: `README.md` (alerting philosophy paragraph + inventory mention, house voice)

- [ ] **Step 1:** Write both doc updates — protocol.md documents every additive field with its default and the reopen/notify-generation semantics; README explains baselines/learning period/notification policy in plain language mirroring TUNE descriptions.
- [ ] **Step 2:** Full gate: `cargo test --workspace`, `cargo clippy --workspace --all-targets`.
- [ ] **Step 3:** Live smoke on this machine (controller + user): rebuild service+TUI, reinstall or restart service from the build, confirm — inventory appears in `PcPulse.exe snapshot` JSON (cpu brand, this machine's NVIDIA-less/AMD-less profile as applicable, explicit unavailable details), `agent-context` carries it, Incidents page renders quality markers, statusline shows learning on the fresh baseline store, and no alert balloon storm appears on a healthy machine. The Lenovo scenarios are covered by the suite; nothing here can reproduce them live.
- [ ] **Step 4: Commit** — `git commit -m "Document incident lifecycle and hardware inventory"`. No version bump, no release — separate user decision.
