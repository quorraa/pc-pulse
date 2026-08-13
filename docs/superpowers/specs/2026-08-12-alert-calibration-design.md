# Alert calibration and hardware inventory

**Date:** 2026-08-12
**Status:** Approved pending user review

## Summary

PC Pulse's alerting moves from rigid thresholds to learned per-machine
baselines with incident-style lifecycle: sustained breaches, hysteresis,
cooldowns, fingerprint deduplication, reopen-instead-of-respawn, and a
quality layer that gates notifications on confidence, persistence,
corroboration, user impact, and novelty. The evidence bundle gains a
vendor-neutral hardware inventory. Motivating field reports come from a
second machine (Lenovo ThinkCentre M75q Gen 2, Ryzen 5 PRO 5650GE, 16 GB
RAM, Radeon iGPU with no NVML telemetry, no ACPI thermal zones, ~404
processes, high normal memory occupancy): a Critical collector-budget
alert on a 0.769% vs 0.75% crossing, repeatedly reopened collector-growth
incidents, DPC attribution alternating between driver families, and
handle-growth notification spam that later self-resolved.

Guiding principles, from the user's brief:

- Missing hardware *telemetry* never implies missing hardware. Inventory
  states what exists; gauges state what is measurable; explicit
  unavailable/error states are preserved for both.
- Notify for actionable sustained degradation. Low-confidence or transient
  signals live in history only. Raw telemetry and diagnostics are always
  recorded, even when notification is suppressed.
- One evolving incident per underlying condition — never a stream of
  duplicates, never alternating identities while attribution is unstable.

## Current architecture (design inputs)

Verified against the code (service = `src/PcPulse.Service/src`):

- `Alert` (models.rs:147-169) already carries `occurrence_count`,
  `first_seen_ms`/`last_seen_ms`, `resolved_at_ms`, `acknowledged`,
  `archived`. `AlertEngine` (alerting.rs) dedups on an in-memory string
  key (`"{kind}:{pid}:{startedAtMs}"` per-process, fixed keys for
  system-wide detectors), requires `sustained_samples` consecutive
  breaches via a streak map, and resolves by absence.
- Gaps: the key is not persisted (so identity dies at resolution and at
  service restart — each refire mints a new UUID: the reopen spam); no
  exit-threshold hysteresis (streak reset is the only re-arm control); no
  cooldown; no notification gating (the tray pops for any unseen alert).
- Baselines are in-memory EWMA per *process instance* (`(pid,
  started_at_ms)`) and one engine-global kernel-pool baseline; nothing
  survives restart; `handleGrowth`/`threadGrowth` have **no** baseline
  gate at all (raw delta only).
- The DPC/interrupt engine (metrics/interrupts.rs) already implements
  8-second ETW captures (fast phase: 3 captures 2 min apart, then 10 min
  cooldown), 64 KiB-bucket driver attribution, modal-candidate
  consistency, and correlation-based confidence verdicts — but the
  `dpcInterrupt` alert fires on the rate threshold alone, before any
  verdict exists. The alert key is the fixed string `"dpcInterrupt"`, so
  attribution flapping never *splits* the incident today; the flapping
  appears in evidence/title text and in refires after resolution.
- Collector self-watch: CPU ceiling `settings.collector_cpu_percent`
  (default 0.2%, range 0.05–10; the observed machine runs a raised 0.75
  ceiling), **fixed** 25 MB working-set budget, **fixed** 600-handle
  budget, and a three-segment growth-trend test over a 5-minute ring.
  Breaches are Critical with no tolerance band.
- Hardware gauges (`HardwareMetrics`) exist with honest degradation
  (`available: bool`, `detail: String`, per-sensor `Option`s); there is
  no static inventory (no CPU model, RAM size, disk models, GPU via
  anything but NVML).
- Settings ride as a whole JSON struct; additive fields need serde
  defaults in `config.rs` plus TUNE plumbing in the TUI only if
  user-tunable. Alerts upsert into SQLite by id with the full record as
  JSON payload; adding fields is a payload-only change.

## Phase A — Hardware inventory

New module `metrics/inventory.rs` (service), following the `WmiThermal`
pattern: one persistent COM/WMI connection, probe once at service start
(static facts do not need a cadence; a daily re-probe catches driver
updates), every group independently `present | unavailable { detail }`.

`HardwareInventory` (models.rs, camelCase serde):

| Group | Source | Fields |
| --- | --- | --- |
| cpu | `Win32_Processor` (root\CIMV2) | manufacturer, brand string, physical_cores, logical_processors, base_clock_mhz (Option), max_clock_mhz (Option) |
| system | `Win32_ComputerSystem` | manufacturer, model |
| bios | `Win32_BIOS` | version, release_date (Option) |
| memory | `Win32_PhysicalMemory` (summed) | installed_bytes, module_count, speed_mts (Option) |
| storage | `MSFT_PhysicalDisk` (root\microsoft\windows\storage), fallback `Win32_DiskDrive` | per device: model, size_bytes, bus_type, media_type (SSD/HDD/unknown) |
| gpus | `Win32_VideoController` | per adapter: name, vendor, driver_version, vram_bytes (Option) |

Each group is `InventoryGroup<T> { value: Option<T>, detail: String }` —
a failed WMI class query records the error string and never fabricates.
GPU inventory is deliberately independent of NVML: the observed machine's
Radeon iGPU appears in inventory (it exists) while GPU *telemetry* stays
honestly unavailable (NVML absent). The analyzer bundle and any consumer
must be able to distinguish "no GPU" from "GPU present, telemetry
unavailable".

Placement: `Snapshot.hardware.inventory: Option<HardwareInventory>`
(sibling to the existing gauges inside `HardwareMetrics`). It reaches the
agent-context evidence bundle through the existing `snapshot.clone()`
path with no analysis.rs changes. Collection failures never delay or
fail the sampling loop (probe on the startup path with a bounded retry,
then serve the cached result).

## Phase B — Incident lifecycle and durable baselines

### Fingerprint and reopen

- `Alert` gains `fingerprint: String` (the engine's dedup key, now
  persisted and visible) and `state: IncidentState` (`open | reopened |
  resolved`), both serde-default for old records.
- On resolution the engine remembers `(fingerprint → id, resolved_at)` —
  in memory and recoverable from storage (query recent resolved alerts
  by fingerprint) so restarts do not forget.
- A breach within the **quiet period** (6 h) of a resolved incident with
  the same fingerprint *reopens* it: same id, `state: reopened`,
  `occurrence_count += 1`, evidence refreshed. A breach after the quiet
  period is a genuinely new incident.
- Reopening does **not** notify by default; see Phase C for the three
  renotify conditions.
- The startup force-resolve of open alerts is retained but marks them
  resolved with a "service restart" note; their fingerprints stay
  reopen-eligible so a persisting condition reattaches to its incident.

### Hysteresis and cooldown

- Detectors gain an **exit threshold** at 85% of the entry threshold
  (per-detector constant, not a setting) plus a minimum hold time of one
  full sustained window: a value oscillating across the entry threshold
  cannot flap the incident; it resolves only after staying below the
  exit threshold for the hold duration.
- After resolution, the streak requirement re-arms as today, and the
  quiet-period reopen logic ensures a quick refire updates the existing
  incident rather than spawning a sibling.

### Durable baselines

New SQLite table `baselines (scope TEXT PRIMARY KEY, payload TEXT,
updated_ms INTEGER)`:

- **Machine scope** (`machine`): EWMA percentile sketches (p50/p95/p99
  via P²-style estimators) for memory occupancy %, DPC rate, interrupt
  rate, disk latency, process count. Updated every sample, persisted
  every 5 minutes and on clean shutdown, loaded at start.
- **Per-process-name scope** (`process:{name_hash}`): EWMA mean/variance
  for CPU, working set, handles, threads, keyed by executable name (not
  PID), bucketed by process age (0–5 min, 5–60 min, 1 h+) so a young
  process is judged against young-process norms. Bounded: top ~200
  process names by observation count, LRU-evicted.
- Existing per-instance baselines remain for intra-lifetime deviation;
  the durable per-name baselines add the cross-boot, cross-instance
  norm the brief calls "process-age and workload baselines".
- **Learning period**: machine-scope baseline age < 24 h ⇒ the
  notification policy floor rises (only Critical with high confidence
  notifies); incidents accrue normally in history tagged "learning".
  The statusline and Incidents page surface the learning state.

## Phase C — Quality layer and notification policy

New service module `quality.rs`. Every active incident carries
`quality: AlertQuality` (serde-default), recomputed each evaluation:

| Score (0–1) | Meaning / inputs |
| --- | --- |
| confidence | attribution stability (DPC verdict state), baseline maturity, sample depth behind the breach |
| persistence | breach duration relative to the detector's sustained window (saturating at ~3× window) |
| corroboration | correlated co-signals: DPC↔disk latency/GPU/network activity correlation (existing Pearson machinery), growth↔unresponsive windows, latency↔I/O pressure |
| user_impact | co-occurring user-facing evidence: hung windows, slow launches, foreground-process involvement |
| novelty | 1.0 for first occurrence of a fingerprint, decaying with occurrence count and recency of the last notification |

Fixed default policy (constants, no new TUNE settings — YAGNI; the
existing per-detector thresholds remain the tuning surface):

- `notify = severity >= Warning && persistence >= 0.5 && confidence >= 0.5`,
  with Critical requiring `confidence >= 0.35` (a genuinely dying machine
  should not be silenced by an immature baseline).
- Learning period: `notify` additionally requires `severity == Critical
  && confidence >= 0.6`.
- Renotify (an existing incident pops again) only on: (1) severity
  escalation, (2) materially changed fingerprint — defined per-detector,
  e.g. a *confident* DPC driver-family verdict change, never a
  low-confidence label flip, or (3) recurrence after a full quiet
  period. Implemented as `notify_generation: u32` on the alert; the tray
  pops on unseen `(id, notify_generation)` with `notify == true`.
- Suppressed incidents remain fully recorded (SQLite, history page,
  agent context) with their quality scores visible; nothing about
  suppression drops telemetry.

The tray helper's filter changes from "unseen id, not acknowledged, not
archived" to "unseen (id, notify_generation), notify == true, not
acknowledged, not archived". Old-service compatibility: a record without
the new fields defaults to `notify = true, notify_generation = 0` —
identical to today's behavior.

## Phase D — Detector calibrations

### Collector budget (`collectorBudget`, `collectorGrowth`)

- **Tolerance band**: entry requires value ≥ ceiling × 1.15 sustained
  (existing streak), or ≥ ceiling continuously for 10 minutes. Within
  the band (ceiling..ceiling×1.15): Info severity, history-only. Above
  the band sustained: Warning. Critical only at ≥ 2× ceiling sustained.
  The observed 0.769% vs 0.75% (2.5% over) lands in-band: recorded,
  never notified, never Critical.
- Working-set: the fixed 25 MB budget keeps the same banding. The
  growth detector treats oscillation of a few MB around a stable
  11–16 MB range as Info; Warning requires the three-segment trend to
  persist ≥ 30 minutes without returning toward the window's starting
  baseline. Reopens fold into the remembered incident via Phase B.

### DPC / interrupt (`dpcInterrupt`)

- The incident may open from the rate threshold (telemetry value), but
  **notification** requires either: a repeatable attribution — the same
  driver family as modal candidate across ≥ 2 successful captures (the
  engine's existing verdict machinery, now feeding `quality.confidence`)
  — or a sustained rate above the machine's learned p95 for ≥ 15 minutes
  *plus* corroboration (correlated disk/network/GPU activity or user
  impact ≥ 0.3).
- A single 8-second capture is diagnostic evidence only: it decorates
  the history-only incident and never triggers a balloon by itself.
- Fingerprint stays the fixed `dpcInterrupt` key: attribution changes
  never split the incident. Only a confident verdict change (both old
  and new verdicts passed the confidence gate) counts as a materially
  changed fingerprint for renotification. Title text stays stable
  ("High DPC or interrupt activity"); attribution lives in evidence.

### Handle / thread growth (`handleGrowth`, `threadGrowth`)

- Gain the baseline gate the other per-process detectors have: raw
  delta AND deviation from the process-age-bucketed per-name baseline.
- Burst-vs-leak discrimination: entry requires net growth over a
  30-minute window with a monotonic shape (generalized three-segment
  trend test, extracted from the collector-growth helper into a shared
  utility). A plateau (last third flat) or return toward the window
  start auto-resolves the incident silently — history records the
  excursion, no balloon, occurrences update the single incident.
- Forensics captures (handle-type histograms, thread-start modules)
  remain tied to active incidents and feed `corroboration`.

## Phase E — UI and tests

### TUI

- Incidents page rows gain: occurrence count (`×N` when > 1), last-seen
  age, and a compact confidence marker (e.g. `●○○` low / `●●○` medium /
  `●●●` high). Detail pane gains the five quality scores, state
  (open/reopened/resolved), and a reopen timeline (first seen, last
  reopened, notification count).
- History-only incidents render in a muted style with a "history"
  badge; notified incidents keep today's presentation.
- Statusline shows "learning your machine (Nh left)" during the
  learning period.
- No layout redesign; rows and panes keep their shape.

### Tests (named for the field reports)

1. Collector CPU at 0.769% with a 0.75% ceiling: incident recorded at
   Info, `notify == false`, never Critical; telemetry present in
   history and agent context.
2. Collector working set oscillating 11–16 MB: at most one incident,
   Info, no balloon; a genuine 30-minute monotonic climb upgrades to
   Warning with one notification; resolution then reopening within the
   quiet period keeps one id and does not renotify.
3. DPC attribution alternating (storage → graphics → network labels on
   successive low-confidence captures): one incident, title stable, no
   notification until either a repeatable verdict or sustained-p95 +
   corroboration; a confident verdict change renotifies the same id.
4. Handle growth burst-and-release (climb 800 handles, plateau, return):
   incident opens in history, auto-resolves silently, occurrence count
   updates; a true monotonic leak (30 min, age-baseline-deviating)
   notifies once and escalates only per policy.
5. Reopen across restart: resolved fingerprint reattaches after a
   service restart within the quiet period.
6. Learning period: a Warning-grade breach during the first 24 h stays
   history-only; a high-confidence Critical still notifies.
7. Inventory: stub WMI probe returns the Lenovo profile (Radeon present,
   NVML absent) — inventory lists the GPU while gauges stay unavailable;
   a failed class query yields `unavailable{detail}`, never a fabricated
   group; snapshot and agent context carry the inventory.
8. Compatibility: pre-upgrade alert JSON (no fingerprint/state/quality)
   deserializes with defaults equivalent to today's behavior; old TUI
   against new service ignores the additive fields.

## Protocol and compatibility

- All new fields are additive camelCase with serde defaults on both
  crates; `PROTOCOL_VERSION` stays 1. `docs/protocol.md` gains the new
  fields and the incident-state semantics.
- SQLite: one new `baselines` table; the alerts table is unchanged
  (new fields ride in the JSON payload). Retention pruning applies to
  baselines only via LRU caps, not time (baselines are the point of
  long memory).
- The collector remains network-free; all new probes are local WMI/Win32
  reads. Inventory adds one connect-once WMI service handle, within the
  existing collector handle budget.

## Out of scope

- New TUNE settings for the quality policy (fixed constants this
  iteration; revisit only with field evidence).
- Cross-machine baseline sync, exporting baselines.
- Changing detector default thresholds themselves.
- Notification channels beyond the existing tray balloons.
- Client-side (TUI) alerting logic; all intelligence stays in the
  collector.
