# Performance Ratings Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A quick in-app performance rating (`f`), stored with demand context and an agent-ready digest, that calibrates the notification policy per demand bucket — never the baselines — and accumulates the labeled corpus for the future optimization agent.

**Architecture:** New service module `ratings.rs` (record assembly: demand bucketing + digest), `storage.rs` ratings table, two additive pipe commands, lazy policy offsets derived in `quality.rs` from rating history, and a TUI rating overlay + nudge. Spec: `docs/superpowers/specs/2026-08-13-performance-ratings-design.md` — read it before your task; it is the authority.

**Tech Stack:** Rust; rusqlite; existing analysis/redaction machinery for digests; Ratatui overlay.

## Global Constraints

- Ratings NEVER touch baselines, detector thresholds, or severities — policy notify-floor offsets only.
- Spec constants verbatim: offsets ±0.05 per rating, bounded ±0.15 total, 30-day half-life decay applied lazily at read time (ratings table is the single source of truth — no second mutable store); demand buckets light/moderate/heavy from trailing 10 min composite = max(CPU pct, memory-occupancy pct, IO pct percentile vs machine baseline), heavy ≥ p90 sustained, moderate ≥ p50; digest ≤ 32 KB, redacted like agent-context; ratings LRU-capped at 1,000, never time-pruned; nudge ≤ 1/day, only after ≥ 10 min heavy in the trailing hour, never during learning; learning-period ratings stored with `during_learning: true` and produce no offsets; hotkey `f`; a rating only ever affects its own demand bucket (deceptive-comfort guard).
- All protocol additions are additive camelCase, `PROTOCOL_VERSION` stays 1; collector stays network-free; no new TUNE settings.
- Gate per task: `cargo test --workspace`, `cargo clippy --workspace --all-targets`, fmt scoped to your hunks (`git restore` unrelated drift — known repo churn). Plain commits, NO co-author trailer. Service tests in-module.
- Version stays 1.18.x during this plan; the 1.19.0 bump is the release step outside it.

---

### Task R1: Rating model + storage

**Files:**
- Modify: `src/PcPulse.Service/src/models.rs` (Rating types), `src/PcPulse.Service/src/storage.rs` (table + CRUD)

**Interfaces:**
- Produces (camelCase serde): `pub enum RatingVerdict { Good, Acceptable, Sluggish }`; `pub enum DemandBucket { Light, Moderate, Heavy }`; `pub struct DemandDetail { pub cpu_percent: f64, pub cpu_percentile: Option<f64>, pub memory_occupancy_pct: f64, pub memory_percentile: Option<f64>, pub disk_latency_ms: f64, pub disk_percentile: Option<f64>, pub io_bytes_per_sec: f64, pub io_percentile: Option<f64> }` (percentiles None when the sketch can't answer); `pub struct OpenIncidentRef { pub fingerprint: String, pub kind: String, pub severity: Severity, pub notify: bool, pub acknowledged: bool }`; `pub struct Rating { pub id: String, pub at_ms: i64, pub verdict: RatingVerdict, pub demand: DemandBucket, pub demand_detail: DemandDetail, pub digest: serde_json::Value, pub open_incidents: Vec<OpenIncidentRef>, pub during_learning: bool, pub unexplained: bool }`.
- storage.rs: table `ratings (id TEXT PRIMARY KEY, at_ms INTEGER NOT NULL, payload TEXT NOT NULL)` (tolerant creation, same style as `baselines`); `pub fn save_rating(&self, rating: &Rating) -> Result<()>` (insert then enforce the 1,000 cap by deleting oldest `at_ms` beyond it); `pub fn ratings(&self, limit: usize) -> Result<Vec<Rating>>` (newest first); ratings excluded from the retention prune job (verify by reading `prune()` — it targets specific tables; add a test pinning that a 400-day-old rating survives a prune).

- [ ] **Step 1: Failing tests** — round-trip a full Rating through save/load (verdict/bucket serde spellings pinned: `"good"`, `"heavy"`); the 1,000-cap eviction (insert 1,005, oldest 5 gone); prune-survival for an old rating; corrupt payload row skipped without panic (mirror `from_rows` tolerance).
- [ ] **Step 2: Run, verify failure. Step 3: implement. Step 4: green.**
- [ ] **Step 5: Gate + commit** — `git commit -m "Add performance rating records and storage"`

---

### Task R2: Demand bucketing + digest (`ratings.rs`)

**Files:**
- Create: `src/PcPulse.Service/src/ratings.rs`; Modify: `lib.rs` (`pub mod ratings;`)

**Interfaces:**
- Consumes: R1 types; `BaselineStore`/`MachineBaseline` sketches (`baselines.rs`); recent system samples (caller passes a slice — keep the module pure); the redaction/rollup helpers in `analysis.rs` (reuse via `pub(crate)` where needed rather than duplicating — the digest is a compacted sibling of the agent context).
- Produces:
  - `pub fn demand_bucket(recent: &[SystemMetric], machine: &MachineBaseline) -> (DemandBucket, DemandDetail)` — trailing-10-min composite per Global Constraints; a sketch with no quantile answer degrades that channel's percentile to None and excludes it from the composite (never fabricate); an empty slice ⇒ Light with all-None detail.
  - `pub fn build_digest(source: DigestSource) -> serde_json::Value` where `DigestSource` carries: system rollup percentiles over the trailing hour (reuse the analysis rollup), top ≤ 20 processes by the existing pressure score with `%USERPROFILE%`-redacted paths, active incidents with quality scores, learning state, collector health line. Enforce ≤ 32 KB serialized: drop process entries beyond the cap, then truncate log-like strings — never emit an over-cap digest (test with a pathological source).

- [ ] **Step 1: Failing tests** — bucket boundaries (composite exactly at p50 ⇒ Moderate; at p90 sustained ⇒ Heavy; sustained means the 10-min window's majority, pin the chosen rule in a test named for it); no-baseline degradation (fresh sketches ⇒ percentiles None, bucket falls back to fixed sane cutoffs — spec silent here, so: CPU ≥ 80% or memory ≥ 90% ⇒ Heavy, ≥ 50%/70% ⇒ Moderate, documented as the pre-learning fallback); digest ≤ 32 KB under a 500-process pathological source; digest redaction (a path containing the profile dir arrives redacted).
- [ ] **Steps 2-4: fail → implement → green.**
- [ ] **Step 5: Gate + commit** — `git commit -m "Derive demand context and agent-ready digests for ratings"`

---

### Task R3: Pipe commands

**Files:**
- Modify: `src/PcPulse.Service/src/models.rs` (PipeRequest variants), `src/PcPulse.Service/src/runtime.rs` (handlers), `src/PcPulse.Tui/src/client.rs` (client calls), `docs/protocol.md`

**Interfaces:**
- Consumes: R1, R2.
- Produces: `PipeRequest::AddRating { verdict: RatingVerdict }` → handler assembles the full Rating service-side (trailing samples from storage/live snapshot, bucket+detail via `ratings::demand_bucket`, digest via `ratings::build_digest`, open incidents from the snapshot's active alerts, `during_learning` from the baseline store, `unexplained = verdict == Sluggish && no active notifying incident`), saves, returns it. `PipeRequest::GetRatings { limit: usize }` → newest-first, clamped to 100. Client: `pub fn add_rating(&self, verdict: RatingVerdict) -> Result<Rating>`, `pub fn ratings(&self, limit: usize) -> Result<Vec<Rating>>`. protocol.md gains a "Performance ratings" section (commands table rows + record shape + the never-affects-baselines statement).

- [ ] **Step 1: Failing tests** — handler-level: AddRating stores and returns a record whose bucket/detail/digest/incidents are populated (drive with the storage + snapshot fixtures the runtime tests already use; if no runtime handler test harness exists, test the assembly function you factor out of the handler — the handler itself stays a thin shell, state the split); unexplained set exactly per the spec truth table (sluggish+none-notifying true; sluggish+notifying false; good/* false); serde spelling of both commands pinned (`"addRating"`, `"getRatings"` — match the existing command-naming convention in models.rs; read it first).
- [ ] **Steps 2-4: fail → implement → green.**
- [ ] **Step 5: Gate + commit** — `git commit -m "Accept and serve performance ratings over the pipe"`

---

### Task R4: Policy offsets

**Files:**
- Modify: `src/PcPulse.Service/src/quality.rs` (offset derivation + application), `src/PcPulse.Service/src/alerting.rs` (feed offsets into the scoring pass), `src/PcPulse.Service/src/runtime.rs` (load recent ratings into the engine on start + on AddRating)

**Interfaces:**
- Consumes: R1 (ratings from storage).
- Produces:
  - `pub struct PolicyOffsets` derived by `pub fn derive_offsets(ratings: &[Rating], now_ms: i64) -> PolicyOffsets` — per (kind, bucket): each qualifying rating contributes ±0.05 weighted by `0.5^(age_days/30)`, summed, clamped to ±0.15. Qualifying per spec: Good/Acceptable while that kind was notifying in that rating's bucket ⇒ +(stricter); Sluggish with nothing notifying ⇒ −(more permissive) for ALL kinds in that bucket; Sluggish while notifying ⇒ zero contribution; `during_learning` ratings ⇒ zero.
  - `pub fn lookup(&self, kind: &str, bucket: DemandBucket) -> f64` (0.0 default).
  - `decide()` applies the offset additively to the confidence AND persistence floors for the alert's kind and the CURRENT demand bucket (the engine computes the live bucket each evaluation via `ratings::demand_bucket` — reuse, don't duplicate; Calibration carries it).
  - Engine holds `PolicyOffsets`, rebuilt from the newest ≤ 200 ratings at startup and after each AddRating (runtime calls a setter — mirror `observe_interrupts`' setter pattern to avoid signature churn).
  - Effective non-zero offsets surface in the agent context (additive field on AgentContext: `ratingOffsets: [{kind, bucket, offset}]`) — the "visible" requirement; the TUI detail-pane display is R5's.

- [ ] **Step 1: Failing tests** — the spec's tests 3-6 verbatim as behaviors: false-positive path (+0.05, cap at +0.15 after 3+), false-negative path (bucket-wide −0.05 + unexplained already set by R3), confirmation path (zero), decay (60-day-old contributes 0.25 weight — pin the arithmetic), **deceptive-comfort: repeated Good at Light leaves Heavy offsets at 0.0 and a Heavy Sluggish still notifies at full sensitivity** (drive decide() with a Heavy-bucket incident after seeding Light-bucket Good ratings), learning-period ratings contribute zero.
- [ ] **Steps 2-4: fail → implement → green** (existing decide() tests must stay green — offsets default 0.0).
- [ ] **Step 5: Gate + commit** — `git commit -m "Let ratings calibrate the notification floors per demand bucket"`

---

### Task R5: TUI — rating overlay, nudge, visibility

**Files:**
- Modify: `src/PcPulse.Tui/src/app.rs` (input mode + nudge state + prefs `last_rating_nudge_ms: i64` serde default 0), `src/PcPulse.Tui/src/ui.rs` (overlay + incidents-page annotations + offset display), `src/PcPulse.Tui/src/prefs.rs`

**Interfaces:**
- Consumes: R3 client calls.
- Produces: `f` in Normal mode (verify against the bound-key list at dispatch time; `f` was free at planning) opens a centered 3-choice overlay — `g` good / `a` acceptable / `s` sluggish / Esc cancels — one keypress each; on choice, `client.add_rating` on the existing worker pattern (non-blocking; status line confirms "rating recorded — thanks" or error). Nudge: on snapshot updates, if `!learning && now - last_rating_nudge_ms >= 24h && heavy_minutes_in_trailing_hour >= 10` (heavy-minutes tracked client-side from snapshot demand — R3's Rating isn't needed; compute from the snapshot's system metrics vs a simple client heuristic OR have the service expose it — CHOOSE: service exposes `Snapshot.heavy_minutes_trailing_hour: Option<u16>` additive field, computed where the data lives; add it in this task, service side, with a test) → status message "rate how this machine feels — press f", set last_rating_nudge_ms, persist prefs. Incidents detail pane: when the selected alert's (kind, current bucket) has a non-zero offset, one line "policy adjusted by your ratings: +0.05".

- [ ] **Step 1: Failing tests** — overlay opens on `f` and routes g/a/s to the right verdict (mock/channel the client call per the existing worker test pattern); Esc cancels cleanly; nudge fires only when all three gates pass (three negative cases + one positive), persists last-nudge; `heavy_minutes_trailing_hour` service test (window arithmetic); detail-pane offset line renders for a non-zero offset and is absent at zero.
- [ ] **Steps 2-4: fail → implement → green** (gallery/demo fixtures: nudge state must not fire in deterministic renders — verify).
- [ ] **Step 5: Gate + commit** — `git commit -m "Rate how the machine feels and let it tune the notifications"`

---

### Task R6: Docs + live smoke

**Files:**
- Modify: `README.md` (ratings section, house voice); verify `docs/protocol.md` (R3 wrote it; cross-check against shipped serde)

- [ ] **Step 1:** README section: what the person gets (press f, three choices, ratings teach what acceptable means for THIS machine per load level, never lowers the bar measured under load from idle ratings, feeds the future optimization agent).
- [ ] **Step 2:** Full gate.
- [ ] **Step 3:** Live smoke (controller + user): rate via `f` on the running machine; verify the stored record (`GetRatings` via a CLI addition if trivial, else sqlite query) carries bucket + digest ≤ 32 KB + redaction; offset math visible after a false-positive-shaped rating; nudge does NOT fire during learning.
- [ ] **Step 4: Commit** — `git commit -m "Document performance ratings"`. Release (1.19.0) is the user's call.
