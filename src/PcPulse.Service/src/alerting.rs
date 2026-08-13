use crate::{
    baselines::{AgeBucketStats, RunningStats},
    config::Settings,
    metrics::interrupts::VerdictState,
    models::{Alert, AlertQuality, Evidence, IncidentState, ProcessMetric, Severity, SystemMetric},
    quality::{Calibration, NotifyDecision, QualityInputs, decide, score},
    stats::{TrendPoint, TrendShape, classify_trend},
};
use std::collections::{HashMap, HashSet, VecDeque};
use uuid::Uuid;

const MIB: f64 = 1024.0 * 1024.0;
/// Absolute collector handle budget. The original 250 predates the WMI/COM
/// apartment, NVML, and forensics subsystems, whose fixed infrastructure
/// (ETW provider registrations, registry keys, driver handles) measures
/// ~350-500 steady handles on real machines with zero growth. 600 keeps
/// headroom for detection of genuine leaks without flagging the baseline.
const COLLECTOR_HANDLE_BUDGET: u32 = 600;
/// Fraction of a detector's entry threshold that a value must fall below
/// before its incident may close, plus a hold of one full sustained window.
/// A per-detector constant rather than a setting: it exists so a value
/// oscillating across the entry threshold cannot flap the incident.
const EXIT_RATIO: f64 = 0.85;
/// How long a resolved incident stays reopen-eligible. A breach of the same
/// fingerprint inside this window resurrects that incident (same id, state
/// `Reopened`, occurrences continuing); a breach after it is a genuinely new
/// incident. Also the window `runtime` seeds the engine's reopen memory from,
/// so a condition that outlives a service restart reattaches.
pub const QUIET_PERIOD_MS: i64 = 6 * 3_600_000;
/// The engine key -- and so the fingerprint -- of the DPC/interrupt
/// incident. Fixed by the spec: attribution changes never split it.
const DPC_KEY: &str = "dpcInterrupt";
/// The trailing window the kernel rate has to spend above the machine's
/// learned p95 before it can carry a notification on its own evidence, with
/// no repeatable driver-family attribution behind it.
const SUSTAINED_P95_MS: i64 = 15 * 60_000;
/// Share of that window's samples that must sit at or above the p95.
///
/// Deliberately a fraction of a window rather than an unbroken run: p95 is
/// the level roughly one sample in twenty exceeds *by definition*, so a
/// machine whose kernel rate sits above its own p95 for a quarter of an hour
/// will still dip below it now and then. Demanding 450 consecutive
/// exceedances would be a gate a genuinely sick machine never passes, which
/// is the opposite of what this path is for.
const SUSTAINED_P95_FRACTION: f64 = 0.9;
/// Hard cap on the p95 window, guarding against a caller sampling far faster
/// than the settings allow. At the 1 s minimum interval a 15-minute window is
/// 900 samples; if the cap ever bit, the window would stop spanning its full
/// duration and the gate would simply not open, which is the safe direction.
const P95_WINDOW_CAP: usize = 2_048;
/// Incident kinds that speak for the person at the keyboard. Their presence
/// alongside a machine-wide incident is the `user_impact` signal.
const USER_IMPACT_KINDS: [&str; 2] = ["unresponsive", "slowLaunch"];
/// How far back the handle/thread growth *shape* window reaches. It is a
/// separate, longer series from the five-minute per-process ring the raw
/// deltas are measured against: telling a leak from a burst is a question
/// about half an hour of behavior, while "how many handles appeared since a
/// minute ago" is not.
const GROWTH_WINDOW_MS: i64 = 30 * 60_000;
/// The shortest span that window will pronounce on. Below it the series has
/// no shape worth naming, so the detector says nothing at all -- the same
/// four-to-five-minute floor the collector's own growth trend has always
/// used, kept short enough that a ten-minute excursion is still classified
/// while it is happening rather than only in hindsight.
const GROWTH_MIN_SPAN_MS: i64 = 5 * 60_000;
/// How long an unbroken monotonic climb must persist before a growth finding
/// escalates from history-only `Info` to a notifiable `Warning` (spec: growth
/// persistence 30 min). Before that the finding is recorded, scored, and
/// visible -- it is simply not yet distinguishable from a burst, and the
/// field case proves bursts are the common one.
const GROWTH_PERSISTENCE_MS: i64 = 30 * 60_000;
/// Per-segment step, as a fraction of the detector's entry threshold, that
/// the shape test needs to call a segment "higher than the last".
///
/// A tenth of the entry threshold per segment is deliberately small: the
/// shape test's job is to answer "is this still climbing?", and the
/// consequence of answering no is that an open incident auto-resolves. A
/// large step would read a slow leak as a plateau and silently close it,
/// which is the expensive mistake; a small one only costs a slower close on
/// a genuinely finished excursion. It is still far above the handful of
/// handles a steady process jitters by.
const GROWTH_STEP_FRACTION: f64 = 0.1;
/// A process joins the long-window watch list once a raw growth delta reaches
/// this fraction of its entry threshold, so the shape window is already
/// filling by the time the raw gate trips -- a window that only started at
/// the threshold would have nothing to say for its first five minutes.
const GROWTH_WATCH_ENTRY: f64 = 0.25;
/// And it leaves only after sitting below *this* fraction for a full sustained
/// window. The gap between entry and exit is deliberate hysteresis: growth is
/// lumpy, and a single quiet sample used to throw away the whole thirty
/// minutes of history, which is exactly the evidence the next sample needs.
const GROWTH_WATCH_EXIT: f64 = 0.20;
/// How many processes may carry a long window at once. Thirty minutes of
/// samples is a few hundred points per process; a cap keeps a machine where
/// hundreds of processes all drift upward from turning the shape window into
/// a memory budget problem.
///
/// The cap evicts rather than refuses: a process that is actually breaching
/// its threshold must never be locked out by a crowd of sub-threshold
/// drifters, because being locked out means no window, no shape, and so no
/// detection at all. See [`AlertEngine::evict_weakest_growth_window`].
const GROWTH_WATCH_CAP: usize = 32;

#[derive(Debug, Clone, Default)]
struct ProcessBaseline {
    cpu: RunningStats,
    working_set: RunningStats,
    handles: RunningStats,
    threads: RunningStats,
    io_rate: RunningStats,
}

#[derive(Debug, Clone)]
struct ProcessPoint {
    timestamp_ms: i64,
    working_set_bytes: u64,
    handles: u32,
    threads: u32,
}

/// One sample of the long growth window. Deliberately narrower than
/// [`ProcessPoint`]: the only thing thirty minutes of retention is paying for
/// is the handle and thread counts.
#[derive(Debug, Clone, Copy)]
struct GrowthPoint {
    timestamp_ms: i64,
    handles: u32,
    threads: u32,
}

/// The long growth window for one process instance, plus the bookkeeping that
/// decides whether it keeps its slot.
#[derive(Debug, Clone)]
struct GrowthWindow {
    points: VecDeque<GrowthPoint>,
    /// The most recent raw growth delta as a fraction of its own entry
    /// threshold, taken across both dimensions. 1.0 means "breaching right
    /// now". It ranks windows for eviction and drives the watch hysteresis.
    pressure: f64,
    /// When the pressure first fell below [`GROWTH_WATCH_EXIT`]; cleared the
    /// moment it climbs back. `None` means the window is not cooling.
    cooling_since: Option<i64>,
    /// Whether this instance currently holds an open growth incident, which
    /// makes its window ineligible for eviction.
    protected: bool,
    /// The per-name learned norm as it stood when this window opened.
    ///
    /// This is the fix for the detector's worst failure mode. The runtime
    /// folds every sample into the per-name baseline, so a process that leaks
    /// steadily *teaches its own name's baseline to expect the leak*: the
    /// EWMA mean chases the ramp a fixed distance behind it while the
    /// deviation band grows faster still, and the "is this abnormal?" gate
    /// stops firing -- scale-invariantly, at any leak rate. Snapshotting the
    /// norm when the excursion begins means the climb is judged against who
    /// the process was before it started climbing, which is the only
    /// comparison that answers the question being asked.
    ///
    /// `None` when there was nothing learned to snapshot (no store, or a name
    /// the store has never seen), which the gate treats as passing open.
    ///
    /// **Nothing rearms it.** It is captured once, when the window opens, and
    /// the only thing that replaces it is the window being surrendered
    /// entirely and later reopened -- which needs a full watch exit
    /// ([`GROWTH_WATCH_EXIT`] sustained for a hold window, with no open
    /// incident). A process that stays watched for a day therefore keeps
    /// judging itself against a day-old snapshot, and every legitimate
    /// upward shift in its behaviour since then reads as excursion. That is
    /// deliberate: the alternative is a norm that drifts toward whatever the
    /// process is currently doing, which is the exact failure this field
    /// exists to prevent. The bias is toward reporting, which is the
    /// direction this detector is allowed to be wrong in.
    norm: Option<AgeBucketStats>,
}

/// What a growth incident's window shape says about whether it may close.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GrowthFate {
    /// The excursion is over -- the process either stopped taking more
    /// (`Plateau`: stabilized, so not a leak) or gave back what it took
    /// (`Returning`). Close the incident now, silently.
    AutoResolve,
    /// The process is still climbing, or has released only a token part of
    /// what it took and is still sitting on the rest
    /// ([`TrendShape::PartialRelease`]). Whatever the raw delta reads this
    /// sample, the incident stays open.
    StaysOpen,
    /// The window has nothing to say yet; the ordinary exit-threshold
    /// hysteresis decides, exactly as it does for every other detector.
    Undecided,
}

/// The safety-critical half of Phase D's burst-versus-leak discrimination.
///
/// `PartialRelease` is the variant that must never be folded into
/// `Returning`: it means the process handed back some of what it took and is
/// still holding the remainder (its `remaining` field is how much), so
/// closing on it would report a live leak as recovered. `stats`'s
/// `RETURNING_TOLERANCE_FRACTION` exists to keep the two apart for exactly
/// this consumer.
fn growth_fate(shape: TrendShape) -> GrowthFate {
    match shape {
        TrendShape::Plateau | TrendShape::Returning => GrowthFate::AutoResolve,
        TrendShape::Monotonic { .. } | TrendShape::PartialRelease { .. } => GrowthFate::StaysOpen,
        TrendShape::Inconclusive => GrowthFate::Undecided,
    }
}

#[derive(Debug, Clone, Copy)]
struct CollectorGrowth {
    growth_mb: f64,
    first_mean_mb: f64,
    middle_mean_mb: f64,
    last_mean_mb: f64,
    window_seconds: f64,
}

#[derive(Debug, Clone)]
struct Candidate {
    key: String,
    kind: &'static str,
    severity: Severity,
    required_samples: u32,
    pid: Option<u32>,
    process_name: Option<String>,
    title: String,
    explanation: String,
    evidence: Vec<Evidence>,
    recommendation: String,
    /// The entry threshold this candidate's measured value crossed, for
    /// value-shaped detectors. `None` for event-shaped detectors (slow
    /// launch, crash dumps, a hung window), which keep absence-resolution
    /// because they have no sustained value to fall back below.
    entry: Option<f64>,
    exit_ratio: f64,
    /// Detector-supplied "what I am describing is materially different now"
    /// flag -- e.g. a *confident* DPC driver-family verdict change, never a
    /// low-confidence label flip. It is one of the notification policy's
    /// renotify conditions.
    material_change: bool,
    /// What this detector knows about its own evidence, on its way to the
    /// scoring pass.
    quality: CandidateQuality,
}

/// The quality inputs only the detector can supply, carried from the
/// candidate that fired to the scoring pass via [`IncidentCalibration`].
///
/// `Default` is "nothing to add", which is every detector that has not been
/// calibrated to fill it in: an unknown attribution (neutral, not negative),
/// no co-signals, and no veto of its own.
#[derive(Debug, Clone, Copy)]
struct CandidateQuality {
    /// Whether the detector's attribution has held. `None` when it has no
    /// attribution to offer.
    attribution_stable: Option<bool>,
    corroborating_signals: u32,
    user_impact_signals: u32,
    /// Whether the detector's own evidence bar is met. The generic floors in
    /// [`crate::quality::decide`] stay necessary; this makes them
    /// insufficient. It is a veto and never a promotion: a detector cannot
    /// notify past the floors with it.
    notify: bool,
}

impl Default for CandidateQuality {
    fn default() -> Self {
        Self {
            attribution_stable: None,
            corroborating_signals: 0,
            user_impact_signals: 0,
            notify: true,
        }
    }
}

/// What the runtime knows about DPC/interrupt attribution and the machine's
/// learned kernel-rate norms, handed to the engine before each evaluation by
/// [`AlertEngine::observe_interrupts`].
///
/// `Default` is an engine that has never been told anything -- no verdict,
/// nothing learned -- which keeps the DPC incident history-only. That is the
/// honest reading for a caller with no interrupt engine behind it, and it is
/// what every test that does not care about DPC gets.
#[derive(Debug, Clone, Default)]
pub struct InterruptContext {
    pub verdict: VerdictState,
    /// Independent co-signals from the interrupt engine's correlation pass.
    pub corroborating_signals: u32,
    /// Machine-learned p95 of the DPC and interrupt rates; `None` while the
    /// sketch has too few observations to answer.
    pub dpc_p95: Option<f64>,
    pub interrupt_p95: Option<f64>,
}

impl Candidate {
    /// Mark a candidate as value-shaped: its incident may only resolve once
    /// the detector's reading has stayed below `entry × exit_ratio` for a
    /// full sustained window.
    fn with_entry(mut self, entry: f64) -> Self {
        self.entry = Some(entry);
        self
    }
}

/// The hysteresis contract an open incident is held to, captured from the
/// candidate that last fired for it (the candidate is gone by the time the
/// condition clears, so the engine has to remember its terms).
#[derive(Debug, Clone, Copy)]
struct ExitGuard {
    exit_threshold: f64,
    /// One full sustained window: `required_samples × sample_interval_ms`.
    hold_ms: i64,
}

/// What the quality layer needs to remember about a live incident between
/// evaluations: the terms of the detector that raised it, and where the
/// current run of breaching samples began.
#[derive(Debug, Clone, Copy, Default)]
struct IncidentCalibration {
    /// The detector's sustained window (`required_samples × interval`).
    window_ms: Option<i64>,
    /// When the current unbroken run of breaching samples started -- the
    /// honest start of the breach, which for a reopened incident is *not*
    /// its original `first_seen_ms`. `Option`, not a zero sentinel: a
    /// breach that began at timestamp zero is a real breach.
    breach_since_ms: Option<i64>,
    /// Carried from the candidate that fired this sample, and consumed by
    /// the same sample's scoring pass.
    material_change: bool,
    /// The detector's own quality inputs, latched from the candidate that
    /// last fired. Unlike `material_change` these are *not* cleared each
    /// sample: an incident held open by hysteresis has no candidate to
    /// restate them, and the last thing the detector said is the best thing
    /// known about it.
    quality: CandidateQuality,
    /// Set when this run of breaching samples began by reopening a resolved
    /// incident: the severity that incident was remembered at before it
    /// resolved. A reopen has no active `previous` alert to escalate
    /// against (the incident was not in `active` a moment ago), so the
    /// scoring pass substitutes this remembered severity instead -- a
    /// reopen at a higher band must still renotify. Persistence resets on a
    /// reopen and can take several samples to clear the notify floor again,
    /// so this stays set (surviving across evaluations) until a scoring
    /// pass actually gets to use it, at which point it is cleared so a
    /// genuine escalation bumps the generation exactly once rather than on
    /// every later sample.
    reopened_from_severity: Option<Severity>,
}

/// When an incident was last marked notifiable, and at which generation.
/// Outlives the incident itself (pruned on the quiet period) so a reopened
/// incident remembers that the user has already been told.
#[derive(Debug, Clone, Copy)]
struct NotifyMemory {
    generation: u32,
    at_ms: i64,
}

/// What the engine remembers about a resolved incident so a refire of the
/// same fingerprint inside the quiet period continues it rather than
/// starting over. Recoverable from storage across restarts via
/// [`AlertEngine::new`].
#[derive(Debug, Clone)]
struct ResolvedIncident {
    id: String,
    resolved_at_ms: i64,
    /// `first_seen_ms` is remembered alongside the occurrence count because
    /// a reopened incident must keep reporting when it *first* started, not
    /// when it last came back.
    first_seen_ms: i64,
    occurrence_count: u32,
    notify_generation: u32,
    /// The incident's severity at the moment it resolved. Without this, an
    /// escalation on reopen (e.g. resolved at Warning, reopens at Critical)
    /// is undetectable: the reopen has no active `previous` alert to compare
    /// against, so the escalation check has nothing to escalate from.
    severity: Severity,
}

#[derive(Debug, Clone, Default)]
pub struct Evaluation {
    pub active: Vec<Alert>,
    /// New, updated, and resolved alerts that should be persisted.
    pub changed: Vec<Alert>,
}

#[derive(Default)]
pub struct AlertEngine {
    streaks: HashMap<String, u32>,
    active: HashMap<String, Alert>,
    /// Exit terms for each open incident, keyed like `active`.
    guards: HashMap<String, ExitGuard>,
    /// When each open incident's reading first fell below its exit
    /// threshold; cleared the moment the reading climbs back.
    below_exit_since: HashMap<String, i64>,
    /// Fingerprint -> the incident that most recently closed under it,
    /// pruned to the quiet period.
    resolved_memory: HashMap<String, ResolvedIncident>,
    /// Scoring terms for each incident with a live streak or an open alert,
    /// keyed like `streaks`.
    calibrations: HashMap<String, IncidentCalibration>,
    /// Engine key (which is the incident's fingerprint) -> the last
    /// notification the policy authorized for it, keyed like `streaks`.
    notify_memory: HashMap<String, NotifyMemory>,
    baselines: HashMap<(u32, i64), ProcessBaseline>,
    history: HashMap<(u32, i64), VecDeque<ProcessPoint>>,
    /// The thirty-minute handle/thread series, kept only for processes that
    /// are showing a growth signal or already hold a growth incident. Every
    /// other process keeps just the five-minute `history` ring, which is what
    /// stops the longer window from costing memory on all few hundred
    /// processes on the machine.
    growth_history: HashMap<(u32, i64), GrowthWindow>,
    /// Process instances whose samples must be kept out of their own name's
    /// learned norm, rebuilt each evaluation. See
    /// [`AlertEngine::self_training_quarantine`].
    quarantine: HashSet<(u32, i64)>,
    /// This sample's window shape per growth key, rebuilt from scratch every
    /// evaluation. A process that stopped being watched -- or exited -- simply
    /// has no entry, and its incident falls back to hysteresis.
    growth_shapes: HashMap<String, TrendShape>,
    /// When each growth key's current unbroken monotonic run began. This, not
    /// the incident's age, is what the `Info` -> `Warning` escalation is
    /// measured from: the question is how long the climb has held its shape.
    monotonic_since: HashMap<String, i64>,
    pool_baseline: RunningStats,
    /// The latest DPC/interrupt attribution and learned kernel-rate norms.
    interrupts: InterruptContext,
    /// One flag per sample -- "was the kernel rate at or above what this
    /// machine has learned is normal" -- over the trailing
    /// [`SUSTAINED_P95_MS`].
    p95_window: VecDeque<(i64, bool)>,
    /// The last confident driver-family change acted on, so a verdict that
    /// stays `ChangedConfidently` for many samples (the interrupt engine
    /// only re-derives it on a capture, minutes apart) renotifies once.
    last_verdict_change: Option<(String, String)>,
    /// A confident change that has not reached a scoring pass yet. Latched
    /// rather than applied at once because the change can land on a sample
    /// where the incident is held open by hysteresis, with no candidate to
    /// carry it -- and a dropped flag is a renotification the user never got.
    pending_verdict_change: bool,
    /// The collector's own working-set samples, retained to a fixed 30
    /// minutes -- independent of `history`'s 5-minute cap, which exists for
    /// the per-process growth *deltas* (`memoryGrowth`, `handleGrowth`,
    /// `threadGrowth`), not for `collectorGrowth`'s trend shape. `collectorGrowth`
    /// needs a genuine 30-minute span to classify Monotonic vs. Plateau vs.
    /// Returning, so it keeps its own longer-lived buffer rather than
    /// widening `history` for every process.
    collector_growth_points: VecDeque<TrendPoint>,
}

impl AlertEngine {
    /// Build an engine whose reopen memory is pre-loaded from storage
    /// (`Storage::recent_resolved_alerts`), so a condition that outlived a
    /// service restart reattaches to its incident instead of minting a
    /// sibling. `AlertEngine::default()` is the same engine with no memory.
    pub fn new(reopen_seed: Vec<Alert>) -> Self {
        let mut engine = Self::default();
        for alert in reopen_seed {
            if alert.fingerprint.is_empty() {
                continue;
            }
            // Pre-fingerprint records and mid-flight rows can lack a
            // resolution timestamp; the last sample that touched them is the
            // closest honest stand-in.
            let resolved_at_ms = alert.resolved_at_ms.unwrap_or(alert.last_seen_ms);
            if engine
                .resolved_memory
                .get(&alert.fingerprint)
                .is_none_or(|remembered| remembered.resolved_at_ms <= resolved_at_ms)
            {
                engine.resolved_memory.insert(
                    alert.fingerprint,
                    ResolvedIncident {
                        id: alert.id,
                        resolved_at_ms,
                        first_seen_ms: alert.first_seen_ms,
                        occurrence_count: alert.occurrence_count,
                        notify_generation: alert.notify_generation,
                        severity: alert.severity,
                    },
                );
            }
        }
        engine
    }

    /// Feed the DPC/interrupt attribution verdict, its corroboration, and
    /// the machine's learned kernel-rate p95s. The runtime calls this before
    /// every [`Self::evaluate`]; an engine that is never told keeps the
    /// honest default and holds the DPC incident to history.
    pub fn observe_interrupts(&mut self, context: InterruptContext) {
        if let VerdictState::ChangedConfidently { from, to } = &context.verdict {
            let change = (from.clone(), to.clone());
            if self.last_verdict_change.as_ref() != Some(&change) {
                self.last_verdict_change = Some(change);
                self.pending_verdict_change = true;
            }
        }
        self.interrupts = context;
    }

    /// Open incidents that speak for the user rather than the machine. Read
    /// from the active map, so an impact incident that opens on this very
    /// sample counts from the next one -- a one-sample lag against a gate
    /// measured in quarter-hours.
    ///
    /// Archived incidents do not count: archiving is the user saying this
    /// finding is not worth surfacing, and something they have filed away
    /// must not vouch for something else. Acknowledged ones still do --
    /// acknowledging says "I have seen it", not "it is not happening".
    fn user_impact_signals(&self) -> u32 {
        let count = self
            .active
            .values()
            .filter(|alert| USER_IMPACT_KINDS.contains(&alert.kind.as_str()) && !alert.archived)
            .count();
        u32::try_from(count).unwrap_or(u32::MAX)
    }

    /// Whether the kernel rate has spent the trailing [`SUSTAINED_P95_MS`]
    /// mostly at or above the machine's learned p95.
    ///
    /// Three things have to hold: the window has to actually span its full
    /// duration, it has to be populated at something like the sampling
    /// cadence (a stalled collector must not turn two readings a
    /// quarter-hour apart into a sustained run), and
    /// [`SUSTAINED_P95_FRACTION`] of its samples have to be above.
    fn sustained_above_p95(&self, now_ms: i64, interval_ms: u64) -> bool {
        let Some((oldest_ms, _)) = self.p95_window.front() else {
            return false;
        };
        if now_ms - oldest_ms < SUSTAINED_P95_MS {
            return false;
        }
        let expected = (SUSTAINED_P95_MS / interval_ms.max(1) as i64) as f64;
        let samples = self.p95_window.len() as f64;
        if samples < expected * SUSTAINED_P95_FRACTION {
            return false;
        }
        let above = self.p95_window.iter().filter(|(_, above)| *above).count() as f64;
        above >= samples * SUSTAINED_P95_FRACTION
    }

    /// What the DPC detector knows about its own evidence this sample.
    ///
    /// The incident opens on the configured rate, but notification needs
    /// evidence the rate alone cannot give (spec Phase D): either an
    /// attribution that held across captures, or a quarter of an hour above
    /// the machine's own learned p95 with something independent agreeing.
    /// `user_impact >= 0.3` is one signal -- the score closes half the
    /// remaining gap per signal, so the first one is 0.5.
    fn dpc_quality(&self, system: &SystemMetric, settings: &Settings) -> CandidateQuality {
        let user_impact_signals = self.user_impact_signals();
        let sustained = self.sustained_above_p95(system.timestamp_ms, settings.sample_interval_ms);
        let corroborated = self.interrupts.corroborating_signals >= 1 || user_impact_signals >= 1;
        CandidateQuality {
            attribution_stable: self.interrupts.verdict.attribution_stable(),
            corroborating_signals: self.interrupts.corroborating_signals,
            user_impact_signals,
            notify: self.interrupts.verdict.is_attributed() || (sustained && corroborated),
        }
    }

    pub fn evaluate(
        &mut self,
        system: &SystemMetric,
        processes: &[ProcessMetric],
        settings: &Settings,
        calibration: Calibration<'_>,
    ) -> Evaluation {
        let mut candidates = Vec::new();
        // The pre-evaluation state of every open incident, which the
        // notification policy compares against (severity escalation, whether
        // the incident was already notifying). Bounded by the active set,
        // which is a handful of alerts even on a struggling machine.
        let previous: HashMap<String, Alert> = self.active.clone();
        // What each value-shaped detector currently reads, whether or not it
        // breached. An open incident needs these to decide whether the
        // condition has actually cleared or merely dipped under the entry
        // threshold. Gathering them costs a formatted key per detector per
        // process, so it only happens while something is open — with nothing
        // open there is no exit threshold to test.
        let track_exits = !self.active.is_empty();
        let mut readings: HashMap<String, f64> = HashMap::new();
        // The shape window describes this sample only, so it is rebuilt from
        // scratch: a key that no process produced this time round has no
        // shape, which is exactly what an exited process should look like.
        self.growth_shapes.clear();
        self.quarantine.clear();
        // Every growth key this sample produced. The monotonic-run bookkeeping
        // is pruned to it, so a climb belonging to a process that has exited
        // does not outlive the process.
        let mut watched_growth_keys: HashSet<String> = HashSet::new();
        self.resolved_memory.retain(|_, remembered| {
            system.timestamp_ms - remembered.resolved_at_ms <= QUIET_PERIOD_MS
        });
        let live_keys: HashSet<(u32, i64)> = processes
            .iter()
            .map(|process| (process.pid, process.started_at_ms))
            .collect();
        let live_pids: HashSet<u32> = processes.iter().map(|process| process.pid).collect();

        for process in processes {
            let identity = (process.pid, process.started_at_ms);
            let baseline = self.baselines.entry(identity).or_default().clone();
            let history = self.history.entry(identity).or_default();
            history.push_back(ProcessPoint {
                timestamp_ms: process.timestamp_ms,
                working_set_bytes: process.working_set_bytes,
                handles: process.handle_count,
                threads: process.thread_count,
            });
            let cutoff = process.timestamp_ms - 5 * 60 * 1_000;
            while history
                .front()
                .is_some_and(|point| point.timestamp_ms < cutoff)
            {
                history.pop_front();
            }
            let prior = history
                .iter()
                .find(|point| process.timestamp_ms - point.timestamp_ms >= 60_000)
                .or_else(|| history.front());

            if track_exits {
                readings.insert(process_key("sustainedCpu", process), process.cpu_percent);
            }
            if process.cpu_percent >= settings.cpu_percent
                && baseline
                    .cpu
                    .deviates(process.cpu_percent, settings.baseline_sigma, 10.0)
            {
                candidates.push(process_candidate(
                    process,
                    "sustainedCpu",
                    Severity::Warning,
                    settings.sustained_samples,
                    "Sustained CPU usage",
                    format!(
                        "{} has remained CPU-bound above both the configured limit and its normal baseline.",
                        process.name
                    ),
                    vec![
                        evidence("Current CPU", format!("{:.1}%", process.cpu_percent)),
                        evidence("Baseline CPU", format!("{:.1}%", baseline.cpu.mean)),
                        evidence("Threshold", format!("{:.1}%", settings.cpu_percent)),
                    ],
                    "Inspect the process tree and current workload. Close or restart the app only after saving work.",
                ).with_entry(settings.cpu_percent));
            }

            if let Some(prior) = prior {
                let memory_growth = process
                    .working_set_bytes
                    .saturating_sub(prior.working_set_bytes);
                let handle_growth = process.handle_count.saturating_sub(prior.handles);
                let thread_growth = process.thread_count.saturating_sub(prior.threads);
                let window_seconds =
                    ((process.timestamp_ms - prior.timestamp_ms) as f64 / 1_000.0).max(1.0);
                if track_exits {
                    readings.insert(process_key("memoryGrowth", process), memory_growth as f64);
                    readings.insert(
                        process_key("handleGrowth", process),
                        f64::from(handle_growth),
                    );
                    readings.insert(
                        process_key("threadGrowth", process),
                        f64::from(thread_growth),
                    );
                }
                if memory_growth as f64 >= settings.memory_growth_mb * MIB
                    && baseline.working_set.deviates(
                        process.working_set_bytes as f64,
                        settings.baseline_sigma,
                        settings.memory_growth_mb * MIB / 2.0,
                    )
                {
                    candidates.push(process_candidate(
                        process,
                        "memoryGrowth",
                        Severity::Warning,
                        settings.sustained_samples,
                        "Memory is growing abnormally",
                        format!("{} is retaining memory faster than its established baseline.", process.name),
                        vec![
                            evidence("Growth", format!("{:.1} MB", memory_growth as f64 / MIB)),
                            evidence("Window", format!("{window_seconds:.0} seconds")),
                            evidence("Working set", format!("{:.1} MB", process.working_set_bytes as f64 / MIB)),
                        ],
                        "Check the app for a long-running task or leak. Restart it only after saving work; update or repair it if growth returns.",
                    ).with_entry(settings.memory_growth_mb * MIB));
                }
                // Handle and thread growth are the two detectors that cannot
                // be judged from a single delta: a burst that opens 800
                // handles and gives them all back reads identically to a leak
                // for the first ten minutes. So they get a second, longer
                // window whose *shape* answers the question the delta cannot,
                // and it is kept only for processes that are actually moving.
                let handle_key = process_key("handleGrowth", process);
                let thread_key = process_key("threadGrowth", process);
                // How hard this process is pushing against its own thresholds
                // right now, on whichever dimension is pushing hardest.
                let pressure = threshold_fraction(handle_growth, settings.handle_growth)
                    .max(threshold_fraction(thread_growth, settings.thread_growth));
                let protected =
                    self.active.contains_key(&handle_key) || self.active.contains_key(&thread_key);
                let hold_ms =
                    i64::from(settings.sustained_samples) * settings.sample_interval_ms as i64;

                // An existing window is updated in place and only surrendered
                // after a full sustained window of genuine quiet.
                let mut cooled_off = false;
                if let Some(window) = self.growth_history.get_mut(&identity) {
                    window.pressure = pressure;
                    window.protected = protected;
                    if protected || pressure >= GROWTH_WATCH_EXIT {
                        window.cooling_since = None;
                    } else {
                        let since = *window.cooling_since.get_or_insert(process.timestamp_ms);
                        cooled_off = process.timestamp_ms - since >= hold_ms;
                    }
                    if !cooled_off {
                        window.points.push_back(GrowthPoint {
                            timestamp_ms: process.timestamp_ms,
                            handles: process.handle_count,
                            threads: process.thread_count,
                        });
                        let cutoff = process.timestamp_ms - GROWTH_WINDOW_MS;
                        while window
                            .points
                            .front()
                            .is_some_and(|point| point.timestamp_ms < cutoff)
                        {
                            window.points.pop_front();
                        }
                    }
                }
                if cooled_off {
                    self.growth_history.remove(&identity);
                } else if !self.growth_history.contains_key(&identity)
                    && (pressure >= GROWTH_WATCH_ENTRY || protected)
                {
                    if self.growth_history.len() >= GROWTH_WATCH_CAP {
                        evict_weakest_growth_window(&mut self.growth_history, pressure);
                    }
                    if self.growth_history.len() < GROWTH_WATCH_CAP {
                        let age_ms = (system.timestamp_ms - process.started_at_ms).max(0);
                        self.growth_history.insert(
                            identity,
                            GrowthWindow {
                                // Seed from the five-minute ring rather than
                                // starting empty. Those points are already
                                // paid for, they include the current sample,
                                // and they are what gives the window a
                                // pre-excursion baseline to measure a return
                                // against -- without them the first third of
                                // the window is the climb itself, and a
                                // process that hands everything back never
                                // looks like it came home.
                                points: history
                                    .iter()
                                    .map(|point| GrowthPoint {
                                        timestamp_ms: point.timestamp_ms,
                                        handles: point.handles,
                                        threads: point.threads,
                                    })
                                    .collect(),
                                pressure,
                                cooling_since: None,
                                protected,
                                // Snapshot the norm before the excursion can
                                // teach it anything. The bucket is chosen by
                                // the age the process is now and stays fixed
                                // for the excursion, which is the honest
                                // reading: this is who it was when it started.
                                norm: calibration
                                    .names
                                    .and_then(|store| store.name_stats(&process.name, age_ms))
                                    .cloned(),
                            },
                        );
                    }
                }

                let window = self.growth_history.get(&identity);
                let (handle_shape, thread_shape) = match window {
                    Some(window) => (
                        Some(growth_shape(
                            &window.points,
                            |point| f64::from(point.handles),
                            growth_step(settings.handle_growth),
                        )),
                        Some(growth_shape(
                            &window.points,
                            |point| f64::from(point.threads),
                            growth_step(settings.thread_growth),
                        )),
                    ),
                    None => (None, None),
                };
                let norm = window.and_then(|window| window.norm.as_ref());
                for (key, shape) in [(&handle_key, handle_shape), (&thread_key, thread_shape)] {
                    watched_growth_keys.insert(key.clone());
                    match shape {
                        Some(shape) => {
                            self.growth_shapes.insert(key.clone(), shape);
                            if matches!(shape, TrendShape::Monotonic { .. }) {
                                self.monotonic_since
                                    .entry(key.clone())
                                    .or_insert(system.timestamp_ms);
                            } else {
                                self.monotonic_since.remove(key);
                            }
                        }
                        None => {
                            self.monotonic_since.remove(key);
                        }
                    }
                }

                // A climb that has already proved itself a leak must stop
                // teaching its own name that leaking is normal.
                let handle_climb =
                    monotonic_run_ms(self.monotonic_since.get(&handle_key), system.timestamp_ms);
                let thread_climb =
                    monotonic_run_ms(self.monotonic_since.get(&thread_key), system.timestamp_ms);
                if handle_climb.max(thread_climb) >= GROWTH_PERSISTENCE_MS {
                    self.quarantine.insert(identity);
                }

                if handle_growth >= settings.handle_growth
                    && matches!(handle_shape, Some(TrendShape::Monotonic { .. }))
                    && name_baseline_admits(
                        norm,
                        |stats| &stats.handles,
                        f64::from(process.handle_count),
                        settings.baseline_sigma,
                        f64::from(settings.handle_growth) / 2.0,
                    )
                {
                    let climbed_ms = handle_climb;
                    candidates.push(process_candidate(
                        process,
                        "handleGrowth",
                        growth_severity(climbed_ms),
                        settings.sustained_samples,
                        "Handle count is growing",
                        format!("{} is opening handles faster than it releases them, and has been climbing rather than bursting.", process.name),
                        vec![
                            evidence("New handles", handle_growth.to_string()),
                            evidence("Current handles", process.handle_count.to_string()),
                            evidence("Window", format!("{window_seconds:.0} seconds")),
                            evidence("Climbing for", format!("{} minutes", climbed_ms / 60_000)),
                        ],
                        "Inspect the process and its plug-ins. A confirmed restart is safer than force-ending it; update the app if the pattern repeats.",
                    ).with_entry(f64::from(settings.handle_growth)));
                }
                if thread_growth >= settings.thread_growth
                    && matches!(thread_shape, Some(TrendShape::Monotonic { .. }))
                    && name_baseline_admits(
                        norm,
                        |stats| &stats.threads,
                        f64::from(process.thread_count),
                        settings.baseline_sigma,
                        f64::from(settings.thread_growth) / 2.0,
                    )
                {
                    let climbed_ms = thread_climb;
                    candidates.push(process_candidate(
                        process,
                        "threadGrowth",
                        growth_severity(climbed_ms),
                        settings.sustained_samples,
                        "Thread count is growing",
                        format!("{} is creating threads without returning to its normal range.", process.name),
                        vec![
                            evidence("New threads", thread_growth.to_string()),
                            evidence("Current threads", process.thread_count.to_string()),
                            evidence("Window", format!("{window_seconds:.0} seconds")),
                            evidence("Climbing for", format!("{} minutes", climbed_ms / 60_000)),
                        ],
                        "Pause the triggering workload and inspect extensions or child processes. Restart only with confirmation.",
                    ).with_entry(f64::from(settings.thread_growth)));
                }
            }

            let io_mb = (process.read_bytes_per_sec + process.write_bytes_per_sec) / MIB;
            if track_exits {
                readings.insert(process_key("sustainedIo", process), io_mb);
            }
            if io_mb >= settings.io_mb_per_sec
                && baseline
                    .io_rate
                    .deviates(io_mb, settings.baseline_sigma, 10.0)
            {
                candidates.push(process_candidate(
                    process,
                    "sustainedIo",
                    Severity::Warning,
                    settings.sustained_samples,
                    "Unusually heavy disk I/O",
                    format!("{} is the leading source of sustained disk traffic.", process.name),
                    vec![
                        evidence("Read rate", format!("{:.1} MB/s", process.read_bytes_per_sec / MIB)),
                        evidence("Write rate", format!("{:.1} MB/s", process.write_bytes_per_sec / MIB)),
                        evidence("Normal combined rate", format!("{:.1} MB/s", baseline.io_rate.mean)),
                    ],
                    "Let expected indexing, updates, or copies finish. Otherwise inspect the process before choosing a confirmed close or restart.",
                ).with_entry(settings.io_mb_per_sec));
            }

            let unresponsive_samples = ((settings.unresponsive_seconds as u64 * 1_000)
                .div_ceil(settings.sample_interval_ms))
                as u32;
            if process.has_visible_window && !process.responsive {
                candidates.push(process_candidate(
                    process,
                    "unresponsive",
                    Severity::Critical,
                    unresponsive_samples.max(settings.sustained_samples),
                    "Application is not responding",
                    format!("Windows reports that {} has stopped processing window messages.", process.name),
                    vec![
                        evidence("Status", "Not responding"),
                        evidence("Required duration", format!("{} seconds", settings.unresponsive_seconds)),
                    ],
                    "Wait for recovery first. If it stays hung, save work elsewhere and use the confirmed End process action.",
                ));
            }

            if process
                .launch_duration_ms
                .is_some_and(|duration| duration >= settings.slow_launch_ms)
            {
                candidates.push(process_candidate(
                    process,
                    "slowLaunch",
                    Severity::Info,
                    2,
                    "Slow application launch",
                    format!("{} took substantially longer than the configured launch target to show a usable window.", process.name),
                    vec![
                        evidence("Launch time", format!("{:.1} seconds", process.launch_duration_ms.unwrap_or_default() as f64 / 1_000.0)),
                        evidence("Target", format!("{:.1} seconds", settings.slow_launch_ms as f64 / 1_000.0)),
                    ],
                    "Review startup extensions and storage pressure. Avoid registry cleaners or disabling security software.",
                ));
            }

            let age_minutes = (system.timestamp_ms - process.started_at_ms).max(0) / 60_000;
            let quiet = process.cpu_percent < 1.0
                && process.read_bytes_per_sec + process.write_bytes_per_sec < MIB;
            let orphaned = process.parent_pid == 0 || !live_pids.contains(&process.parent_pid);
            if process.is_agent_candidate
                && orphaned
                && quiet
                && age_minutes >= i64::from(settings.abandoned_agent_minutes)
            {
                candidates.push(process_candidate(
                    process,
                    "abandonedAgent",
                    Severity::Info,
                    settings.sustained_samples,
                    "Possible abandoned agent process",
                    format!("{} looks detached from its parent and has been idle for an extended period.", process.name),
                    vec![
                        evidence("Process ID", process.pid.to_string()),
                        evidence("Parent ID", process.parent_pid.to_string()),
                        evidence("Age", format!("{age_minutes} minutes")),
                    ],
                    "Verify that no terminal, editor, or automation still owns this agent. End it only through the confirmation dialog if it is truly abandoned.",
                ));
            }

            if process.pid == std::process::id() {
                let memory_mb = process.working_set_bytes as f64 / MIB;
                let memory_ratio = memory_mb / 25.0;
                let cpu_ratio = ratio(process.cpu_percent, settings.collector_cpu_percent);
                let handles_ratio =
                    f64::from(process.handle_count) / f64::from(COLLECTOR_HANDLE_BUDGET);
                let memory_breached = memory_ratio >= 1.0;
                let cpu_breached = cpu_ratio >= 1.0;
                let handles_breached = handles_ratio >= 1.0;
                // Three absolute budgets share one incident, so its exit
                // reading is how far the worst dimension sits above its
                // own ceiling; 1.0 is the entry threshold by construction.
                let worst_ratio = [memory_ratio, cpu_ratio, handles_ratio]
                    .into_iter()
                    .fold(0.0_f64, f64::max);
                let budget_key = process_key("collectorBudget", process);
                if track_exits {
                    readings.insert(budget_key.clone(), worst_ratio);
                }
                if memory_breached || cpu_breached || handles_breached {
                    // How long the worst dimension has sat at or above its
                    // bare ceiling without a break, from the calibration the
                    // *previous* evaluation left behind -- this sample's own
                    // streak has not been recorded yet. Feeds the alternate
                    // ten-minute entry path below.
                    let continuous_breach_ms = self
                        .calibrations
                        .get(&budget_key)
                        .and_then(|terms| terms.breach_since_ms)
                        .map_or(0, |since| process.timestamp_ms - since);
                    let severity = collector_budget_severity(worst_ratio, continuous_breach_ms);
                    let mut budget_evidence = Vec::new();
                    if memory_breached {
                        budget_evidence.push(evidence(
                            "Breached budget",
                            format!("Working set {memory_mb:.1} MB >= 25 MB"),
                        ));
                    }
                    if cpu_breached {
                        budget_evidence.push(evidence(
                            "Breached budget",
                            format!(
                                "CPU {:.3}% >= {}%",
                                process.cpu_percent, settings.collector_cpu_percent
                            ),
                        ));
                    }
                    if handles_breached {
                        budget_evidence.push(evidence(
                            "Breached budget",
                            format!(
                                "Handles {} >= {COLLECTOR_HANDLE_BUDGET}",
                                process.handle_count
                            ),
                        ));
                    }
                    budget_evidence.extend([
                        evidence("Working set", format!("{memory_mb:.1} MB / 25 MB")),
                        evidence(
                            "CPU",
                            format!(
                                "{:.3}% / {}%",
                                process.cpu_percent, settings.collector_cpu_percent
                            ),
                        ),
                        evidence(
                            "Handles",
                            format!("{} / {COLLECTOR_HANDLE_BUDGET}", process.handle_count),
                        ),
                    ]);
                    candidates.push(process_candidate(
                        process,
                        "collectorBudget",
                        severity,
                        settings.sustained_samples.max(5),
                        "Collector resource budget exceeded",
                        "The PC Pulse collector has remained beyond at least one absolute production resource budget.".into(),
                        budget_evidence,
                        "Capture the diagnostics and restart only the PC Pulse Collector service. Report the breached dimension; do not terminate monitored applications.",
                    ).with_entry(1.0));
                }

                // A dedicated 30-minute buffer, independent of the 5-minute
                // `history` used for growth deltas: `collectorGrowth` needs
                // a genuine 30-minute span to classify Monotonic vs. Plateau
                // vs. Returning.
                self.collector_growth_points.push_back(TrendPoint {
                    at_ms: process.timestamp_ms,
                    value: process.working_set_bytes as f64,
                });
                let growth_cutoff = process.timestamp_ms - COLLECTOR_GROWTH_WINDOW_MS;
                while self
                    .collector_growth_points
                    .front()
                    .is_some_and(|point| point.at_ms < growth_cutoff)
                {
                    self.collector_growth_points.pop_front();
                }

                let age_ms = process.timestamp_ms.saturating_sub(process.started_at_ms);
                if age_ms >= 10 * 60_000
                    && let Some((severity, growth)) =
                        collector_growth_shape(self.collector_growth_points.make_contiguous())
                {
                    let (title, explanation, recommendation): (&str, String, &str) = match severity
                    {
                        Severity::Warning => (
                            "Collector working set is trending upward",
                            "After startup warm-up, the PC Pulse collector working set rose through each segment of a mature 30-minute observation window instead of making a one-time cache allocation.".into(),
                            "Capture diagnostics and keep observing. Restart only the PC Pulse Collector service if the trend continues; report repeatable growth rather than terminating monitored applications.",
                        ),
                        _ => (
                            "Collector working set grew, then leveled off or gave it back",
                            "The PC Pulse collector working set grew earlier in the 30-minute observation window but has since plateaued or returned toward its starting level. Recorded for visibility; not an active leak.".into(),
                            "No action needed while the trend does not persist. Keep observing if growth resumes.",
                        ),
                    };
                    candidates.push(process_candidate(
                        process,
                        "collectorGrowth",
                        severity,
                        settings.sustained_samples.max(15),
                        title,
                        explanation,
                        vec![
                            evidence("Sustained growth", format!("{:.1} MB", growth.growth_mb)),
                            evidence(
                                "Early-window mean",
                                format!("{:.1} MB", growth.first_mean_mb),
                            ),
                            evidence(
                                "Mid-window mean",
                                format!("{:.1} MB", growth.middle_mean_mb),
                            ),
                            evidence("Recent mean", format!("{:.1} MB", growth.last_mean_mb)),
                            evidence(
                                "Observation window",
                                format!("{:.0} seconds", growth.window_seconds),
                            ),
                        ],
                        recommendation,
                    ));
                }
            }
        }

        let owner = processes.iter().max_by(|a, b| {
            (a.read_bytes_per_sec + a.write_bytes_per_sec)
                .total_cmp(&(b.read_bytes_per_sec + b.write_bytes_per_sec))
        });
        // Fixed key, matching `dpcInterrupt`'s pattern: the top-I/O owner
        // churns sample to sample, and embedding its pid in the fingerprint
        // used to resolve-and-split the incident on every attribution change,
        // defeating hysteresis. The owner still identifies itself in the
        // evidence and explanation below; only the incident identity is
        // fixed to the condition, not to whoever is currently blamed for it.
        let disk_key = "diskLatency".to_string();
        if track_exits {
            readings.insert(disk_key.clone(), system.disk_latency_ms);
            // The kernel-pool detector fires on the excess over its learned
            // baseline, so that excess -- not the absolute pool size -- is
            // what the exit threshold has to be a fraction of.
            readings.insert(
                "kernelPool".into(),
                (system.paged_pool_bytes + system.nonpaged_pool_bytes) as f64
                    - self.pool_baseline.mean,
            );
            readings.insert(
                DPC_KEY.into(),
                ratio(system.dpc_rate, settings.dpc_rate)
                    .max(ratio(system.interrupt_rate, settings.interrupt_rate)),
            );
        }

        // The learned-p95 window runs whether or not the configured threshold
        // is breached: it measures the machine against itself.
        let above_p95 = self
            .interrupts
            .dpc_p95
            .is_some_and(|p95| system.dpc_rate >= p95)
            || self
                .interrupts
                .interrupt_p95
                .is_some_and(|p95| system.interrupt_rate >= p95);
        self.p95_window.push_back((system.timestamp_ms, above_p95));
        let p95_cutoff = system.timestamp_ms - SUSTAINED_P95_MS;
        while self
            .p95_window
            .front()
            .is_some_and(|(at_ms, _)| *at_ms < p95_cutoff)
        {
            self.p95_window.pop_front();
        }
        while self.p95_window.len() > P95_WINDOW_CAP {
            self.p95_window.pop_front();
        }

        // What the DPC detector currently knows about its own evidence,
        // computed every sample rather than only when its candidate fires --
        // an incident parked between the exit and entry thresholds fires no
        // candidate and arms no exit clock, so without a refresh its latched
        // inputs (and the notification veto built from them) would stand for
        // as long as the reading stayed in that band.
        let dpc_quality = self.dpc_quality(system, settings);

        if system.disk_latency_ms >= settings.disk_latency_ms {
            candidates.push(Candidate {
                key: disk_key,
                kind: "diskLatency",
                severity: Severity::Warning,
                required_samples: settings.sustained_samples,
                pid: owner.map(|p| p.pid),
                process_name: owner.map(|p| p.name.clone()),
                title: "Sustained disk latency".into(),
                explanation: owner.map_or_else(
                    || "Disk response time is above the configured sustained limit.".into(),
                    |p| format!("Disk response time is high; {} is currently issuing the most I/O.", p.name),
                ),
                evidence: vec![
                    evidence("Average latency", format!("{:.1} ms", system.disk_latency_ms)),
                    evidence("Threshold", format!("{:.1} ms", settings.disk_latency_ms)),
                    evidence("System I/O", format!("{:.1} MB/s", (system.disk_read_bytes_per_sec + system.disk_write_bytes_per_sec) / MIB)),
                ],
                recommendation: "Let active transfers finish, check free disk space and drive health, then inspect the named process. Do not disable write caching or security tools blindly.".into(),
                entry: Some(settings.disk_latency_ms),
                exit_ratio: EXIT_RATIO,
                material_change: false,
                quality: CandidateQuality::default(),
            });
        }

        let pool_total = (system.paged_pool_bytes + system.nonpaged_pool_bytes) as f64;
        if self.pool_baseline.deviates(
            pool_total,
            settings.baseline_sigma,
            settings.kernel_pool_growth_mb * MIB,
        ) && pool_total > self.pool_baseline.mean + settings.kernel_pool_growth_mb * MIB
        {
            candidates.push(Candidate {
                key: "kernelPool".into(),
                kind: "kernelPoolGrowth",
                severity: Severity::Critical,
                required_samples: settings.sustained_samples,
                pid: None,
                process_name: None,
                title: "Kernel pool usage is growing".into(),
                explanation: "Paged or nonpaged kernel allocations remain well above their learned baseline; a driver is the likely owner.".into(),
                evidence: vec![
                    evidence("Current pools", format!("{:.1} MB", pool_total / MIB)),
                    evidence("Baseline", format!("{:.1} MB", self.pool_baseline.mean / MIB)),
                    evidence("Nonpaged", format!("{:.1} MB", system.nonpaged_pool_bytes as f64 / MIB)),
                ],
                recommendation: "Update recently changed drivers and use PoolMon to identify the allocation tag. Reboot only as temporary relief; do not terminate arbitrary system processes.".into(),
                entry: Some(settings.kernel_pool_growth_mb * MIB),
                exit_ratio: EXIT_RATIO,
                material_change: false,
                quality: CandidateQuality::default(),
            });
        }

        if system.dpc_rate >= settings.dpc_rate || system.interrupt_rate >= settings.interrupt_rate
        {
            candidates.push(Candidate {
                key: DPC_KEY.into(),
                kind: "dpcInterrupt",
                severity: Severity::Warning,
                required_samples: settings.sustained_samples,
                pid: None,
                process_name: None,
                title: "High DPC or interrupt activity".into(),
                explanation: "Kernel interrupt work is sustained above the configured limit, which commonly points to a device or driver rather than a user process.".into(),
                evidence: vec![
                    evidence("DPC rate", format!("{:.0}/s", system.dpc_rate)),
                    evidence("Interrupt rate", format!("{:.0}/s", system.interrupt_rate)),
                ],
                recommendation: "Check recently connected devices and update OEM chipset, network, audio, and storage drivers. Do not disable devices until you have identified a repeatable cause.".into(),
                entry: Some(1.0),
                exit_ratio: EXIT_RATIO,
                // The verdict change is latched on arrival instead (it can
                // land while no candidate is firing), so the candidate never
                // has to carry it.
                material_change: false,
                quality: dpc_quality,
            });
        }

        let present: HashSet<String> = candidates
            .iter()
            .map(|candidate| candidate.key.clone())
            .collect();
        // Keys whose alert this evaluation created or updated. Their records
        // are cloned into `changed` after scoring, so what reaches storage
        // and the snapshot carries this sample's quality and notify decision.
        let mut touched: HashSet<String> = HashSet::new();
        for candidate in candidates {
            // The condition is present again, so any exit clock it had
            // started is void.
            self.below_exit_since.remove(&candidate.key);
            let streak = self.streaks.entry(candidate.key.clone()).or_default();
            *streak = streak.saturating_add(1);
            let terms = self.calibrations.entry(candidate.key.clone()).or_default();
            if *streak == 1 {
                terms.breach_since_ms = Some(system.timestamp_ms);
            }
            terms.window_ms =
                Some(i64::from(candidate.required_samples) * settings.sample_interval_ms as i64);
            terms.material_change = candidate.material_change;
            terms.quality = candidate.quality;
            if *streak < candidate.required_samples {
                continue;
            }
            match candidate.entry {
                Some(entry) => {
                    self.guards.insert(
                        candidate.key.clone(),
                        ExitGuard {
                            exit_threshold: entry * candidate.exit_ratio,
                            hold_ms: i64::from(candidate.required_samples)
                                * settings.sample_interval_ms as i64,
                        },
                    );
                }
                None => {
                    self.guards.remove(&candidate.key);
                }
            }
            if let Some(alert) = self.active.get_mut(&candidate.key) {
                alert.last_seen_ms = system.timestamp_ms;
                alert.occurrence_count = alert.occurrence_count.saturating_add(1);
                alert.evidence = candidate.evidence;
                // The detector's current reading of how bad this is: a
                // banded detector can move an incident between severities
                // while it stays the same incident, and an escalation is one
                // of the policy's renotify conditions.
                alert.severity = candidate.severity;
                touched.insert(candidate.key);
            } else {
                // A refire inside the quiet period continues the incident it
                // belongs to instead of minting a sibling: same id, same
                // start, occurrences carried forward. The notify generation
                // rides along unchanged, so a reopen is silent until the
                // notification policy decides otherwise.
                let reopened = self
                    .resolved_memory
                    .remove(&candidate.key)
                    .filter(|prior| system.timestamp_ms - prior.resolved_at_ms <= QUIET_PERIOD_MS);
                if let Some(prior) = &reopened {
                    self.calibrations
                        .entry(candidate.key.clone())
                        .or_default()
                        .reopened_from_severity = Some(prior.severity);
                }
                let alert = Alert {
                    id: reopened
                        .as_ref()
                        .map_or_else(|| Uuid::new_v4().to_string(), |prior| prior.id.clone()),
                    kind: candidate.kind.into(),
                    severity: candidate.severity,
                    first_seen_ms: reopened
                        .as_ref()
                        .map_or(system.timestamp_ms, |prior| prior.first_seen_ms),
                    last_seen_ms: system.timestamp_ms,
                    process_id: candidate.pid,
                    process_name: candidate.process_name,
                    title: candidate.title,
                    explanation: candidate.explanation,
                    evidence: candidate.evidence,
                    recommendation: candidate.recommendation,
                    acknowledged: false,
                    occurrence_count: reopened
                        .as_ref()
                        .map_or(1, |prior| prior.occurrence_count.saturating_add(1)),
                    resolved_at_ms: None,
                    archived: false,
                    fingerprint: candidate.key.clone(),
                    state: reopened
                        .as_ref()
                        .map_or(IncidentState::Open, |_| IncidentState::Reopened),
                    // Both are decided by the scoring pass below, for this
                    // incident and every other open one.
                    quality: crate::models::AlertQuality::default(),
                    notify: false,
                    notify_generation: reopened.as_ref().map_or(0, |prior| prior.notify_generation),
                };
                touched.insert(candidate.key.clone());
                self.active.insert(candidate.key, alert);
            }
        }

        // Resolved records keep the last quality the incident was scored
        // with: persistence and novelty describe a live breach, and there is
        // no live breach left to describe.
        let mut resolved = Vec::new();
        let resolved_keys: Vec<String> = self
            .active
            .keys()
            .filter(|key| !present.contains(*key))
            .cloned()
            .collect();
        for key in resolved_keys {
            // A growth incident closes on the shape of its window, not on the
            // raw delta having dipped: the delta goes quiet the instant a leak
            // pauses, while the window still knows the process is sitting on
            // everything it took.
            let fate = self.growth_shapes.get(&key).copied().map(growth_fate);
            match fate {
                Some(GrowthFate::StaysOpen) => {
                    // The window overrides hysteresis, so the exit clock the
                    // reading may have started is meaningless -- leaving it
                    // running would let the first sample where the window
                    // falls silent inherit a hold that was never served, and
                    // close the incident without the quiet the hysteresis
                    // exists to require.
                    self.below_exit_since.remove(&key);
                    continue;
                }
                // Deliberately bypasses the exit-threshold hold: the shape of
                // half an hour is stronger evidence that the excursion is
                // over than a reading sitting under a threshold for one
                // sustained window, and holding the incident open past that
                // only delays a resolution everyone already agrees on. The
                // flap this hold normally guards against is instead bounded
                // by the quiet-period reopen -- a growth incident that comes
                // back within six hours resumes the same incident rather than
                // minting a new one, so churn costs occurrences, not alerts.
                Some(GrowthFate::AutoResolve) => {}
                Some(GrowthFate::Undecided) | None => {
                    if !self.condition_cleared(&key, &readings, system.timestamp_ms) {
                        continue;
                    }
                }
            }
            if let Some(mut alert) = self.active.remove(&key) {
                alert.resolved_at_ms = Some(system.timestamp_ms);
                alert.state = IncidentState::Resolved;
                if fate == Some(GrowthFate::AutoResolve) {
                    // Silent auto-resolve: the excursion is over, so there is
                    // nothing left to interrupt anyone about. The resolution
                    // row is still recorded -- history keeps the whole
                    // excursion, occurrence count included -- it just carries
                    // notify = false through the transition.
                    alert.notify = false;
                }
                self.resolved_memory.insert(
                    key.clone(),
                    ResolvedIncident {
                        id: alert.id.clone(),
                        resolved_at_ms: system.timestamp_ms,
                        first_seen_ms: alert.first_seen_ms,
                        occurrence_count: alert.occurrence_count,
                        notify_generation: alert.notify_generation,
                        severity: alert.severity,
                    },
                );
                resolved.push(alert);
            }
            if key == DPC_KEY {
                // Nothing left to renotify: a verdict change that never
                // reached a notification dies with the incident it described.
                self.pending_verdict_change = false;
            }
            self.guards.remove(&key);
            self.below_exit_since.remove(&key);
            self.streaks.remove(&key);
        }
        // Streaks survive for still-open incidents: a condition held open by
        // hysteresis must not have to re-earn its sustained window when its
        // value crosses back above the entry threshold. Their scoring terms
        // live and die with them.
        let active = &self.active;
        self.streaks
            .retain(|key, _| present.contains(key) || active.contains_key(key));
        self.calibrations
            .retain(|key, _| present.contains(key) || active.contains_key(key));
        // A notification is remembered for as long as the incident it belongs
        // to could still come back.
        self.notify_memory.retain(|key, memory| {
            active.contains_key(key) || system.timestamp_ms - memory.at_ms <= QUIET_PERIOD_MS
        });
        // Refresh the DPC incident's detector inputs even when no candidate
        // fired for it this sample, so a reading parked in the hysteresis
        // band cannot freeze a stale attribution (or a stale veto) into the
        // scoring pass indefinitely.
        if self.active.contains_key(DPC_KEY) {
            self.calibrations
                .entry(DPC_KEY.to_string())
                .or_default()
                .quality = dpc_quality;
        }

        // Score every open incident and apply the notification policy. This
        // runs after reconciliation so an incident opened, updated, or held
        // open by hysteresis this sample is all scored the same way, and
        // before `changed` is built so storage and the snapshot carry the
        // decision rather than the state that preceded it.
        let default_window_ms =
            i64::from(settings.sustained_samples) * settings.sample_interval_ms as i64;
        let mut changed = Vec::new();
        for (key, alert) in &mut self.active {
            let terms = self.calibrations.get(key).copied().unwrap_or_default();
            let window_ms = terms.window_ms.unwrap_or(default_window_ms);
            let breach_since_ms = terms.breach_since_ms.unwrap_or(alert.first_seen_ms);
            let notified = self.notify_memory.get(key).copied();
            let quality = score(&QualityInputs {
                alert,
                sustained_window_ms: window_ms,
                breach_duration_ms: system.timestamp_ms - breach_since_ms,
                baseline_maturity: calibration.baseline_maturity,
                // Detector-supplied, carried here from the candidate that
                // last fired for this incident. A detector with nothing to
                // say leaves an unknown attribution (which scores neutral)
                // and two honestly empty signal counts.
                attribution_stable: terms.quality.attribution_stable,
                corroborating_signals: terms.quality.corroborating_signals,
                user_impact_signals: terms.quality.user_impact_signals,
                notified_before: notified.is_some(),
                last_notified_ms: notified.map(|memory| memory.at_ms),
            });
            // A confident DPC verdict change may have arrived on a sample
            // with no candidate to carry it, so the latch is redeemed here,
            // at a pass that actually scores the incident.
            let pending_change = key.as_str() == DPC_KEY && self.pending_verdict_change;
            let material_change = terms.material_change || pending_change;
            // A reopen has no active `previous` alert to escalate against
            // (a moment ago the incident was resolved, not open), so stand
            // in the severity it was remembered at before it resolved.
            let remembered = terms
                .reopened_from_severity
                .map(|severity| remembered_previous(severity, notified.is_some()));
            let decision = decide(
                alert,
                &quality,
                calibration.learning,
                remembered.as_ref().or_else(|| previous.get(key)),
                material_change,
            );
            // The detector's own bar, applied after the generic floors and
            // only ever downward.
            let decision = if terms.quality.notify {
                decision
            } else {
                NotifyDecision {
                    notify: false,
                    bump_generation: false,
                }
            };
            // The latch is spent only when the change is actually delivered.
            // Consuming it on any scored sample would eat the renotification
            // whenever the incident happened to be suppressed that sample --
            // by this detector's own veto, by the floors, or simply because
            // it was not notifying yet -- and the dedupe on
            // `last_verdict_change` means a standing verdict never re-latches.
            if pending_change && decision.bump_generation {
                self.pending_verdict_change = false;
            }
            let before = (alert.quality, alert.notify, alert.notify_generation);
            alert.quality = quality;
            alert.notify = decision.notify;
            if decision.bump_generation {
                alert.notify_generation = alert.notify_generation.saturating_add(1);
            }
            if decision.notify {
                // Consumed: this incident has now actually been scored
                // against its pre-reopen severity, whether or not that
                // produced a bump. Later samples compare against its own
                // ongoing state like any other open incident, so a genuine
                // escalation cannot bump the generation more than once.
                if let Some(entry) = self.calibrations.get_mut(key) {
                    entry.reopened_from_severity = None;
                }
            }
            if decision.notify
                && notified.is_none_or(|memory| memory.generation != alert.notify_generation)
            {
                self.notify_memory.insert(
                    key.clone(),
                    NotifyMemory {
                        generation: alert.notify_generation,
                        at_ms: system.timestamp_ms,
                    },
                );
            }
            if touched.contains(key)
                || before != (alert.quality, alert.notify, alert.notify_generation)
            {
                changed.push(alert.clone());
            }
        }
        // The flag describes one sample's candidate, not a standing state.
        for terms in self.calibrations.values_mut() {
            terms.material_change = false;
        }
        changed.extend(resolved);

        for process in processes {
            let identity = (process.pid, process.started_at_ms);
            let baseline = self.baselines.entry(identity).or_default();
            baseline.cpu.observe(process.cpu_percent);
            baseline
                .working_set
                .observe(process.working_set_bytes as f64);
            baseline.handles.observe(process.handle_count as f64);
            baseline.threads.observe(process.thread_count as f64);
            baseline
                .io_rate
                .observe((process.read_bytes_per_sec + process.write_bytes_per_sec) / MIB);
        }
        self.pool_baseline.observe(pool_total);
        self.baselines.retain(|key, _| live_keys.contains(key));
        self.history.retain(|key, _| live_keys.contains(key));
        self.growth_history.retain(|key, _| live_keys.contains(key));
        // A monotonic run belongs to a window; when the window goes, so does
        // the run, or an exited process would leave its climb behind forever.
        self.monotonic_since
            .retain(|key, _| watched_growth_keys.contains(key));

        let mut active: Vec<Alert> = self.active.values().cloned().collect();
        active.sort_by_key(|alert| std::cmp::Reverse(alert.first_seen_ms));
        Evaluation { active, changed }
    }

    /// Whether an incident whose candidate is absent this sample may close.
    ///
    /// Value-shaped detectors have to clear hysteresis first: the reading
    /// must sit below the exit threshold (85% of the entry threshold) for a
    /// full sustained window, so a value oscillating across the entry
    /// threshold cannot flap the incident. Event-shaped detectors -- and any
    /// detector whose subject has vanished, such as an exited process --
    /// supply no reading and resolve on absence exactly as they always have.
    fn condition_cleared(
        &mut self,
        key: &str,
        readings: &HashMap<String, f64>,
        now_ms: i64,
    ) -> bool {
        let (Some(guard), Some(value)) = (self.guards.get(key).copied(), readings.get(key)) else {
            return true;
        };
        if *value >= guard.exit_threshold {
            self.below_exit_since.remove(key);
            return false;
        }
        let since = *self
            .below_exit_since
            .entry(key.to_string())
            .or_insert(now_ms);
        now_ms - since >= guard.hold_ms
    }

    /// Process instances whose samples the caller must keep out of their own
    /// executable name's learned baseline, as of the last evaluation.
    ///
    /// **The predicate is not "confirmed leak".** It is: this instance holds a
    /// growth window whose shape has been `Monotonic` for an unbroken thirty
    /// minutes. No alert need ever have been raised. A process creeping upward
    /// at half its threshold raises nothing -- the raw gate never trips -- and
    /// still freezes its name's norm for as long as the creep holds its shape,
    /// which for a genuine slow creeper is indefinitely. The consequence is
    /// that the norm stays at the creeper's *pre-creep* level rather than
    /// following it up, so later instances of that name are judged against a
    /// low bar and fire more readily. That is the permissive direction, and it
    /// is the direction this detector should fail in, so the broad predicate
    /// stays; requiring an open incident instead would create a worse loop,
    /// where a name poisoned high enough to block its own detection would then
    /// never qualify to stop being poisoned.
    ///
    /// **What this actually buys, precisely.** It stops *further* teaching
    /// once the thirty-minute mark passes. It does not undo what the ramp
    /// taught before then, and that is a real quantity: a leak spends its
    /// whole pre-confirmation ramp folding rising readings into the norm, so
    /// by the time the quarantine engages the norm has already been dragged
    /// most of the way to wherever the leak had got to. The current instance
    /// does not care -- it is judged against [`GrowthWindow::norm`], snapshotted
    /// before any of that happened -- but a *second* instance of the same
    /// executable starting afterwards inherits the dragged norm and is
    /// correspondingly slower to be judged abnormal, by an amount that scales
    /// with how long the first instance took to confirm.
    ///
    /// So: cross-instance protection during the ramp is a **known gap**, not a
    /// delivered property. Closing it means deferring the decision instead of
    /// making it live -- buffering an excursion's observations and folding
    /// them in only once the excursion ends, keeping them if it turned out to
    /// be a burst and dropping them if it turned out to be a leak. That is
    /// tracked as follow-up work rather than done here.
    ///
    /// Scoped this way rather than to everything on the growth watch list on
    /// purpose, and the reason is load-bearing: withholding every watched
    /// sample starves the baseline of exactly the observations it needs. A
    /// routinely bursty process is on the watch list precisely while it
    /// bursts, so its peaks are never learned and its norm collapses to its
    /// idle level -- measured at 303 against an 800 peak -- after which every
    /// future burst looks abnormal. That variant was implemented and fails
    /// `a_bursty_process_still_learns_its_own_norm_while_being_judged_by_it`.
    ///
    /// Other instances of the same executable keep contributing throughout.
    pub fn self_training_quarantine(&self) -> &HashSet<(u32, i64)> {
        &self.quarantine
    }

    pub fn acknowledge(&mut self, id: &str) -> Option<Alert> {
        let alert = self.active.values_mut().find(|alert| alert.id == id)?;
        alert.acknowledged = true;
        Some(alert.clone())
    }

    /// Set or clear the archive flag on a still-active alert, mirroring
    /// [`Self::acknowledge`]. Keeping the flag on the engine's copy means
    /// every later evaluation writes it back through `changed`, so an
    /// archived active finding stays archived while it keeps updating.
    pub fn set_archived(&mut self, id: &str, archived: bool) -> Option<Alert> {
        let alert = self.active.values_mut().find(|alert| alert.id == id)?;
        alert.archived = archived;
        Some(alert.clone())
    }
}

/// The window `classify_trend` must see before it will call a shape at all
/// for `collectorGrowth`, matching the spec's "persist >= 30 minutes"
/// requirement -- a shorter apparent trend is noise, not a leak.
const COLLECTOR_GROWTH_WINDOW_MS: i64 = 30 * 60_000;
/// Minimum absolute working-set movement for a `Monotonic` or still-elevated
/// `PartialRelease` shape to count as a real trend rather than sampling
/// jitter in the collector's own working set.
const COLLECTOR_GROWTH_MIN_BYTES: f64 = MIB;

/// Classify the collector's own working-set trend over its rolling
/// 30-minute buffer and band it into a severity. `Monotonic` growth (or a
/// `PartialRelease` that is still mostly stuck, per `stats::classify_trend`'s
/// contract) is a live trend: Warning. `Plateau` or `Returning` -- grew,
/// then leveled off or gave most of it back -- is recorded for visibility
/// but is not an active leak: Info, and (being event-shaped, like every
/// other candidate here) eligible to resolve the moment neither the
/// candidate nor the hysteresis hold applies. Anything else (not enough
/// span or data, or a real trend too small to matter) raises nothing.
fn collector_growth_shape(points: &[TrendPoint]) -> Option<(Severity, CollectorGrowth)> {
    if points.len() < 6 {
        return None;
    }
    let first_ms = points.iter().map(|point| point.at_ms).min()?;
    let last_ms = points.iter().map(|point| point.at_ms).max()?;
    let span_ms = last_ms.saturating_sub(first_ms);
    let third = span_ms / 3;
    let first_end = first_ms + third;
    let middle_end = first_ms + 2 * third;
    let (first_mean, first_samples) = trend_mean(points, None, first_end);
    let (middle_mean, middle_samples) = trend_mean(points, Some(first_end), middle_end);
    let (last_mean, last_samples) = trend_mean(points, Some(middle_end), last_ms);
    if [first_samples, middle_samples, last_samples]
        .into_iter()
        .any(|samples| samples < 5)
    {
        return None;
    }

    let shape = classify_trend(points, COLLECTOR_GROWTH_WINDOW_MS, MIB / 4.0);
    let (severity, growth_bytes) = match shape {
        TrendShape::Monotonic { total_growth } if total_growth >= COLLECTOR_GROWTH_MIN_BYTES => {
            (Severity::Warning, total_growth)
        }
        TrendShape::PartialRelease { remaining } if remaining >= COLLECTOR_GROWTH_MIN_BYTES => {
            // Still mostly stuck per `classify_trend`'s own contract (see
            // `stats::RETURNING_TOLERANCE_FRACTION`): a live trend, not a
            // resolved excursion.
            (Severity::Warning, remaining)
        }
        TrendShape::Plateau | TrendShape::Returning => (Severity::Info, last_mean - first_mean),
        _ => return None,
    };

    Some((
        severity,
        CollectorGrowth {
            growth_mb: growth_bytes / MIB,
            first_mean_mb: first_mean / MIB,
            middle_mean_mb: middle_mean / MIB,
            last_mean_mb: last_mean / MIB,
            window_seconds: span_ms as f64 / 1_000.0,
        },
    ))
}

/// Mean of the points whose timestamp falls in `(from_exclusive, to_inclusive]`,
/// mirroring `stats::classify_trend`'s own internal segment split so the
/// evidence reports exactly the windows the shape decision was made from.
fn trend_mean(
    points: &[TrendPoint],
    from_exclusive: Option<i64>,
    to_inclusive: i64,
) -> (f64, usize) {
    let mut sum = 0.0;
    let mut count = 0usize;
    for point in points {
        let after_start = from_exclusive.is_none_or(|from| point.at_ms > from);
        if after_start && point.at_ms <= to_inclusive {
            sum += point.value;
            count += 1;
        }
    }
    if count == 0 {
        (0.0, 0)
    } else {
        (sum / count as f64, count)
    }
}

/// Classify the long growth window on one of its two dimensions.
///
/// Known limitation of the seeding in [`AlertEngine::evaluate`]: the window is
/// seeded from the five-minute ring at watch entry, so if the climb was
/// already underway when the window opened, its first points are climb rather
/// than baseline. That biases the first third upward, which makes a full
/// release read as a `PartialRelease` for a little longer than it should --
/// erring toward keeping an incident open, never toward closing one early.
/// The bias is bounded by the seed length (five minutes) and disappears
/// entirely once the window has run its full thirty.
fn growth_shape(
    window: &VecDeque<GrowthPoint>,
    value: impl Fn(&GrowthPoint) -> f64,
    min_step: f64,
) -> TrendShape {
    let points: Vec<TrendPoint> = window
        .iter()
        .map(|point| TrendPoint {
            at_ms: point.timestamp_ms,
            value: value(point),
        })
        .collect();
    classify_trend(&points, GROWTH_MIN_SPAN_MS, min_step)
}

/// The per-segment step the shape test uses for a detector whose entry
/// threshold is `threshold`. Floored at one whole handle or thread, because
/// these are counts: a step below one can never be cleared, which would make
/// every series `Inconclusive`.
fn growth_step(threshold: u32) -> f64 {
    (f64::from(threshold) * GROWTH_STEP_FRACTION).max(1.0)
}

/// How long a growth key's current monotonic run has lasted.
fn monotonic_run_ms(since: Option<&i64>, now_ms: i64) -> i64 {
    since.map_or(0, |since| (now_ms - since).max(0))
}

/// A climb is only worth interrupting someone about once it has held its
/// shape for the spec's thirty minutes of growth persistence. Before that it
/// is recorded at `Info` -- the same history-only band the collector budget
/// uses inside its tolerance band -- because for the first half hour a leak
/// and a burst are the same picture, and bursts are the common one.
///
/// A climb that pauses long enough to break its monotonic run and then
/// resumes drops back to `Info` and later climbs to `Warning` again. That
/// second escalation deliberately does *not* re-pop the tray: the policy only
/// bumps a notification generation for an incident that was already
/// notifying, and an `Info` incident never is. One leak stays one
/// notification however many times its shape stutters.
fn growth_severity(monotonic_run_ms: i64) -> Severity {
    if monotonic_run_ms >= GROWTH_PERSISTENCE_MS {
        Severity::Warning
    } else {
        Severity::Info
    }
}

/// Whether a process's reading stands out against `norm` -- the learned norm
/// for processes of its name at its age, snapshotted when its excursion began
/// (see [`GrowthWindow::norm`]).
///
/// The gate passes open in three cases, all of them "we have nothing to
/// compare against": no baseline store at all, a name the store had never
/// seen, and -- through `RunningStats::deviates` -- a bucket with fewer than
/// fifteen observations. That last one is the existing young-process
/// convention, reused deliberately: a norm learned from a handful of samples
/// is not a norm, and suppressing a finding on the strength of one would be
/// worse than the false positive it saves.
fn name_baseline_admits(
    norm: Option<&AgeBucketStats>,
    pick: impl Fn(&AgeBucketStats) -> &RunningStats,
    value: f64,
    sigma: f64,
    minimum_delta: f64,
) -> bool {
    norm.is_none_or(|stats| pick(stats).deviates(value, sigma, minimum_delta))
}

/// A raw growth delta as a fraction of the threshold it is measured against.
/// A zero threshold cannot be exceeded by proportion, so any growth at all
/// counts as fully breaching.
fn threshold_fraction(growth: u32, threshold: u32) -> f64 {
    if threshold > 0 {
        f64::from(growth) / f64::from(threshold)
    } else if growth > 0 {
        f64::INFINITY
    } else {
        0.0
    }
}

/// Make room for a newcomer pushing at `pressure` by dropping the weakest
/// window currently held.
///
/// Without this the cap is a denial-of-service on the detector itself: thirty-
/// two processes drifting upward at a quarter of their thresholds would hold
/// every slot indefinitely, and a real leak arriving afterwards would get no
/// window, no shape, and so never be detected at all -- silently.
///
/// Windows belonging to an open growth incident are never evicted. Among the
/// rest the weakest goes, and a newcomer that is actually breaching its
/// threshold (`pressure >= 1.0`) displaces the weakest even if that window is
/// pushing just as hard: an actual breach outranks a drift. If every slot is
/// held by an open incident there is nothing to give, which is the one case
/// where the newcomer waits -- thirty-two concurrent growth incidents is a
/// machine with larger problems than this detector.
fn evict_weakest_growth_window(windows: &mut HashMap<(u32, i64), GrowthWindow>, pressure: f64) {
    let weakest = windows
        .iter()
        .filter(|(_, window)| !window.protected)
        .min_by(|left, right| left.1.pressure.total_cmp(&right.1.pressure))
        .map(|(identity, window)| (*identity, window.pressure));
    if let Some((identity, weakest_pressure)) = weakest
        && (weakest_pressure < pressure || pressure >= 1.0)
    {
        windows.remove(&identity);
    }
}

/// The engine key (and so the alert fingerprint) for a per-process detector.
fn process_key(kind: &str, process: &ProcessMetric) -> String {
    format!("{kind}:{}:{}", process.pid, process.started_at_ms)
}

/// How far a reading sits above its own threshold, for detectors whose
/// incident spans several dimensions. A zero threshold cannot be exceeded by
/// proportion, so any positive reading counts as fully breached.
fn ratio(value: f64, threshold: f64) -> f64 {
    if threshold > 0.0 {
        value / threshold
    } else if value > 0.0 {
        f64::INFINITY
    } else {
        0.0
    }
}

/// Fraction of the collector budget ceiling a reading must clear before the
/// band counts as a genuine overage rather than a hairline crossing.
const COLLECTOR_BUDGET_WARNING_BAND: f64 = 1.15;
/// Fraction of the ceiling at which a collector budget overage is Critical
/// regardless of how long it has run.
const COLLECTOR_BUDGET_CRITICAL_BAND: f64 = 2.0;
/// How long a reading may sit at the bare ceiling (below the 1.15x band)
/// before the alternate entry path escalates it to Warning anyway. A single
/// hairline crossing must stay Info; a reading stuck there for this long is
/// no longer a hairline.
const COLLECTOR_BUDGET_CONTINUOUS_WARNING_MS: i64 = 10 * 60_000;

/// Bands a collector budget reading (already normalized to a ratio of its
/// ceiling, 1.0 = the ceiling itself) into a severity. `[1.0, 1.15)` is
/// in-band: Info, history-only, and never escalates on ratio alone. Above
/// the band and below double the ceiling is Warning; at or past double is
/// Critical outright. The alternate path: a reading that never crosses 1.15x
/// but has sat at or above the bare ceiling continuously for ten minutes
/// still escalates to Warning -- a stuck low-grade overage should not go
/// unflagged forever, even though a momentary hairline crossing must stay
/// Info (see `a_hairline_ceiling_crossing_is_informational_never_critical`).
fn collector_budget_severity(worst_ratio: f64, continuous_breach_ms: i64) -> Severity {
    if worst_ratio >= COLLECTOR_BUDGET_CRITICAL_BAND {
        Severity::Critical
    } else if worst_ratio >= COLLECTOR_BUDGET_WARNING_BAND
        || continuous_breach_ms >= COLLECTOR_BUDGET_CONTINUOUS_WARNING_MS
    {
        Severity::Warning
    } else {
        Severity::Info
    }
}

/// A stand-in `previous` for [`quality::decide`]'s escalation check when the
/// real "previous" is not an active alert but a resolved incident's
/// remembered state (a reopen). `decide` only reads `.severity` and
/// `.notify` off of `previous`, so every other field here is an unused
/// placeholder -- this value is never stored or surfaced anywhere.
fn remembered_previous(severity: Severity, notified: bool) -> Alert {
    Alert {
        id: String::new(),
        kind: String::new(),
        severity,
        first_seen_ms: 0,
        last_seen_ms: 0,
        process_id: None,
        process_name: None,
        title: String::new(),
        explanation: String::new(),
        evidence: Vec::new(),
        recommendation: String::new(),
        acknowledged: false,
        occurrence_count: 0,
        resolved_at_ms: None,
        archived: false,
        fingerprint: String::new(),
        state: IncidentState::Resolved,
        quality: AlertQuality::default(),
        notify: notified,
        notify_generation: 0,
    }
}

#[allow(clippy::too_many_arguments)]
fn process_candidate(
    process: &ProcessMetric,
    kind: &'static str,
    severity: Severity,
    required_samples: u32,
    title: &str,
    explanation: String,
    evidence: Vec<Evidence>,
    recommendation: &str,
) -> Candidate {
    Candidate {
        key: process_key(kind, process),
        kind,
        severity,
        required_samples,
        pid: Some(process.pid),
        process_name: Some(process.name.clone()),
        title: title.into(),
        explanation,
        evidence,
        recommendation: recommendation.into(),
        // Event-shaped unless a caller supplies an entry threshold with
        // `Candidate::with_entry`.
        entry: None,
        exit_ratio: EXIT_RATIO,
        // Per-process detectors have no attribution machinery and no veto of
        // their own; the DPC detector builds its candidate by hand.
        material_change: false,
        quality: CandidateQuality::default(),
    }
}

fn evidence(label: impl Into<String>, value: impl Into<String>) -> Evidence {
    Evidence {
        label: label.into(),
        value: value.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::baselines::BaselineStore;
    use crate::models::IncidentState;
    use crate::quality::{CONFIDENCE_FLOOR, PERSISTENCE_FLOOR};

    fn process(timestamp_ms: i64, cpu: f64, memory_mb: u64) -> ProcessMetric {
        ProcessMetric {
            timestamp_ms,
            pid: 42,
            parent_pid: 4,
            name: "worker.exe".into(),
            executable_path: String::new(),
            cpu_percent: cpu,
            working_set_bytes: memory_mb * 1024 * 1024,
            private_bytes: memory_mb * 1024 * 1024,
            handle_count: 20,
            thread_count: 4,
            read_bytes_per_sec: 0.0,
            write_bytes_per_sec: 0.0,
            total_read_bytes: 0,
            total_write_bytes: 0,
            started_at_ms: 1,
            session_id: 1,
            responsive: true,
            has_visible_window: false,
            launch_duration_ms: None,
            is_agent_candidate: false,
        }
    }

    fn collector_process(
        timestamp_ms: i64,
        started_at_ms: i64,
        cpu: f64,
        working_set_bytes: u64,
        handles: u32,
    ) -> ProcessMetric {
        let mut value = process(timestamp_ms, cpu, 1);
        value.pid = std::process::id();
        value.name = "PcPulse.Service.exe".into();
        value.started_at_ms = started_at_ms;
        value.working_set_bytes = working_set_bytes;
        value.private_bytes = working_set_bytes;
        value.handle_count = handles;
        value
    }

    #[test]
    fn collector_cpu_ceiling_follows_the_configured_setting() {
        // 1% CPU breaches the 0.2% default but not a raised 5% ceiling —
        // the budget alert must track settings.collector_cpu_percent, while
        // the memory and handle budgets stay fixed.
        let run = |ceiling: f64| {
            let mut engine = AlertEngine::default();
            let settings = Settings {
                sustained_samples: 2,
                collector_cpu_percent: ceiling,
                ..Settings::default()
            };
            let mut system = SystemMetric::default();
            for index in 0..7 {
                system.timestamp_ms = 20 * 60_000 + index * 2_000;
                engine.evaluate(
                    &system,
                    &[collector_process(
                        system.timestamp_ms,
                        0,
                        1.0,
                        16 << 20,
                        200,
                    )],
                    &settings,
                    Calibration::default(),
                );
            }
            engine
                .active
                .values()
                .any(|alert| alert.kind == "collectorBudget")
        };
        assert!(run(0.2), "1% CPU must breach the 0.2% default ceiling");
        assert!(!run(5.0), "1% CPU must not breach a raised 5% ceiling");

        let raised = Settings {
            collector_cpu_percent: 5.0,
            ..Settings::default()
        };
        let evidence_uses_setting = {
            let mut engine = AlertEngine::default();
            let mut system = SystemMetric::default();
            // Memory over its fixed 25 MB budget keeps the finding alive so
            // the CPU evidence row's denominator can be read.
            for index in 0..7 {
                system.timestamp_ms = 20 * 60_000 + index * 2_000;
                engine.evaluate(
                    &system,
                    &[collector_process(
                        system.timestamp_ms,
                        0,
                        1.0,
                        40 << 20,
                        200,
                    )],
                    &raised,
                    Calibration::default(),
                );
            }
            engine
                .active
                .values()
                .find(|alert| alert.kind == "collectorBudget")
                .and_then(|alert| {
                    alert
                        .evidence
                        .iter()
                        .find(|row| row.label == "CPU")
                        .map(|row| row.value.clone())
                })
                .unwrap_or_default()
        };
        assert!(
            evidence_uses_setting.contains("/ 5%"),
            "CPU evidence must show the configured ceiling: {evidence_uses_setting}"
        );
    }

    #[test]
    fn one_cpu_spike_does_not_alert() {
        let mut engine = AlertEngine::default();
        let settings = Settings {
            sustained_samples: 3,
            ..Settings::default()
        };
        let system = SystemMetric {
            timestamp_ms: 1_000,
            ..SystemMetric::default()
        };
        let evaluation = engine.evaluate(
            &system,
            &[process(1_000, 99.0, 20)],
            &settings,
            Calibration::default(),
        );
        assert!(evaluation.active.is_empty());
    }

    #[test]
    fn sustained_cpu_creates_and_resolution_closes_alert() {
        let mut engine = AlertEngine::default();
        let settings = Settings {
            sustained_samples: 3,
            ..Settings::default()
        };
        let mut system = SystemMetric::default();
        for index in 0..3 {
            system.timestamp_ms = index * 2_000;
            engine.evaluate(
                &system,
                &[process(system.timestamp_ms, 95.0, 20)],
                &settings,
                Calibration::default(),
            );
        }
        assert_eq!(engine.active.len(), 1);
        // Recovery clears the exit threshold immediately, but the finding
        // still has to hold for one full sustained window (3 x 2 s) before it
        // closes -- see `resolution_requires_the_exit_threshold_and_hold_window`.
        let mut resolved = None;
        for _ in 0..4 {
            system.timestamp_ms += 2_000;
            let evaluation = engine.evaluate(
                &system,
                &[process(system.timestamp_ms, 1.0, 20)],
                &settings,
                Calibration::default(),
            );
            resolved = resolved.or_else(|| {
                evaluation
                    .changed
                    .iter()
                    .find(|alert| alert.resolved_at_ms.is_some())
                    .cloned()
                    .map(|alert| (alert, evaluation.active.clone()))
            });
        }
        let (alert, active_at_resolution) = resolved.expect("the quiet condition closes the alert");
        assert!(active_at_resolution.is_empty());
        assert_eq!(alert.state, IncidentState::Resolved);
    }

    #[test]
    fn archived_flag_rides_every_later_update_of_an_active_finding() {
        let mut engine = AlertEngine::default();
        let settings = Settings {
            sustained_samples: 3,
            ..Settings::default()
        };
        let mut system = SystemMetric::default();
        for index in 0..3 {
            system.timestamp_ms = index * 2_000;
            engine.evaluate(
                &system,
                &[process(system.timestamp_ms, 95.0, 20)],
                &settings,
                Calibration::default(),
            );
        }
        let id = engine.active.values().next().unwrap().id.clone();
        let archived = engine.set_archived(&id, true).expect("active finding");
        assert!(archived.archived);
        assert!(engine.set_archived("unknown", true).is_none());

        // The condition persists: the next evaluation's changed record (the
        // one that reaches storage) must still carry the flag.
        system.timestamp_ms += 2_000;
        let evaluation = engine.evaluate(
            &system,
            &[process(system.timestamp_ms, 95.0, 20)],
            &settings,
            Calibration::default(),
        );
        let updated = evaluation
            .changed
            .iter()
            .find(|alert| alert.id == id)
            .expect("updated finding");
        assert!(updated.archived, "archive must survive detector updates");
        assert!(evaluation.active.iter().any(|alert| alert.archived));

        // Recovery clears it the same way.
        assert!(!engine.set_archived(&id, false).unwrap().archived);
    }

    #[test]
    fn collector_startup_settling_does_not_raise_a_budget_alert() {
        let mut engine = AlertEngine::default();
        let settings = Settings {
            sustained_samples: 2,
            ..Settings::default()
        };
        let mut system = SystemMetric::default();
        for index in 0..50 {
            system.timestamp_ms = index * 2_000;
            let working_set = 18 * 1024 * 1024 + index as u64 * 40 * 1024;
            engine.evaluate(
                &system,
                &[collector_process(
                    system.timestamp_ms,
                    0,
                    0.05,
                    working_set,
                    210,
                )],
                &settings,
                Calibration::default(),
            );
        }
        assert!(
            engine
                .active
                .values()
                .all(|alert| !alert.kind.starts_with("collector"))
        );
    }

    #[test]
    fn collector_critical_evidence_leads_with_the_actual_breach() {
        // Calibration banding (Task 7) means a ratio has to clear 2x the
        // ceiling to read Critical -- 0.25% against the 0.2% default ceiling
        // is only 1.25x (in the Warning band), so this fixture was bumped
        // to 0.5% (2.5x) to keep exercising the Critical evidence-ordering
        // path this test is actually about.
        let mut engine = AlertEngine::default();
        let settings = Settings {
            sustained_samples: 2,
            ..Settings::default()
        };
        let mut system = SystemMetric::default();
        for index in 0..5 {
            system.timestamp_ms = 20 * 60_000 + index * 2_000;
            engine.evaluate(
                &system,
                &[collector_process(
                    system.timestamp_ms,
                    0,
                    0.5,
                    20 * 1024 * 1024,
                    210,
                )],
                &settings,
                Calibration::default(),
            );
        }
        let alert = engine
            .active
            .values()
            .find(|alert| alert.kind == "collectorBudget")
            .expect("collector budget alert");
        assert_eq!(alert.severity, Severity::Critical);
        assert_eq!(alert.evidence[0].label, "Breached budget");
        assert!(alert.evidence[0].value.starts_with("CPU"));
        assert!(!alert.evidence[0].value.contains("Working set"));
    }

    #[test]
    fn mature_continuous_collector_growth_is_a_warning() {
        // Calibration (Task 7) moved `collectorGrowth` to a genuine
        // 30-minute `classify_trend` window, so this fixture was extended
        // from ~5 minutes to just past 30 minutes of steady linear growth
        // (still well under the 25 MB budget ceiling, so it does not also
        // trip `collectorBudget`).
        let mut engine = AlertEngine::default();
        let settings = Settings {
            sustained_samples: 2,
            ..Settings::default()
        };
        let mut system = SystemMetric::default();
        for index in 0..950 {
            system.timestamp_ms = 10 * 60_000 + index * 2_000;
            let working_set = 18 * 1024 * 1024 + index as u64 * 4 * 1024;
            engine.evaluate(
                &system,
                &[collector_process(
                    system.timestamp_ms,
                    0,
                    0.05,
                    working_set,
                    210,
                )],
                &settings,
                Calibration::default(),
            );
        }
        let alert = engine
            .active
            .values()
            .find(|alert| alert.kind == "collectorGrowth")
            .expect("collector growth warning");
        assert_eq!(alert.severity, Severity::Warning);
        assert_eq!(alert.evidence[0].label, "Sustained growth");
        assert!(
            engine
                .active
                .values()
                .all(|alert| alert.kind != "collectorBudget")
        );
    }

    #[test]
    fn disk_latency_owner_churn_does_not_split_the_incident() {
        // Carried assignment: the diskLatency key used to embed the top-I/O
        // owner's pid, so owner churn (a different process becomes the
        // busiest reader/writer each sample) resolved-and-split the
        // incident and defeated hysteresis entirely (confirmed by probe).
        // The fingerprint is now the fixed string "diskLatency", matching
        // `dpcInterrupt`'s pattern -- one incident per latency condition
        // regardless of attribution churn.
        let mut engine = AlertEngine::default();
        let settings = Settings {
            sustained_samples: 2,
            ..Settings::default()
        };
        let mut system = SystemMetric {
            disk_latency_ms: 999.0,
            ..SystemMetric::default()
        };
        let mut ids: HashSet<String> = HashSet::new();
        for index in 0..20 {
            system.timestamp_ms = index * 2_000;
            // Alternate which process is the busiest I/O owner every sample.
            let mut a = process(system.timestamp_ms, 1.0, 20);
            a.pid = 100;
            a.name = "reader.exe".into();
            let mut b = process(system.timestamp_ms, 1.0, 20);
            b.pid = 200;
            b.name = "writer.exe".into();
            if index % 2 == 0 {
                a.read_bytes_per_sec = 50.0 * MIB;
                b.read_bytes_per_sec = 1.0 * MIB;
            } else {
                a.read_bytes_per_sec = 1.0 * MIB;
                b.read_bytes_per_sec = 50.0 * MIB;
            }
            let evaluation = engine.evaluate(&system, &[a, b], &settings, Calibration::default());
            for alert in evaluation
                .active
                .iter()
                .filter(|alert| alert.kind == "diskLatency")
            {
                ids.insert(alert.id.clone());
            }
        }
        assert_eq!(
            ids.len(),
            1,
            "owner churn must not resolve-and-split the incident: {ids:?}"
        );
    }

    #[test]
    fn a_hairline_ceiling_crossing_is_informational_never_critical() {
        // The Lenovo field case: ceiling 0.75%, observed 0.769% (in-band).
        // Sustained for many samples: alert exists at Info, notify == false,
        // severity never reaches Critical; telemetry recorded (alert present
        // in evaluation output).
        let mut engine = AlertEngine::default();
        let settings = Settings {
            sustained_samples: 2,
            collector_cpu_percent: 0.75,
            ..Settings::default()
        };
        let mut system = SystemMetric::default();
        let mut severities = Vec::new();
        // Two minutes -- comfortably under the ten-minute alternate entry
        // path, so only the ratio band is under test here.
        for index in 0..60 {
            system.timestamp_ms = 20 * 60_000 + index * 2_000;
            let evaluation = engine.evaluate(
                &system,
                &[collector_process(
                    system.timestamp_ms,
                    0,
                    0.769,
                    16 << 20,
                    200,
                )],
                &settings,
                Calibration::default(),
            );
            if let Some(alert) = evaluation
                .active
                .iter()
                .find(|alert| alert.kind == "collectorBudget")
            {
                assert!(!alert.notify, "an in-band crossing must never notify");
                severities.push(alert.severity);
            }
        }
        assert!(
            !severities.is_empty(),
            "the crossing must be recorded in evaluation output"
        );
        assert!(
            severities
                .iter()
                .all(|&severity| severity == Severity::Info),
            "must stay Info throughout, never Critical: {severities:?}"
        );
    }

    #[test]
    fn the_band_and_double_ceiling_set_severity() {
        // 0.9% vs 0.75 ceiling (>=1.15x) sustained => Warning.
        // 1.6% vs 0.75 ceiling (>=2x) sustained => Critical.
        let severity_at = |cpu: f64| {
            let mut engine = AlertEngine::default();
            let settings = Settings {
                sustained_samples: 2,
                collector_cpu_percent: 0.75,
                ..Settings::default()
            };
            let mut system = SystemMetric::default();
            for index in 0..5 {
                system.timestamp_ms = 20 * 60_000 + index * 2_000;
                engine.evaluate(
                    &system,
                    &[collector_process(
                        system.timestamp_ms,
                        0,
                        cpu,
                        16 << 20,
                        200,
                    )],
                    &settings,
                    Calibration::default(),
                );
            }
            engine
                .active
                .values()
                .find(|alert| alert.kind == "collectorBudget")
                .map(|alert| alert.severity)
        };
        assert_eq!(severity_at(0.9), Some(Severity::Warning));
        assert_eq!(severity_at(1.6), Some(Severity::Critical));
    }

    #[test]
    fn a_stuck_bare_ceiling_reading_upgrades_to_warning_after_ten_minutes() {
        // The alternate entry path: a reading that never crosses the 1.15x
        // band but has sat at or above the bare ceiling continuously for ten
        // minutes still escalates to Warning -- a stuck low-grade overage
        // must not go unflagged forever, even though the same in-band ratio
        // held only briefly (see the Lenovo case above) must stay Info.
        let mut engine = AlertEngine::default();
        let settings = Settings {
            sustained_samples: 2,
            collector_cpu_percent: 0.75,
            ..Settings::default()
        };
        let mut system = SystemMetric::default();
        let mut severities = Vec::new();
        // Eleven minutes: past the ten-minute alternate-path threshold.
        for index in 0..340 {
            system.timestamp_ms = 20 * 60_000 + index * 2_000;
            let evaluation = engine.evaluate(
                &system,
                &[collector_process(
                    system.timestamp_ms,
                    0,
                    0.769,
                    16 << 20,
                    200,
                )],
                &settings,
                Calibration::default(),
            );
            if let Some(alert) = evaluation
                .active
                .iter()
                .find(|alert| alert.kind == "collectorBudget")
            {
                severities.push(alert.severity);
            }
        }
        assert_eq!(
            severities.first(),
            Some(&Severity::Info),
            "must start Info like any hairline crossing: {severities:?}"
        );
        assert_eq!(
            severities.last(),
            Some(&Severity::Warning),
            "a bare-ceiling reading stuck for ten minutes must escalate to Warning: {severities:?}"
        );
        assert!(
            severities
                .iter()
                .all(|&severity| severity != Severity::Critical),
            "the alternate path only reaches Warning, never Critical: {severities:?}"
        );
    }

    #[test]
    fn working_set_oscillation_in_the_steady_range_stays_informational() {
        // WS bouncing 11-16 MB for an hour: at most one incident, Info,
        // notify == false, no reopen churn (single id throughout).
        let mut engine = AlertEngine::default();
        let settings = Settings {
            sustained_samples: 2,
            ..Settings::default()
        };
        let mut system = SystemMetric::default();
        let mut ids: HashSet<String> = HashSet::new();
        // High-frequency oscillation (an 8-second period) so any 30-minute
        // trend window sees hundreds of complete cycles -- noise the shape
        // classifier must not mistake for a trend.
        for index in 0..1_800 {
            system.timestamp_ms = index * 2_000;
            let working_set: u64 = if index % 4 < 2 { 11 << 20 } else { 16 << 20 };
            let evaluation = engine.evaluate(
                &system,
                &[collector_process(
                    system.timestamp_ms,
                    0,
                    0.01,
                    working_set,
                    50,
                )],
                &settings,
                Calibration::default(),
            );
            for alert in evaluation
                .active
                .iter()
                .filter(|alert| alert.kind == "collectorGrowth" || alert.kind == "collectorBudget")
            {
                ids.insert(alert.id.clone());
                assert_eq!(
                    alert.severity,
                    Severity::Info,
                    "oscillation must never escalate: {alert:?}"
                );
                assert!(!alert.notify, "an Info incident must never notify");
            }
        }
        assert!(
            ids.len() <= 1,
            "no reopen churn: at most one incident id throughout the hour: {ids:?}"
        );
    }

    #[test]
    fn a_thirty_minute_monotonic_climb_upgrades_to_warning_once() {
        // Feed a genuine monotonic WS climb over 30+ min: Warning, notify
        // true exactly once (generation bumps once).
        let mut engine = AlertEngine::default();
        let settings = Settings {
            sustained_samples: 2,
            ..Settings::default()
        };
        let mut system = SystemMetric::default();
        let mut notify_flags = Vec::new();
        let mut severities = Vec::new();
        let mut generations = Vec::new();
        for index in 0..1_000 {
            system.timestamp_ms = 10 * 60_000 + index * 2_000;
            let working_set = 18 * 1024 * 1024 + index as u64 * 4 * 1024;
            let evaluation = engine.evaluate(
                &system,
                &[collector_process(
                    system.timestamp_ms,
                    0,
                    0.05,
                    working_set,
                    210,
                )],
                &settings,
                Calibration::default(),
            );
            if let Some(alert) = evaluation
                .active
                .iter()
                .find(|alert| alert.kind == "collectorGrowth")
            {
                notify_flags.push(alert.notify);
                severities.push(alert.severity);
                generations.push(alert.notify_generation);
            }
        }
        assert!(
            !severities.is_empty(),
            "the climb must eventually raise the incident"
        );
        assert!(
            severities
                .iter()
                .all(|&severity| severity == Severity::Warning),
            "growth must read Warning, never Info or Critical: {severities:?}"
        );
        // Exactly one rising edge: notify goes false -> true once and never
        // flaps back for the rest of the run.
        let mut rising_edges = 0;
        let mut previous = false;
        for &notify in &notify_flags {
            if notify && !previous {
                rising_edges += 1;
            }
            previous = notify;
        }
        assert_eq!(
            rising_edges, 1,
            "must become notify-worthy exactly once: {notify_flags:?}"
        );
        assert!(
            *notify_flags.last().unwrap(),
            "must still be notifying at the end of the climb"
        );
        // The generation that popped stays put once set: nothing escalates
        // past Warning here, so there is nothing left to bump again.
        let first_notify = notify_flags.iter().position(|&notify| notify).unwrap();
        let generation_after_pop = generations[first_notify];
        assert!(
            generations[first_notify..]
                .iter()
                .all(|&generation| generation == generation_after_pop),
            "the generation must not bump again while nothing escalates further: {generations:?}"
        );
    }

    #[test]
    fn a_reopen_at_a_higher_band_renotifies_with_a_generation_bump() {
        // Carried assignment: `ResolvedIncident` must carry severity so a
        // reopen at a higher band is detectable as an escalation. Resolve a
        // collectorBudget incident at Warning, then reopen it within the
        // quiet period at Critical (2x ceiling): same incident id, and the
        // escalation bumps notify_generation exactly once. This is the only
        // end-to-end escalation-on-reopen coverage in the codebase.
        let mut engine = AlertEngine::default();
        let settings = Settings {
            sustained_samples: 2,
            ..Settings::default()
        };
        let ceiling = settings.collector_cpu_percent;
        let mut system = SystemMetric::default();

        // Phase 1: open and notify at Warning (1.3x ceiling).
        let mut opened = None;
        for index in 0..15 {
            system.timestamp_ms = 20 * 60_000 + index * 2_000;
            let evaluation = engine.evaluate(
                &system,
                &[collector_process(
                    system.timestamp_ms,
                    0,
                    ceiling * 1.3,
                    1 << 20,
                    50,
                )],
                &settings,
                Calibration::default(),
            );
            if let Some(alert) = evaluation
                .active
                .iter()
                .find(|alert| alert.kind == "collectorBudget" && alert.notify)
            {
                opened = Some(alert.clone());
            }
        }
        let opened = opened.expect("the incident must actually notify at Warning before resolving");
        assert_eq!(opened.severity, Severity::Warning);
        let opened_generation = opened.notify_generation;

        // Phase 2: recover well under the exit ratio and hold for a full
        // sustained window to resolve.
        let mut resolved = None;
        for _ in 0..8 {
            system.timestamp_ms += 2_000;
            let evaluation = engine.evaluate(
                &system,
                &[collector_process(system.timestamp_ms, 0, 0.0, 1 << 20, 10)],
                &settings,
                Calibration::default(),
            );
            resolved = resolved.or_else(|| {
                evaluation
                    .changed
                    .iter()
                    .find(|alert| alert.kind == "collectorBudget" && alert.resolved_at_ms.is_some())
                    .cloned()
            });
        }
        let resolved = resolved.expect("the warning incident must resolve");
        assert_eq!(resolved.id, opened.id);
        assert_eq!(resolved.severity, Severity::Warning);
        assert_eq!(resolved.state, IncidentState::Resolved);
        assert!(
            engine
                .active
                .values()
                .all(|alert| alert.kind != "collectorBudget")
        );

        // Phase 3: reopen inside the quiet period at Critical (>= 2x ceiling).
        let mut reopened_id = None;
        let mut severities = Vec::new();
        let mut bumped_generation = None;
        for _ in 0..20 {
            system.timestamp_ms += 2_000;
            let evaluation = engine.evaluate(
                &system,
                &[collector_process(
                    system.timestamp_ms,
                    0,
                    ceiling * 2.5,
                    1 << 20,
                    50,
                )],
                &settings,
                Calibration::default(),
            );
            if let Some(alert) = evaluation
                .active
                .iter()
                .find(|alert| alert.kind == "collectorBudget")
            {
                reopened_id = Some(alert.id.clone());
                severities.push(alert.severity);
                if alert.notify && bumped_generation.is_none() {
                    bumped_generation = Some(alert.notify_generation);
                }
            }
        }
        assert_eq!(
            reopened_id,
            Some(opened.id.clone()),
            "a reopen inside the quiet period must reuse the same incident"
        );
        assert!(
            severities
                .iter()
                .all(|&severity| severity == Severity::Critical),
            "must read Critical throughout the reopen: {severities:?}"
        );
        let bumped_generation =
            bumped_generation.expect("the reopened incident must eventually notify");
        assert_eq!(
            bumped_generation,
            opened_generation + 1,
            "an escalation on reopen must bump the generation exactly once"
        );

        // The generation must not bump again on later samples.
        let final_alert = engine
            .active
            .values()
            .find(|alert| alert.kind == "collectorBudget")
            .expect("still open");
        assert_eq!(final_alert.notify_generation, bumped_generation);
    }

    /// A three-sample sustained window on the default 2 s interval, so the
    /// exit hold window (`sustained_samples × sample_interval_ms`) is 6 s
    /// and the entry threshold for CPU is the 80% default.
    fn lifecycle_settings() -> Settings {
        Settings {
            sustained_samples: 3,
            ..Settings::default()
        }
    }

    /// Drive `count` evaluations one sample interval apart from `start_ms`,
    /// feeding the single worker process at `cpu` percent, and return every
    /// evaluation in order.
    fn drive_cpu(
        engine: &mut AlertEngine,
        settings: &Settings,
        start_ms: i64,
        count: i64,
        cpu: f64,
    ) -> Vec<Evaluation> {
        drive_cpu_calibrated(
            engine,
            settings,
            start_ms,
            count,
            cpu,
            Calibration::default(),
        )
    }

    /// [`drive_cpu`] against a stated view of the machine's learned baselines.
    fn drive_cpu_calibrated(
        engine: &mut AlertEngine,
        settings: &Settings,
        start_ms: i64,
        count: i64,
        cpu: f64,
        calibration: Calibration,
    ) -> Vec<Evaluation> {
        (0..count)
            .map(|index| {
                let timestamp_ms = start_ms + index * settings.sample_interval_ms as i64;
                let system = SystemMetric {
                    timestamp_ms,
                    ..SystemMetric::default()
                };
                engine.evaluate(
                    &system,
                    &[process(timestamp_ms, cpu, 20)],
                    settings,
                    calibration,
                )
            })
            .collect()
    }

    fn resolution(evaluations: &[Evaluation]) -> Option<Alert> {
        evaluations
            .iter()
            .flat_map(|evaluation| &evaluation.changed)
            .find(|alert| alert.resolved_at_ms.is_some())
            .cloned()
    }

    /// The single incident an engine is holding open.
    fn only_active(engine: &AlertEngine) -> Alert {
        assert_eq!(engine.active.len(), 1, "exactly one incident must be open");
        engine.active.values().next().cloned().unwrap()
    }

    #[test]
    fn a_refire_inside_the_quiet_period_reopens_the_same_incident() {
        let settings = lifecycle_settings();
        let mut engine = AlertEngine::default();
        drive_cpu(&mut engine, &settings, 0, 4, 95.0);
        let opened = only_active(&engine);
        assert_eq!(opened.state, IncidentState::Open);
        assert_eq!(
            opened.fingerprint, "sustainedCpu:42:1",
            "every alert carries the engine key as its fingerprint"
        );

        // Quiet well below the exit threshold for a full hold window closes it.
        let quiet = drive_cpu(&mut engine, &settings, 8_000, 6, 4.0);
        let resolved = resolution(&quiet).expect("a quiet condition resolves");
        assert_eq!(resolved.id, opened.id);
        assert_eq!(resolved.state, IncidentState::Resolved);
        assert!(engine.active.is_empty());

        // Ten minutes later — well inside the six-hour quiet period — the
        // same condition returns.
        let refire = drive_cpu(&mut engine, &settings, 20_000 + 10 * 60_000, 4, 95.0);
        let reopened = refire
            .iter()
            .flat_map(|evaluation| &evaluation.changed)
            .next()
            .expect("the refire reaches its sustained window");
        assert_eq!(
            reopened.id, opened.id,
            "a refire inside the quiet period resurrects the same incident"
        );
        assert_eq!(reopened.state, IncidentState::Reopened);
        assert_eq!(reopened.fingerprint, opened.fingerprint);
        assert_eq!(
            reopened.first_seen_ms, opened.first_seen_ms,
            "first_seen_ms is preserved across the reopen"
        );
        assert_eq!(
            reopened.occurrence_count,
            resolved.occurrence_count + 1,
            "occurrence_count continues from the remembered incident"
        );
        assert!(reopened.resolved_at_ms.is_none());
    }

    #[test]
    fn a_refire_after_the_quiet_period_is_a_new_incident() {
        let settings = lifecycle_settings();
        let mut engine = AlertEngine::default();
        drive_cpu(&mut engine, &settings, 0, 4, 95.0);
        let opened = only_active(&engine);
        let quiet = drive_cpu(&mut engine, &settings, 8_000, 6, 4.0);
        let resolved = resolution(&quiet).expect("a quiet condition resolves");
        assert!(resolved.occurrence_count >= 1);

        // Seven hours later the quiet period has expired.
        let refire = drive_cpu(&mut engine, &settings, 20_000 + 7 * 3_600_000, 4, 95.0);
        let fresh = refire
            .iter()
            .flat_map(|evaluation| &evaluation.changed)
            .next()
            .expect("the refire reaches its sustained window");
        assert_ne!(
            fresh.id, opened.id,
            "a refire past the quiet period is a genuinely new incident"
        );
        assert_eq!(fresh.state, IncidentState::Open);
        assert_eq!(fresh.occurrence_count, 1, "occurrence_count restarts");
        assert_eq!(fresh.fingerprint, opened.fingerprint);
        assert_ne!(fresh.first_seen_ms, opened.first_seen_ms);
    }

    #[test]
    fn oscillation_around_the_entry_threshold_does_not_flap() {
        let settings = lifecycle_settings();
        let mut engine = AlertEngine::default();
        let entry = settings.cpu_percent;
        let opened = {
            drive_cpu(&mut engine, &settings, 0, 4, entry * 1.2);
            only_active(&engine)
        };

        // Alternate just above and just below the entry threshold, but always
        // above the 0.85 exit ratio.
        let mut ids: HashSet<String> = HashSet::new();
        let mut resolutions = 0;
        let start_ms = 4 * settings.sample_interval_ms as i64;
        for index in 0..24 {
            let cpu = if index % 2 == 0 {
                entry * 1.02
            } else {
                entry * 0.95
            };
            for evaluation in drive_cpu(
                &mut engine,
                &settings,
                start_ms + index * settings.sample_interval_ms as i64,
                1,
                cpu,
            ) {
                for alert in evaluation.changed {
                    if alert.resolved_at_ms.is_some() {
                        resolutions += 1;
                    }
                    ids.insert(alert.id);
                }
            }
        }
        assert_eq!(resolutions, 0, "an oscillating value must never resolve");
        assert!(
            ids.iter().all(|id| *id == opened.id),
            "the oscillation must not mint a sibling incident: {ids:?}"
        );
        assert_eq!(only_active(&engine).id, opened.id);
    }

    #[test]
    fn resolution_requires_the_exit_threshold_and_hold_window() {
        let settings = lifecycle_settings();
        let interval_ms = settings.sample_interval_ms as i64;
        let mut engine = AlertEngine::default();
        drive_cpu(&mut engine, &settings, 0, 4, 95.0);
        let opened = only_active(&engine);

        // 0.80x the entry threshold is below the 0.85 exit ratio, so the
        // clock starts — but the first quiet sample resolves nothing.
        let quiet = settings.cpu_percent * 0.80;
        let quiet_start = 4 * interval_ms;
        let first = drive_cpu(&mut engine, &settings, quiet_start, 1, quiet);
        assert!(
            resolution(&first).is_none(),
            "the first quiet sample only starts the hold window"
        );
        assert_eq!(only_active(&engine).id, opened.id);

        // Two further samples are still inside the 6 s hold window.
        let holding = drive_cpu(&mut engine, &settings, quiet_start + interval_ms, 2, quiet);
        assert!(
            resolution(&holding).is_none(),
            "the incident holds for a full sustained window"
        );
        assert_eq!(only_active(&engine).id, opened.id);

        // The evaluation that completes the window closes it.
        let closing = drive_cpu(
            &mut engine,
            &settings,
            quiet_start + 3 * interval_ms,
            1,
            quiet,
        );
        let resolved = resolution(&closing).expect("resolution after a full hold window");
        assert_eq!(resolved.id, opened.id);
        assert_eq!(resolved.state, IncidentState::Resolved);
        assert!(engine.active.is_empty());
    }

    #[test]
    fn restart_reattaches_a_persisting_condition_to_its_incident() {
        let settings = lifecycle_settings();
        let directory = tempfile::tempdir().unwrap();
        let storage = crate::storage::Storage::open(&directory.path().join("history.db")).unwrap();

        let mut before = AlertEngine::default();
        for evaluation in drive_cpu(&mut before, &settings, 0, 4, 95.0) {
            storage.upsert_alerts(&evaluation.changed).unwrap();
        }
        let opened = only_active(&before);

        // Restart: the service force-resolves everything still open, but the
        // fingerprints stay reopen-eligible.
        let restart_ms = 30_000;
        assert_eq!(storage.resolve_open_alerts(restart_ms).unwrap(), 1);
        let seed = storage
            .recent_resolved_alerts(restart_ms - QUIET_PERIOD_MS)
            .unwrap();
        assert_eq!(seed.len(), 1);
        assert_eq!(seed[0].id, opened.id);
        assert_eq!(seed[0].fingerprint, "sustainedCpu:42:1");

        let mut after = AlertEngine::new(seed);
        let refire = drive_cpu(&mut after, &settings, restart_ms + 60_000, 4, 95.0);
        let reopened = refire
            .iter()
            .flat_map(|evaluation| &evaluation.changed)
            .next()
            .expect("the persisting condition reacquires");
        assert_eq!(
            reopened.id, opened.id,
            "a restart must reattach to the stored incident, not mint a new one"
        );
        assert_eq!(reopened.state, IncidentState::Reopened);
        assert_eq!(reopened.first_seen_ms, opened.first_seen_ms);
        assert_eq!(reopened.occurrence_count, opened.occurrence_count + 1);
    }

    #[test]
    fn an_incident_is_recorded_before_it_is_worth_notifying() {
        // The sustained window is 3 x 2 s; persistence reaches the policy's
        // 0.5 floor at 1.5 windows (9 s) of breach. So the incident opens at
        // 4 s, is recorded and scored from that moment, and only becomes
        // notifiable at 10 s.
        let settings = lifecycle_settings();
        let mut engine = AlertEngine::default();
        let evaluations = drive_cpu(&mut engine, &settings, 0, 8, 95.0);
        let timeline: Vec<(i64, bool, f64, u32)> = evaluations
            .iter()
            .filter_map(|evaluation| evaluation.active.first())
            .map(|alert| {
                (
                    alert.last_seen_ms,
                    alert.notify,
                    alert.quality.persistence,
                    alert.notify_generation,
                )
            })
            .collect();
        assert_eq!(
            timeline
                .iter()
                .map(|(at_ms, notify, _, _)| (*at_ms, *notify))
                .collect::<Vec<_>>(),
            vec![
                (4_000, false),
                (6_000, false),
                (8_000, false),
                (10_000, true),
                (12_000, true),
                (14_000, true),
            ]
        );
        // Persistence only ever climbs, and the floor is what flipped the
        // decision -- not some incidental change.
        let mut previous = 0.0;
        for (at_ms, notify, persistence, generation) in &timeline {
            assert!(*persistence > previous, "persistence must climb at {at_ms}");
            assert_eq!(*notify, *persistence >= 0.5);
            // A steady incident never re-pops: nothing escalated and nothing
            // materially changed, so the generation stays put across the
            // suppressed-to-notifiable flip too.
            assert_eq!(*generation, 0);
            previous = *persistence;
        }
        // Suppression is a notification decision only: every sample, including
        // the suppressed ones, still reached storage carrying its scores.
        for evaluation in &evaluations[2..] {
            let active = evaluation.active.first().expect("the incident is open");
            let stored = evaluation
                .changed
                .iter()
                .find(|alert| alert.id == active.id)
                .expect("an open incident is persisted every sample it is scored");
            assert_eq!(stored.quality, active.quality);
            assert_eq!(stored.notify, active.notify);
            // Confidence is what the machine actually knows, and on a learned
            // machine it clears the floor as soon as the incident has more
            // than its opening sample behind it -- so persistence is the only
            // thing still holding the notification back above.
            assert_eq!(
                stored.quality.confidence >= 0.5,
                stored.occurrence_count > 1,
                "confidence tracks evidence depth, not the clock"
            );
        }
    }

    #[test]
    fn an_incident_held_open_by_hysteresis_keeps_earning_persistence() {
        // The engine holds an incident open while its value sits between the
        // exit and entry thresholds, because that hold *is* the condition
        // continuing. Persistence measures the incident, not the count of
        // entry-threshold breaches, so it keeps accruing through the hold --
        // and an incident can therefore become notifiable during one.
        let settings = lifecycle_settings();
        let mut engine = AlertEngine::default();
        drive_cpu(&mut engine, &settings, 0, 4, 95.0);
        let opened = only_active(&engine);
        assert!(!opened.notify, "not yet persistent enough to interrupt");
        let occurrences = opened.occurrence_count;

        // 0.90x the entry threshold: no candidate fires (so no new breaching
        // sample is recorded) but it is above the 0.85 exit ratio, so the
        // incident cannot close either.
        let held = drive_cpu(
            &mut engine,
            &settings,
            4 * settings.sample_interval_ms as i64,
            4,
            settings.cpu_percent * 0.90,
        );
        let during_hold: Vec<(i64, bool, f64, u32)> = held
            .iter()
            .map(|evaluation| {
                let alert = evaluation
                    .active
                    .first()
                    .expect("hysteresis keeps the incident open");
                (
                    alert.first_seen_ms,
                    alert.notify,
                    alert.quality.persistence,
                    alert.occurrence_count,
                )
            })
            .collect();
        let mut previous = opened.quality.persistence;
        for (_, _, persistence, count) in &during_hold {
            assert!(
                *persistence > previous,
                "persistence accrues through a hold"
            );
            assert_eq!(
                *count, occurrences,
                "no new breaching sample is being credited"
            );
            previous = *persistence;
        }
        assert!(
            during_hold
                .first()
                .is_some_and(|(_, notify, _, _)| !*notify),
            "the hold starts below the notification floor"
        );
        assert!(
            during_hold.last().is_some_and(|(_, notify, _, _)| *notify),
            "and crosses it while the value is still under the entry threshold"
        );
    }

    #[test]
    fn the_learning_period_records_a_warning_without_ever_notifying() {
        // Identical breach, identical duration; the only difference is a
        // machine that has not finished learning what normal looks like.
        let settings = lifecycle_settings();
        let mut engine = AlertEngine::default();
        let evaluations = drive_cpu_calibrated(
            &mut engine,
            &settings,
            0,
            10,
            95.0,
            Calibration {
                learning: true,
                baseline_maturity: 0.2,
                ..Calibration::default()
            },
        );
        let scored: Vec<&Alert> = evaluations
            .iter()
            .filter_map(|evaluation| evaluation.active.first())
            .collect();
        assert!(
            !scored.is_empty(),
            "the incident still opens while learning"
        );
        assert!(
            scored.iter().all(|alert| !alert.notify),
            "a Warning cannot notify during the learning period"
        );
        let last = scored.last().expect("at least one scored sample");
        assert!(
            last.quality.persistence > 0.5,
            "it is suppressed by policy, not by a weak score"
        );
        assert_eq!(last.notify_generation, 0);
        // And the same breach on a learned machine does notify.
        let mut learned = AlertEngine::default();
        let after = drive_cpu(&mut learned, &settings, 0, 10, 95.0);
        assert!(
            after
                .iter()
                .filter_map(|evaluation| evaluation.active.first())
                .any(|alert| alert.notify)
        );
    }

    #[test]
    fn an_event_shaped_detector_still_resolves_on_absence() {
        // Slow launch has no sustained value to fall below an exit
        // threshold, so its incident closes the moment the event stops.
        let settings = lifecycle_settings();
        let mut engine = AlertEngine::default();
        let mut system = SystemMetric::default();
        for index in 0..3 {
            system.timestamp_ms = index * 2_000;
            let mut slow = process(system.timestamp_ms, 1.0, 20);
            slow.launch_duration_ms = Some(settings.slow_launch_ms + 1_000);
            engine.evaluate(&system, &[slow], &settings, Calibration::default());
        }
        let opened = only_active(&engine);
        assert_eq!(opened.kind, "slowLaunch");
        assert_eq!(opened.fingerprint, "slowLaunch:42:1");

        system.timestamp_ms += 2_000;
        let evaluation = engine.evaluate(
            &system,
            &[process(system.timestamp_ms, 1.0, 20)],
            &settings,
            Calibration::default(),
        );
        let resolved = resolution(&[evaluation]).expect("event-shaped absence resolves at once");
        assert_eq!(resolved.id, opened.id);
        assert!(engine.active.is_empty());
    }

    #[test]
    fn one_time_collector_cache_step_is_not_a_growth_trend() {
        // A one-time cache allocation early in a full 30-minute window: the
        // step lands entirely inside the first third, so that segment's own
        // mean is already dragged most of the way to the post-step level.
        // The remaining first-to-middle step is too small to clear the
        // shape test's minimum, so this must classify as `Inconclusive`
        // (not `Monotonic`) and raise no candidate at all.
        let points: Vec<TrendPoint> = (0..=900)
            .map(|index| TrendPoint {
                at_ms: index * 2_000,
                value: if index < 30 {
                    18.0 * 1024.0 * 1024.0
                } else {
                    20.0 * 1024.0 * 1024.0
                },
            })
            .collect();
        assert!(collector_growth_shape(&points).is_none());
    }

    const DPC_TITLE: &str = "High DPC or interrupt activity";

    /// A system sample whose DPC rate breaches the configured limit by the
    /// stated factor. `1.0` is exactly the entry threshold; `0.9` sits inside
    /// the hysteresis band (below entry, above 85% of it), where the incident
    /// stays open with no candidate to carry anything.
    fn dpc_system(settings: &Settings, timestamp_ms: i64, factor: f64) -> SystemMetric {
        SystemMetric {
            timestamp_ms,
            dpc_rate: settings.dpc_rate * factor,
            ..SystemMetric::default()
        }
    }

    /// Drive `count` DPC samples one interval apart, returning the incident's
    /// state after the last one.
    fn drive_dpc(
        engine: &mut AlertEngine,
        settings: &Settings,
        start_ms: i64,
        count: i64,
        factor: f64,
    ) -> Option<Alert> {
        for index in 0..count {
            let timestamp_ms = start_ms + index * settings.sample_interval_ms as i64;
            engine.evaluate(
                &dpc_system(settings, timestamp_ms, factor),
                &[],
                settings,
                Calibration::default(),
            );
        }
        engine.active.get(DPC_KEY).cloned()
    }

    fn repeatable(family: &str) -> InterruptContext {
        InterruptContext {
            verdict: VerdictState::Repeatable {
                driver_family: family.into(),
            },
            ..InterruptContext::default()
        }
    }

    #[test]
    fn alternating_low_confidence_attribution_is_one_silent_incident() {
        // The interrupt engine reports `SingleCapture` for exactly the field
        // report's storage -> graphics -> network rotation (asserted over
        // real captures in `interrupts.rs`). Here that verdict has to buy
        // nothing: one incident, one title, never a notification.
        let settings = lifecycle_settings();
        let mut engine = AlertEngine::default();
        engine.observe_interrupts(InterruptContext {
            verdict: VerdictState::SingleCapture,
            ..InterruptContext::default()
        });
        let mut ids = HashSet::new();
        let mut titles = HashSet::new();
        let mut rates = HashSet::new();
        for index in 0..30 {
            let timestamp_ms = index * settings.sample_interval_ms as i64;
            // The reading wanders; the evidence has to follow it.
            let factor = 5.0 + (index % 3) as f64;
            let evaluation = engine.evaluate(
                &dpc_system(&settings, timestamp_ms, factor),
                &[],
                &settings,
                Calibration::default(),
            );
            for alert in evaluation
                .active
                .iter()
                .filter(|a| a.kind == "dpcInterrupt")
            {
                ids.insert(alert.id.clone());
                titles.insert(alert.title.clone());
                rates.extend(
                    alert
                        .evidence
                        .iter()
                        .filter(|row| row.label == "DPC rate")
                        .map(|row| row.value.clone()),
                );
                assert!(
                    !alert.notify,
                    "an attribution that never held cannot notify: {:?}",
                    alert.quality
                );
                assert_eq!(alert.notify_generation, 0);
            }
        }
        assert_eq!(ids.len(), 1, "one incident, not one per label");
        assert_eq!(titles.len(), 1);
        assert_eq!(titles.into_iter().next().as_deref(), Some(DPC_TITLE));
        assert_eq!(rates.len(), 3, "evidence keeps tracking the live reading");
        // Suppression is a notification decision, and an explainable one: the
        // incident is scored and recorded either way.
        let incident = engine.active.get(DPC_KEY).expect("still open");
        assert!(incident.quality.persistence > PERSISTENCE_FLOOR);
        assert!(
            incident.quality.confidence >= CONFIDENCE_FLOOR,
            "the generic floors would have let it through: {}",
            incident.quality.confidence
        );
    }

    #[test]
    fn a_repeatable_driver_family_verdict_notifies_once() {
        let settings = lifecycle_settings();
        let mut engine = AlertEngine::default();
        engine.observe_interrupts(repeatable("storage"));
        let opened = drive_dpc(&mut engine, &settings, 0, 3, 5.0).expect("the incident opens");
        assert!(
            !opened.notify,
            "one sustained window is not yet persistent enough"
        );

        let notified =
            drive_dpc(&mut engine, &settings, 6_000, 4, 5.0).expect("the incident stays open");
        assert!(notified.notify, "a repeatable family carries the finding");
        assert_eq!(
            notified.notify_generation, 0,
            "a first notification pops on an unseen (id, generation); it never bumps"
        );

        // Further agreeing captures say nothing new.
        let later = drive_dpc(&mut engine, &settings, 20_000, 10, 5.0).expect("still open");
        assert_eq!(later.id, notified.id);
        assert!(later.notify);
        assert_eq!(
            later.notify_generation, 0,
            "agreeing captures neither bump nor re-pop"
        );
    }

    #[test]
    fn sustained_p95_with_corroboration_notifies_without_attribution() {
        // Sixteen minutes above the machine's learned p95 with no usable
        // capture at all: the rate alone must not notify, but the rate plus
        // something else agreeing must.
        let settings = lifecycle_settings();
        let sustained_samples = (SUSTAINED_P95_MS + 60_000) / settings.sample_interval_ms as i64;
        let run = |corroborating_signals: u32, hung: bool| -> Alert {
            let mut engine = AlertEngine::default();
            engine.observe_interrupts(InterruptContext {
                verdict: VerdictState::NoCapture,
                corroborating_signals,
                dpc_p95: Some(settings.dpc_rate * 2.0),
                interrupt_p95: None,
            });
            for index in 0..sustained_samples {
                let timestamp_ms = index * settings.sample_interval_ms as i64;
                let mut worker = process(timestamp_ms, 1.0, 20);
                worker.has_visible_window = hung;
                worker.responsive = !hung;
                engine.evaluate(
                    &dpc_system(&settings, timestamp_ms, 3.0),
                    &[worker],
                    &settings,
                    Calibration::default(),
                );
            }
            engine.active.get(DPC_KEY).cloned().expect("open incident")
        };
        let alone = run(0, false);
        assert!(
            !alone.notify,
            "a rate above p95 with nothing agreeing stays history-only"
        );
        assert!(
            alone.quality.confidence >= CONFIDENCE_FLOOR,
            "again, not the generic floors doing the suppressing: {}",
            alone.quality.confidence
        );
        assert!(
            run(1, false).notify,
            "correlated device activity corroborates it"
        );
        let impacted = run(0, true);
        assert!(
            impacted.notify,
            "a hung window is user impact, which corroborates it too"
        );
        assert!(impacted.quality.user_impact >= 0.3);
    }

    #[test]
    fn an_archived_impact_incident_stops_vouching_for_the_machine() {
        // Archiving says "do not surface this", so a hung window the user
        // has filed away cannot go on corroborating the DPC finding.
        let settings = lifecycle_settings();
        let mut engine = AlertEngine::default();
        engine.observe_interrupts(InterruptContext {
            verdict: VerdictState::NoCapture,
            corroborating_signals: 0,
            dpc_p95: Some(settings.dpc_rate * 2.0),
            interrupt_p95: None,
        });
        let samples = (SUSTAINED_P95_MS + 60_000) / settings.sample_interval_ms as i64;
        let mut notified_while_impacted = false;
        for index in 0..samples {
            let timestamp_ms = index * settings.sample_interval_ms as i64;
            let mut hung = process(timestamp_ms, 1.0, 20);
            hung.has_visible_window = true;
            hung.responsive = false;
            engine.evaluate(
                &dpc_system(&settings, timestamp_ms, 3.0),
                &[hung],
                &settings,
                Calibration::default(),
            );
            notified_while_impacted |= engine
                .active
                .get(DPC_KEY)
                .is_some_and(|incident| incident.notify);
        }
        assert!(
            notified_while_impacted,
            "the hung window carried it while it counted"
        );
        let hung_id = engine
            .active
            .values()
            .find(|alert| alert.kind == "unresponsive")
            .map(|alert| alert.id.clone())
            .expect("the hung window is its own incident");
        engine.set_archived(&hung_id, true);
        let last_ms = samples * settings.sample_interval_ms as i64;
        let mut hung = process(last_ms, 1.0, 20);
        hung.has_visible_window = true;
        hung.responsive = false;
        engine.evaluate(
            &dpc_system(&settings, last_ms, 3.0),
            &[hung],
            &settings,
            Calibration::default(),
        );
        assert!(
            !engine.active.get(DPC_KEY).expect("still open").notify,
            "an archived impact incident is not corroboration"
        );
    }

    #[test]
    fn a_confident_verdict_change_renotifies_the_same_incident() {
        let settings = lifecycle_settings();
        let mut engine = AlertEngine::default();
        engine.observe_interrupts(repeatable("storage"));
        let before = drive_dpc(&mut engine, &settings, 0, 8, 5.0).expect("open");
        assert!(before.notify);

        engine.observe_interrupts(InterruptContext {
            verdict: VerdictState::ChangedConfidently {
                from: "storage".into(),
                to: "gpu".into(),
            },
            ..InterruptContext::default()
        });
        let changed = drive_dpc(&mut engine, &settings, 16_000, 1, 5.0).expect("still open");
        assert_eq!(
            changed.id, before.id,
            "attribution never splits the incident"
        );
        assert_eq!(changed.title, DPC_TITLE, "the title never moves either");
        assert_eq!(changed.state, IncidentState::Open);
        assert!(changed.notify);
        assert_eq!(
            changed.notify_generation,
            before.notify_generation + 1,
            "a confident change is a materially changed fingerprint"
        );

        // The change is spent: the same standing verdict does not keep popping.
        let settled = drive_dpc(&mut engine, &settings, 18_000, 5, 5.0).expect("still open");
        assert_eq!(settled.notify_generation, changed.notify_generation);
    }

    /// The window semantics, pinned at their boundaries: the trailing
    /// quarter-hour has to be spanned *and* mostly above the learned p95.
    #[test]
    fn the_sustained_p95_gate_measures_a_window_not_an_unbroken_run() {
        let settings = lifecycle_settings();
        let interval_ms = settings.sample_interval_ms as i64;
        // `above_every` samples out of every `above_every` are at or above
        // p95; `run_ms` is how long the incident is driven for.
        let notifies = |run_ms: i64, below_every: i64| -> bool {
            let mut engine = AlertEngine::default();
            engine.observe_interrupts(InterruptContext {
                verdict: VerdictState::NoCapture,
                corroborating_signals: 1,
                dpc_p95: Some(settings.dpc_rate * 2.0),
                interrupt_p95: None,
            });
            let samples = run_ms / interval_ms;
            for index in 0..=samples {
                // Below-p95 samples still breach the configured threshold,
                // so the incident stays open either way.
                let factor = if index % below_every == below_every - 1 {
                    1.5
                } else {
                    3.0
                };
                let timestamp_ms = index * interval_ms;
                engine.evaluate(
                    &dpc_system(&settings, timestamp_ms, factor),
                    &[],
                    &settings,
                    Calibration::default(),
                );
            }
            engine.active.get(DPC_KEY).expect("open incident").notify
        };
        // Never below p95, but a minute short of the window.
        assert!(
            !notifies(SUSTAINED_P95_MS - 60_000, i64::MAX),
            "fourteen minutes is not a quarter of an hour"
        );
        assert!(
            notifies(SUSTAINED_P95_MS, i64::MAX),
            "the fifteenth minute opens the gate"
        );
        // One sample in thirteen below p95 is ~92% above: a real machine
        // never sits above its own p95 without a single dip.
        assert!(
            notifies(SUSTAINED_P95_MS, 13),
            "an occasional dip must not restart the quarter-hour"
        );
        // One in five below is 80%, and that is not a sustained excursion.
        assert!(
            !notifies(SUSTAINED_P95_MS, 5),
            "eighty percent of the window is not sustained"
        );
    }

    #[test]
    fn a_change_arriving_while_the_detector_vetoes_is_not_eaten() {
        // The trace the review asked for: notify at generation 0, the
        // attribution then degrades so the detector's own veto suppresses
        // the finding, the reading dips into the hysteresis band, the
        // confident change lands *there*, and the reading recrosses. The
        // change must survive every one of those steps.
        let settings = lifecycle_settings();
        let mut engine = AlertEngine::default();
        engine.observe_interrupts(repeatable("storage"));
        let notified = drive_dpc(&mut engine, &settings, 0, 8, 5.0).expect("open");
        assert!(notified.notify);
        assert_eq!(notified.notify_generation, 0);

        // The verdict falls apart: vetoed, but the tray has already banked
        // (id, generation 0), so a later change cannot pop on novelty.
        engine.observe_interrupts(InterruptContext {
            verdict: VerdictState::SingleCapture,
            ..InterruptContext::default()
        });
        let degraded = drive_dpc(&mut engine, &settings, 16_000, 3, 5.0).expect("still open");
        assert!(!degraded.notify, "the detector's veto suppresses it");
        assert_eq!(degraded.notify_generation, 0);

        // Into the hysteresis band, where no candidate fires at all.
        let held = drive_dpc(&mut engine, &settings, 22_000, 2, 0.9).expect("held");
        assert!(!held.notify);

        // The confident change lands during the hold.
        engine.observe_interrupts(InterruptContext {
            verdict: VerdictState::ChangedConfidently {
                from: "storage".into(),
                to: "gpu".into(),
            },
            ..InterruptContext::default()
        });
        // Still held, still no candidate: the refreshed verdict has to lift
        // the veto by itself, and the change has to reach the tray on the
        // first sample that can carry it.
        let in_hold = drive_dpc(&mut engine, &settings, 26_000, 2, 0.9).expect("still held");
        assert!(
            in_hold.notify,
            "a verdict that improves during a hold must not stay behind a stale veto"
        );
        assert_eq!(in_hold.notify_generation, 1);

        let recrossed = drive_dpc(&mut engine, &settings, 30_000, 3, 5.0).expect("still open");
        assert_eq!(recrossed.id, notified.id);
        assert_eq!(recrossed.state, IncidentState::Open);
        assert!(recrossed.notify);
        assert_eq!(
            recrossed.notify_generation, 1,
            "the change has to reach the tray on an id and generation it has not seen"
        );
        // And exactly once.
        let settled = drive_dpc(&mut engine, &settings, 36_000, 4, 5.0).expect("still open");
        assert_eq!(settled.notify_generation, 1);
    }

    #[test]
    fn a_confident_verdict_change_lands_through_a_hysteresis_hold() {
        // The verdict arrives on a sample where the rate has dipped into the
        // hysteresis band: the incident is held open with no candidate, so
        // there is nothing to carry the flag unless the engine latches it.
        let settings = lifecycle_settings();
        let mut engine = AlertEngine::default();
        engine.observe_interrupts(repeatable("storage"));
        let before = drive_dpc(&mut engine, &settings, 0, 8, 5.0).expect("open");
        assert!(before.notify);

        engine.observe_interrupts(InterruptContext {
            verdict: VerdictState::ChangedConfidently {
                from: "storage".into(),
                to: "gpu".into(),
            },
            ..InterruptContext::default()
        });
        let held = drive_dpc(&mut engine, &settings, 16_000, 2, 0.9).expect("held by hysteresis");
        assert_eq!(held.id, before.id);
        assert!(held.notify);
        assert_eq!(
            held.notify_generation,
            before.notify_generation + 1,
            "a change that lands during a hold must not be dropped"
        );
    }

    // ---- Handle / thread growth discrimination --------------------------

    /// Growth fixtures run at a 30-second cadence. The shape window these
    /// detectors read is thirty minutes wide, so the default two-second
    /// cadence would need thousands of samples per fixture to say anything.
    fn growth_settings() -> Settings {
        Settings {
            sustained_samples: 3,
            sample_interval_ms: 30_000,
            // The shipped 500-handle entry threshold assumes the two-second
            // cadence; the field case (+800 handles over ten minutes) is a
            // 400-handle delta across the raw comparison window. The fixtures
            // state a threshold that delta can cross, because what is under
            // test is the shape and baseline discrimination on top of the raw
            // gate, not the raw number itself.
            handle_growth: 200,
            thread_growth: 20,
            ..Settings::default()
        }
    }

    /// Fixtures start three hours in so the process sits in the per-name
    /// baseline's mature age bucket, the same bucket the training helpers
    /// below fill.
    const GROWTH_START_MS: i64 = 3 * 3_600_000;

    fn flat(value: u32, samples: usize) -> Vec<u32> {
        vec![value; samples]
    }

    /// `samples` values walking from just after `from` to exactly `to`.
    fn ramp(from: u32, to: u32, samples: usize) -> Vec<u32> {
        let span = i64::from(to) - i64::from(from);
        (1..=samples)
            .map(|index| (i64::from(from) + span * index as i64 / samples as i64) as u32)
            .collect()
    }

    fn growth_process(timestamp_ms: i64, name: &str, handles: u32, threads: u32) -> ProcessMetric {
        let mut value = process(timestamp_ms, 1.0, 20);
        value.name = name.into();
        value.handle_count = handles;
        value.thread_count = threads;
        value
    }

    fn drive_growth(
        engine: &mut AlertEngine,
        settings: &Settings,
        name: &str,
        handles: &[u32],
        threads: &[u32],
        calibration: Calibration<'_>,
    ) -> Vec<Evaluation> {
        handles
            .iter()
            .zip(threads.iter())
            .enumerate()
            .map(|(index, (handles, threads))| {
                let timestamp_ms =
                    GROWTH_START_MS + index as i64 * settings.sample_interval_ms as i64;
                let system = SystemMetric {
                    timestamp_ms,
                    ..SystemMetric::default()
                };
                engine.evaluate(
                    &system,
                    &[growth_process(timestamp_ms, name, *handles, *threads)],
                    settings,
                    calibration,
                )
            })
            .collect()
    }

    /// [`drive_growth`] with the thread count pinned flat, for the handle
    /// fixtures.
    fn drive_handles(
        engine: &mut AlertEngine,
        settings: &Settings,
        name: &str,
        trajectory: &[u32],
        calibration: Calibration<'_>,
    ) -> Vec<Evaluation> {
        let threads = flat(4, trajectory.len());
        drive_growth(engine, settings, name, trajectory, &threads, calibration)
    }

    /// [`drive_growth`] wired the way `runtime.rs` actually wires it: the
    /// learned norms are read *before* the sample is judged and updated
    /// *after*, with confirmed leaks held out of their own name's bucket.
    ///
    /// This ordering is the whole point. A store handed to the engine frozen
    /// -- as the fixtures above do -- cannot show the failure this class of
    /// test exists to catch, because in the shipped runtime a leaking process
    /// feeds its own baseline every two seconds.
    fn drive_growth_live(
        engine: &mut AlertEngine,
        settings: &Settings,
        store: &mut BaselineStore,
        name: &str,
        handles: &[u32],
        threads: &[u32],
    ) -> Vec<Evaluation> {
        handles
            .iter()
            .zip(threads.iter())
            .enumerate()
            .map(|(index, (handles, threads))| {
                let timestamp_ms =
                    GROWTH_START_MS + index as i64 * settings.sample_interval_ms as i64;
                let system = SystemMetric {
                    timestamp_ms,
                    ..SystemMetric::default()
                };
                let process = growth_process(timestamp_ms, name, *handles, *threads);
                let evaluation = engine.evaluate(
                    &system,
                    std::slice::from_ref(&process),
                    settings,
                    Calibration {
                        names: Some(store),
                        ..Calibration::default()
                    },
                );
                if !engine
                    .self_training_quarantine()
                    .contains(&(process.pid, process.started_at_ms))
                {
                    store.observe_process(&process, timestamp_ms);
                }
                evaluation
            })
            .collect()
    }

    /// Train a per-name baseline by replaying a handle trajectory into the
    /// store the way the runtime does, at the same age bucket the fixtures
    /// run in.
    fn trained_baseline(name: &str, trajectory: &[u32]) -> BaselineStore {
        let mut store = BaselineStore::new(0);
        for (index, handles) in trajectory.iter().enumerate() {
            let at_ms = GROWTH_START_MS + index as i64 * 30_000;
            store.observe_process(&growth_process(at_ms, name, *handles, 4), at_ms);
        }
        store
    }

    /// Every version of every alert of `kind` this run produced, active or
    /// changed, in evaluation order.
    fn seen_of_kind<'a>(evaluations: &'a [Evaluation], kind: &str) -> Vec<&'a Alert> {
        evaluations
            .iter()
            .flat_map(|evaluation| evaluation.active.iter().chain(evaluation.changed.iter()))
            .filter(|alert| alert.kind == kind)
            .collect()
    }

    /// The field case: a process that opens 800 handles over ten minutes,
    /// holds them, then gives them all back. It is a real excursion and is
    /// recorded as one from the first sustained sample to the last, but it is
    /// never worth interrupting the user for, and it closes itself without a
    /// word once the window flattens.
    #[test]
    fn burst_and_release_never_notifies_but_is_recorded() {
        let settings = growth_settings();
        let mut engine = AlertEngine::default();
        // Ten minutes of climb, then a long hold, then the handles come back.
        // The hold runs past the thirty-minute window on purpose: the point
        // of the test is that the incident closes itself on the *plateau*,
        // before the release, because a process that stopped taking more has
        // already stopped being a leak.
        let mut trajectory = flat(300, 10);
        let climb_ends = trajectory.len() + 20;
        trajectory.extend(ramp(300, 1100, 20));
        trajectory.extend(flat(1100, 60));
        let plateau_ends = trajectory.len();
        trajectory.extend(ramp(1100, 300, 10));
        trajectory.extend(flat(300, 20));
        let evaluations = drive_handles(
            &mut engine,
            &settings,
            "burst.exe",
            &trajectory,
            Calibration::default(),
        );

        let seen = seen_of_kind(&evaluations, "handleGrowth");
        assert!(
            !seen.is_empty(),
            "the excursion must be recorded as an incident"
        );
        assert!(
            seen.iter().all(|alert| !alert.notify),
            "a burst-and-release must never be worth a notification"
        );
        assert!(
            seen.iter().all(|alert| alert.notify_generation == 0),
            "nothing about a burst-and-release earns a notification generation"
        );

        // The incident is in the evaluation output for every sample between
        // the one that opened it and the one that closed it -- suppression is
        // a notification decision, never a recording decision.
        let live: Vec<bool> = evaluations
            .iter()
            .map(|evaluation| {
                evaluation
                    .active
                    .iter()
                    .any(|alert| alert.kind == "handleGrowth")
            })
            .collect();
        let opened_at = live.iter().position(|live| *live).expect("it opens");
        let closed_at = live.iter().rposition(|live| *live).expect("it opens");
        assert!(
            live[opened_at..=closed_at].iter().all(|live| *live),
            "the incident is recorded continuously across the excursion"
        );

        let resolved_at = evaluations
            .iter()
            .position(|evaluation| {
                evaluation
                    .changed
                    .iter()
                    .any(|alert| alert.kind == "handleGrowth" && alert.resolved_at_ms.is_some())
            })
            .expect("the excursion auto-resolves once its window stops climbing");
        assert!(
            (climb_ends..plateau_ends).contains(&resolved_at),
            "the incident closes on the plateau, while the process is still \
             holding every handle it took -- not only once it hands them back \
             (sample {resolved_at}, plateau {climb_ends}..{plateau_ends})"
        );
        let resolution = evaluations[resolved_at]
            .changed
            .iter()
            .find(|alert| alert.kind == "handleGrowth" && alert.resolved_at_ms.is_some())
            .expect("the resolution row is recorded");
        assert_eq!(resolution.state, IncidentState::Resolved);
        assert!(
            !resolution.notify,
            "the resolution transition stays silent: notify is false"
        );
        assert!(
            resolution.occurrence_count >= 5,
            "occurrence_count reflects the excursion, not one sample: {}",
            resolution.occurrence_count
        );
        assert!(
            engine.active.is_empty(),
            "nothing is left open once the handles come back"
        );
    }

    /// A genuine leak: a monotonic climb that keeps going, on a process whose
    /// own mature baseline says this is not how it behaves.
    #[test]
    fn a_monotonic_leak_against_baseline_notifies_once_and_updates_thereafter() {
        let settings = growth_settings();
        let store = trained_baseline("leaky.exe", &flat(300, 60));
        let mut engine = AlertEngine::default();
        let mut trajectory = flat(300, 10);
        // Ninety samples at a thirty-second cadence: forty-five minutes of
        // unbroken climb, comfortably past the thirty minutes of monotonic
        // persistence a notifiable leak has to show.
        trajectory.extend(ramp(300, 3900, 90));
        let climb_ends = trajectory.len();
        // Then it stops. Even a leak that has already been notified about
        // closes without a second word once it stops taking more.
        trajectory.extend(flat(3900, 80));
        let evaluations = drive_handles(
            &mut engine,
            &settings,
            "leaky.exe",
            &trajectory,
            Calibration {
                names: Some(&store),
                ..Calibration::default()
            },
        );

        let timeline: Vec<Option<(bool, u32, u32, i64)>> = evaluations
            .iter()
            .map(|evaluation| {
                evaluation
                    .active
                    .iter()
                    .find(|alert| alert.kind == "handleGrowth")
                    .map(|alert| {
                        (
                            alert.notify,
                            alert.notify_generation,
                            alert.occurrence_count,
                            alert.last_seen_ms,
                        )
                    })
            })
            .collect();
        let first_notify = timeline
            .iter()
            .position(|entry| entry.is_some_and(|(notify, ..)| notify))
            .expect("a sustained monotonic leak eventually notifies");
        assert!(
            first_notify < climb_ends,
            "the climb itself is what notifies"
        );
        assert!(
            timeline[..first_notify]
                .iter()
                .all(|entry| entry.is_none_or(|(notify, ..)| !notify)),
            "the climb is recorded silently until it has persisted long enough"
        );
        assert!(
            timeline[first_notify..climb_ends]
                .iter()
                .all(|entry| entry.is_some_and(|(notify, ..)| notify)),
            "once it is worth saying, it stays said"
        );
        assert!(
            timeline
                .iter()
                .flatten()
                .all(|(_, generation, ..)| *generation == 0),
            "continued growth must not re-pop: the generation stays stable"
        );

        // And when the leak stops, the incident closes itself without a
        // second notification -- the resolution transition carries notify
        // false even though the incident had been notifying right up to it.
        let resolution = evaluations
            .iter()
            .flat_map(|evaluation| &evaluation.changed)
            .find(|alert| alert.kind == "handleGrowth" && alert.resolved_at_ms.is_some())
            .expect("a leak that stops growing auto-resolves");
        assert_eq!(resolution.state, IncidentState::Resolved);
        assert!(
            !resolution.notify,
            "silent auto-resolve: the resolution row never asks to interrupt"
        );
        assert_eq!(
            resolution.notify_generation, 0,
            "and it does not spend a generation on the way out"
        );

        let after: Vec<(u32, i64)> = timeline[first_notify..climb_ends]
            .iter()
            .flatten()
            .map(|(_, _, occurrences, last_seen)| (*occurrences, *last_seen))
            .collect();
        assert!(after.len() >= 3, "the leak keeps being observed");
        assert!(
            after.windows(2).all(|pair| pair[1].0 > pair[0].0),
            "continued growth updates occurrence_count"
        );
        assert!(
            after.windows(2).all(|pair| pair[1].1 > pair[0].1),
            "continued growth updates last_seen"
        );
        assert_eq!(
            evaluations
                .iter()
                .flat_map(|evaluation| &evaluation.changed)
                .filter(|alert| alert.kind == "handleGrowth")
                .map(|alert| alert.id.clone())
                .collect::<HashSet<String>>()
                .len(),
            1,
            "one climb is one incident"
        );
    }

    /// A process that bursts 500 handles as a matter of routine is judged
    /// against its own norm, not against the raw threshold.
    #[test]
    fn a_known_bursty_process_is_judged_against_its_own_norm() {
        let settings = growth_settings();
        let mut training = Vec::new();
        for _ in 0..6 {
            training.extend(flat(300, 10));
            training.extend(ramp(300, 800, 20));
            training.extend(flat(800, 10));
            training.extend(ramp(800, 300, 10));
        }
        let store = trained_baseline("bursty.exe", &training);

        let mut burst = flat(300, 10);
        burst.extend(ramp(300, 800, 20));
        burst.extend(flat(800, 20));

        let mut known = AlertEngine::default();
        let known_run = drive_handles(
            &mut known,
            &settings,
            "bursty.exe",
            &burst,
            Calibration {
                names: Some(&store),
                ..Calibration::default()
            },
        );
        assert!(
            seen_of_kind(&known_run, "handleGrowth").is_empty(),
            "a burst this process makes routinely is not an incident"
        );

        // The identical burst under a name the store has never seen has no
        // norm to be judged against, so the baseline gate passes open and the
        // other gates decide.
        let mut stranger = AlertEngine::default();
        let stranger_run = drive_handles(
            &mut stranger,
            &settings,
            "stranger.exe",
            &burst,
            Calibration {
                names: Some(&store),
                ..Calibration::default()
            },
        );
        assert!(
            !seen_of_kind(&stranger_run, "handleGrowth").is_empty(),
            "the same burst on an unknown name still passes the baseline gate"
        );
    }

    /// The failure this whole class of test exists for: in the shipped
    /// runtime every sample is folded into the leaking process's *own* name
    /// baseline, so the norm chases the leak. The EWMA mean settles a fixed
    /// distance behind a steady ramp while its deviation band settles further
    /// still, and "is this abnormal?" answers no forever -- at any leak rate,
    /// because both quantities scale with the rate. Snapshotting the norm at
    /// watch entry is what keeps the question answerable.
    #[test]
    fn a_steady_leak_is_not_hidden_by_the_norm_it_trains() {
        let settings = growth_settings();
        // One and three times the entry-threshold rate. The threshold rate is
        // `handle_growth` per raw comparison window, which is ten samples at
        // this cadence.
        for multiple in [1, 3] {
            let per_sample = settings.handle_growth * multiple / 10;
            let mut store = BaselineStore::new(0);
            let mut engine = AlertEngine::default();
            // Twenty steady samples first: enough to take the name's mature
            // bucket past the fifteen-observation floor, so the gate is
            // genuinely being applied and not passing open as immature.
            let mut trajectory = flat(300, 20);
            let leak_starts = trajectory.len();
            trajectory.extend((1..=100).map(|step| 300 + per_sample * step));
            let threads = flat(4, trajectory.len());
            let evaluations = drive_growth_live(
                &mut engine,
                &settings,
                &mut store,
                "steady-leak.exe",
                &trajectory,
                &threads,
            );

            let opened_at = evaluations
                .iter()
                .position(|evaluation| {
                    evaluation
                        .active
                        .iter()
                        .any(|alert| alert.kind == "handleGrowth")
                })
                .unwrap_or_else(|| {
                    panic!("a leak at {multiple}x the threshold rate must open an incident")
                });
            let notified_at = evaluations
                .iter()
                .position(|evaluation| {
                    evaluation
                        .active
                        .iter()
                        .any(|alert| alert.kind == "handleGrowth" && alert.notify)
                })
                .unwrap_or_else(|| panic!("a leak at {multiple}x the threshold rate must notify"));

            // The design envelope: the shape window needs five minutes before
            // it will say anything, and a climb needs thirty monotonic
            // minutes before it is worth interrupting anyone. Ten and fifty
            // minutes after the leak starts leave room for both plus the
            // sustained-sample streak, and nothing like room for the
            // baseline-chasing failure, which never fired at all.
            let minutes = |index: usize| {
                (index - leak_starts) as i64 * settings.sample_interval_ms as i64 / 60_000
            };
            assert!(
                minutes(opened_at) <= 10,
                "{multiple}x leak opened {} minutes in",
                minutes(opened_at)
            );
            assert!(
                minutes(notified_at) <= 50,
                "{multiple}x leak notified {} minutes in",
                minutes(notified_at)
            );
        }
    }

    /// The snapshot keeps a leak from hiding behind the norm it is training
    /// *during* the excursion. The quarantine is the other half: once a climb
    /// has been confirmed a leak, it stops teaching that name's norm at all,
    /// so it cannot poison the judgement of the next instance of the same
    /// executable hours later.
    #[test]
    fn a_confirmed_leak_stops_teaching_its_own_name_that_leaking_is_normal() {
        let settings = growth_settings();
        let mut trajectory = flat(300, 20);
        trajectory.extend((1..=100).map(|step| 300 + 20 * step));
        let threads = flat(4, trajectory.len());

        let learn = |honour_quarantine: bool| {
            let mut store = BaselineStore::new(0);
            let mut engine = AlertEngine::default();
            for (index, (handles, threads)) in trajectory.iter().zip(threads.iter()).enumerate() {
                let timestamp_ms =
                    GROWTH_START_MS + index as i64 * settings.sample_interval_ms as i64;
                let system = SystemMetric {
                    timestamp_ms,
                    ..SystemMetric::default()
                };
                let process = growth_process(timestamp_ms, "leaky.exe", *handles, *threads);
                engine.evaluate(
                    &system,
                    std::slice::from_ref(&process),
                    &settings,
                    Calibration {
                        names: Some(&store),
                        ..Calibration::default()
                    },
                );
                let quarantined = engine
                    .self_training_quarantine()
                    .contains(&(process.pid, process.started_at_ms));
                if !honour_quarantine || !quarantined {
                    store.observe_process(&process, timestamp_ms);
                }
            }
            store
                .name_stats("leaky.exe", 3 * 3_600_000)
                .map(|stats| stats.handles.mean())
                .unwrap_or_default()
        };

        let held_back = learn(true);
        let unchecked = learn(false);
        let finished = f64::from(trajectory.last().copied().unwrap_or_default());
        assert!(
            held_back < unchecked,
            "honouring the quarantine must learn strictly less of the leak \
             ({held_back:.0} vs {unchecked:.0})"
        );
        assert!(
            unchecked > finished * 0.7,
            "without it the norm follows the leak most of the way up \
             ({unchecked:.0} of a final {finished:.0})"
        );
        assert!(
            held_back < finished * 0.6,
            "with it the norm stops well short of where the leak ended \
             ({held_back:.0} of a final {finished:.0})"
        );
    }

    /// The bursty A/B under live training: the norm has to be learned by the
    /// same loop that consults it, or the suppression it buys is imaginary.
    #[test]
    fn a_bursty_process_still_learns_its_own_norm_while_being_judged_by_it() {
        let settings = growth_settings();
        let mut cycle = flat(300, 10);
        cycle.extend(ramp(300, 800, 20));
        cycle.extend(flat(800, 10));
        cycle.extend(ramp(800, 300, 10));

        let mut store = BaselineStore::new(0);
        let mut engine = AlertEngine::default();
        let mut training = Vec::new();
        for _ in 0..6 {
            training.extend(cycle.iter().copied());
        }
        let threads = flat(4, training.len());
        drive_growth_live(
            &mut engine,
            &settings,
            &mut store,
            "bursty.exe",
            &training,
            &threads,
        );

        // A fresh engine, the norm learned live above, one more identical
        // burst: the process is now known well enough not to be reported.
        let mut engine = AlertEngine::default();
        let threads = flat(4, cycle.len());
        let known = drive_growth_live(
            &mut engine,
            &settings,
            &mut store,
            "bursty.exe",
            &cycle,
            &threads,
        );
        assert!(
            seen_of_kind(&known, "handleGrowth").is_empty(),
            "a burst this process makes routinely is not an incident, even \
             when its norm was learned by the same loop that judges it"
        );

        let mut engine = AlertEngine::default();
        let stranger = drive_growth_live(
            &mut engine,
            &settings,
            &mut store,
            "stranger.exe",
            &cycle,
            &threads,
        );
        assert!(
            !seen_of_kind(&stranger, "handleGrowth").is_empty(),
            "the same burst on an unknown name still passes the baseline gate"
        );
    }

    /// A crowd of sub-threshold drifters must not be able to lock a real
    /// breacher out of the watch list -- that failure is silent and total.
    #[test]
    fn a_real_breacher_takes_a_watch_slot_from_the_crowd() {
        let settings = growth_settings();
        let mut engine = AlertEngine::default();
        // Enough drifters to fill every slot, each growing steadily but never
        // reaching its threshold: five handles a sample is fifty per raw
        // window, a quarter of the two hundred needed to breach -- exactly
        // enough to hold a watch slot forever.
        let drifters = GROWTH_WATCH_CAP;
        let leaker_pid = 9_000;
        let mut opened = false;
        for index in 0..120_i64 {
            let timestamp_ms = GROWTH_START_MS + index * settings.sample_interval_ms as i64;
            let mut processes: Vec<ProcessMetric> = (0..drifters)
                .map(|slot| {
                    let mut drifter = growth_process(
                        timestamp_ms,
                        &format!("drifter{slot}.exe"),
                        300 + 5 * index as u32,
                        4,
                    );
                    drifter.pid = 1_000 + slot as u32;
                    drifter
                })
                .collect();
            // The leaker arrives once every slot is taken, and climbs at four
            // times the threshold rate.
            if index >= 20 {
                let mut leaker = growth_process(
                    timestamp_ms,
                    "latecomer.exe",
                    300 + 80 * (index - 20) as u32,
                    4,
                );
                leaker.pid = leaker_pid;
                processes.push(leaker);
            }
            let system = SystemMetric {
                timestamp_ms,
                ..SystemMetric::default()
            };
            let evaluation =
                engine.evaluate(&system, &processes, &settings, Calibration::default());
            opened |= evaluation
                .active
                .iter()
                .any(|alert| alert.kind == "handleGrowth" && alert.process_id == Some(leaker_pid));
        }
        assert!(
            opened,
            "a process actually breaching its threshold must get a window even \
             when every slot is held by sub-threshold drift"
        );
        assert!(
            engine.growth_history.len() <= GROWTH_WATCH_CAP,
            "and the cap still holds: {} windows",
            engine.growth_history.len()
        );
    }

    /// A short pause must not throw away half an hour of evidence.
    ///
    /// The process here climbs steadily but never fast enough to breach, so
    /// it holds a window without ever opening an incident -- which is exactly
    /// the case where nothing else is keeping the window alive. When it
    /// pauses, its pressure decays as the climb leaves the raw comparison
    /// window, and without the entry/exit gap the first sample under the
    /// entry fraction would discard the whole thirty minutes.
    #[test]
    fn a_brief_pause_does_not_discard_the_growth_window() {
        let settings = growth_settings();
        let mut engine = AlertEngine::default();
        let mut trajectory = flat(300, 4);
        // Fifteen handles a sample is 150 across the five-minute raw window:
        // three quarters of the way to the threshold, never over it.
        trajectory.extend((1..=20).map(|step| 300 + 15 * step));
        let climbed = 300 + 15 * 20;
        trajectory.extend(flat(climbed, 10));
        let threads = flat(4, trajectory.len());
        let evaluations = drive_growth(
            &mut engine,
            &settings,
            "breather.exe",
            &trajectory,
            &threads,
            Calibration::default(),
        );
        assert!(
            seen_of_kind(&evaluations, "handleGrowth").is_empty(),
            "the fixture must stay under the raw threshold, or an open \
             incident would be what keeps the window alive"
        );
        assert_eq!(
            engine.growth_history.len(),
            1,
            "the window survives a pause shorter than the unwatch hold"
        );
    }

    /// A hold clock must not run while the window is holding the incident
    /// open on its own authority.
    ///
    /// The exit hysteresis says "resolve once the reading has sat below the
    /// exit threshold for a full sustained window". A growth incident spends
    /// long stretches with its reading below that threshold while its window
    /// keeps it open anyway (`StaysOpen`) -- the process has paused, or has
    /// released a token part of what it took. If the clock kept running
    /// through those stretches, the first sample where the window fell silent
    /// would find a hold already long since satisfied and close the incident
    /// on the spot, without the sustained window of quiet the hysteresis is
    /// supposed to require.
    #[test]
    fn a_hold_clock_does_not_survive_the_window_holding_an_incident_open() {
        let settings = growth_settings();
        let mut engine = AlertEngine::default();
        // Climb hard enough to open an incident, then slow to a creep: the
        // window still reads `Monotonic`, but the raw delta drops under the
        // entry threshold, so the candidate is absent and the incident is
        // held open by its window alone.
        let mut trajectory = flat(300, 10);
        trajectory.extend((1..=20).map(|step| 300 + 40 * step));
        let climbed = 300 + 40 * 20;
        trajectory.extend((1..=20).map(|step| climbed + 5 * step));
        let threads = flat(4, trajectory.len());
        let evaluations = drive_growth(
            &mut engine,
            &settings,
            "creeper.exe",
            &trajectory,
            &threads,
            Calibration::default(),
        );

        let key = "handleGrowth:42:1".to_string();
        let identity = (42_u32, 1_i64);
        assert!(
            engine.active.contains_key(&key),
            "the window holds the incident open through the creep"
        );
        let last_ms =
            GROWTH_START_MS + (evaluations.len() as i64 - 1) * settings.sample_interval_ms as i64;
        let hold_ms = i64::from(settings.sustained_samples) * settings.sample_interval_ms as i64;

        // Plant the state a brief undecidable dip leaves behind: a hold clock
        // started long enough ago to be satisfied the moment it is consulted.
        engine
            .below_exit_since
            .insert(key.clone(), last_ms - 10 * hold_ms);

        // One more creep sample, which takes the `StaysOpen` arm.
        let next_ms = last_ms + settings.sample_interval_ms as i64;
        let system = SystemMetric {
            timestamp_ms: next_ms,
            ..SystemMetric::default()
        };
        let handles = trajectory.last().copied().unwrap_or_default() + 5;
        engine.evaluate(
            &system,
            &[growth_process(next_ms, "creeper.exe", handles, 4)],
            &settings,
            Calibration::default(),
        );
        assert!(
            !engine.below_exit_since.contains_key(&key),
            "the stale clock is discarded while the window holds the incident open"
        );

        // Now let the window fall silent: too few points to have a shape at
        // all, so the next sample is decided by hysteresis alone. The clock
        // has to start over -- if the stale one had survived, this sample
        // would close the incident outright.
        if let Some(window) = engine.growth_history.get_mut(&identity) {
            while window.points.len() > 2 {
                window.points.pop_front();
            }
        }
        let after_ms = next_ms + settings.sample_interval_ms as i64;
        let system = SystemMetric {
            timestamp_ms: after_ms,
            ..SystemMetric::default()
        };
        let evaluation = engine.evaluate(
            &system,
            &[growth_process(after_ms, "creeper.exe", handles, 4)],
            &settings,
            Calibration::default(),
        );
        assert!(
            evaluation
                .changed
                .iter()
                .all(|alert| alert.resolved_at_ms.is_none()),
            "a silent window starts the hold afresh instead of inheriting one"
        );
        assert!(
            engine.active.contains_key(&key),
            "so the incident stays open"
        );
    }

    /// The safety-critical distinction between the three ways a growth window
    /// can stop climbing. Only a process that has actually given the
    /// resources back -- or stopped taking more -- lets its incident close;
    /// one still sitting on what it took keeps the incident open.
    #[test]
    fn only_a_finished_excursion_auto_resolves() {
        assert_eq!(growth_fate(TrendShape::Plateau), GrowthFate::AutoResolve);
        assert_eq!(growth_fate(TrendShape::Returning), GrowthFate::AutoResolve);
        assert_eq!(
            growth_fate(TrendShape::PartialRelease { remaining: 949.0 }),
            GrowthFate::StaysOpen,
            "a process that grew 1000 and gave back 51 still holds the leak"
        );
        assert_eq!(
            growth_fate(TrendShape::Monotonic {
                total_growth: 1_000.0
            }),
            GrowthFate::StaysOpen
        );
        assert_eq!(
            growth_fate(TrendShape::Inconclusive),
            GrowthFate::Undecided,
            "an empty window decides nothing; hysteresis still applies"
        );
    }

    /// The same distinction end to end: an identical 1000-handle climb, one
    /// giving back 51 handles and one giving back all of them.
    #[test]
    fn a_token_release_keeps_the_incident_open_but_a_full_one_closes_it() {
        let settings = growth_settings();
        let climb = {
            let mut trajectory = flat(300, 10);
            trajectory.extend(ramp(300, 1300, 20));
            trajectory
        };

        let mut token = climb.clone();
        token.extend(flat(1249, 30));
        let mut token_engine = AlertEngine::default();
        let token_run = drive_handles(
            &mut token_engine,
            &settings,
            "sticky.exe",
            &token,
            Calibration::default(),
        );
        assert!(
            !seen_of_kind(&token_run, "handleGrowth").is_empty(),
            "the climb opens an incident"
        );
        assert!(
            token_run
                .iter()
                .flat_map(|evaluation| &evaluation.changed)
                .all(|alert| alert.kind != "handleGrowth" || alert.resolved_at_ms.is_none()),
            "giving back 51 of 1000 handles resolves nothing: the incident stays open"
        );
        assert!(!token_engine.active.is_empty(), "the incident stays open");

        let mut full = climb;
        full.extend(flat(300, 30));
        let mut full_engine = AlertEngine::default();
        let full_run = drive_handles(
            &mut full_engine,
            &settings,
            "tidy.exe",
            &full,
            Calibration::default(),
        );
        let resolution = full_run
            .iter()
            .flat_map(|evaluation| &evaluation.changed)
            .find(|alert| alert.kind == "handleGrowth" && alert.resolved_at_ms.is_some())
            .expect("handing every handle back closes the incident");
        assert!(
            !resolution.notify,
            "and it closes silently, like every growth auto-resolve"
        );
    }

    /// Threads take the same three gates as handles.
    #[test]
    fn thread_growth_takes_the_same_gates_as_handles() {
        let settings = growth_settings();
        let mut engine = AlertEngine::default();
        let mut threads = flat(20, 10);
        threads.extend(ramp(20, 320, 40));
        let handles = flat(300, threads.len());
        let evaluations = drive_growth(
            &mut engine,
            &settings,
            "spawner.exe",
            &handles,
            &threads,
            Calibration::default(),
        );
        assert!(
            !seen_of_kind(&evaluations, "threadGrowth").is_empty(),
            "a monotonic thread climb opens a threadGrowth incident"
        );

        // A thread count that jumps once and holds is a pool, not a leak. The
        // step does cross the window's segment boundaries on its way through,
        // so it can be recorded while it does -- but it never holds a
        // monotonic shape for thirty minutes, so it never escalates past
        // history-only, and it closes itself once the step settles into the
        // window's earlier segments.
        let mut engine = AlertEngine::default();
        let mut threads = flat(20, 10);
        threads.extend(flat(320, 40));
        let evaluations = drive_growth(
            &mut engine,
            &settings,
            "pooled.exe",
            &handles,
            &threads,
            Calibration::default(),
        );
        assert!(
            seen_of_kind(&evaluations, "threadGrowth")
                .iter()
                .all(|alert| alert.severity == Severity::Info && !alert.notify),
            "a one-time step to a bigger thread pool never becomes a notifiable leak"
        );
        assert!(
            engine.active.is_empty(),
            "and it closes itself once the step clears the window"
        );
    }
}
