use crate::{
    baselines::{AgeBucketStats, RunningStats},
    config::Settings,
    models::{Alert, Evidence, IncidentState, ProcessMetric, Severity, SystemMetric},
    quality::{Calibration, QualityInputs, decide, score},
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
    /// renotify conditions. No detector sets it yet (Phase D does); it is
    /// plumbed here so the policy has somewhere to read it from.
    material_change: bool,
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
                    },
                );
            }
        }
        engine
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
                let memory_breached = memory_mb >= 25.0;
                let cpu_breached = process.cpu_percent >= settings.collector_cpu_percent;
                let handles_breached = process.handle_count >= COLLECTOR_HANDLE_BUDGET;
                if track_exits {
                    // Three absolute budgets share one incident, so its exit
                    // reading is how far the worst dimension sits above its
                    // own ceiling; 1.0 is the entry threshold by construction.
                    readings.insert(
                        process_key("collectorBudget", process),
                        [
                            memory_mb / 25.0,
                            ratio(process.cpu_percent, settings.collector_cpu_percent),
                            f64::from(process.handle_count) / f64::from(COLLECTOR_HANDLE_BUDGET),
                        ]
                        .into_iter()
                        .fold(0.0_f64, f64::max),
                    );
                }
                if memory_breached || cpu_breached || handles_breached {
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
                        Severity::Critical,
                        settings.sustained_samples.max(5),
                        "Collector resource budget exceeded",
                        "The PC Pulse collector has remained beyond at least one absolute production resource budget.".into(),
                        budget_evidence,
                        "Capture the diagnostics and restart only the PC Pulse Collector service. Report the breached dimension; do not terminate monitored applications.",
                    ).with_entry(1.0));
                }

                let age_ms = process.timestamp_ms.saturating_sub(process.started_at_ms);
                if age_ms >= 10 * 60_000
                    && let Some(growth) = collector_working_set_growth(history)
                {
                    candidates.push(process_candidate(
                        process,
                        "collectorGrowth",
                        Severity::Warning,
                        settings.sustained_samples.max(15),
                        "Collector working set is trending upward",
                        "After startup warm-up, the PC Pulse collector working set rose through each segment of a mature observation window instead of making a one-time cache allocation.".into(),
                        vec![
                            evidence("Sustained growth", format!("{:.1} MB", growth.growth_mb)),
                            evidence("Early-window mean", format!("{:.1} MB", growth.first_mean_mb)),
                            evidence("Mid-window mean", format!("{:.1} MB", growth.middle_mean_mb)),
                            evidence("Recent mean", format!("{:.1} MB", growth.last_mean_mb)),
                            evidence("Observation window", format!("{:.0} seconds", growth.window_seconds)),
                        ],
                        "Capture diagnostics and keep observing. Restart only the PC Pulse Collector service if the trend continues; report repeatable growth rather than terminating monitored applications.",
                    ));
                }
            }
        }

        let owner = processes.iter().max_by(|a, b| {
            (a.read_bytes_per_sec + a.write_bytes_per_sec)
                .total_cmp(&(b.read_bytes_per_sec + b.write_bytes_per_sec))
        });
        let disk_key = format!("diskLatency:{}", owner.map_or(0, |p| p.pid));
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
                "dpcInterrupt".into(),
                ratio(system.dpc_rate, settings.dpc_rate)
                    .max(ratio(system.interrupt_rate, settings.interrupt_rate)),
            );
        }

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
            });
        }

        if system.dpc_rate >= settings.dpc_rate || system.interrupt_rate >= settings.interrupt_rate
        {
            candidates.push(Candidate {
                key: "dpcInterrupt".into(),
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
                material_change: false,
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
                    },
                );
                resolved.push(alert);
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
                // Detector-supplied corroboration, user impact, and
                // attribution stability are Phase D's to plumb; until then
                // an unknown attribution scores neutral and the two signal
                // counts score honestly empty.
                attribution_stable: None,
                corroborating_signals: 0,
                user_impact_signals: 0,
                notified_before: notified.is_some(),
                last_notified_ms: notified.map(|memory| memory.at_ms),
            });
            let decision = decide(
                alert,
                &quality,
                calibration.learning,
                previous.get(key),
                terms.material_change,
            );
            let before = (alert.quality, alert.notify, alert.notify_generation);
            alert.quality = quality;
            alert.notify = decision.notify;
            if decision.bump_generation {
                alert.notify_generation = alert.notify_generation.saturating_add(1);
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

fn collector_working_set_growth(history: &VecDeque<ProcessPoint>) -> Option<CollectorGrowth> {
    let first = history.front()?;
    let last = history.back()?;
    let span_ms = last.timestamp_ms.saturating_sub(first.timestamp_ms);
    if span_ms < 4 * 60_000 {
        return None;
    }
    let third = span_ms / 3;
    let first_end = first.timestamp_ms + third;
    let middle_end = first.timestamp_ms + 2 * third;
    let (first_mean, first_samples) = mean_working_set(
        history
            .iter()
            .filter(|point| point.timestamp_ms <= first_end),
    );
    let (middle_mean, middle_samples) = mean_working_set(
        history
            .iter()
            .filter(|point| point.timestamp_ms > first_end && point.timestamp_ms <= middle_end),
    );
    let (last_mean, last_samples) = mean_working_set(
        history
            .iter()
            .filter(|point| point.timestamp_ms > middle_end),
    );
    if [first_samples, middle_samples, last_samples]
        .into_iter()
        .any(|samples| samples < 5)
    {
        return None;
    }

    // The shape test (three equal-duration segments, each successive mean
    // must clear the prior by a minimum step) is the shared primitive in
    // `stats::classify_trend`; only the collector-specific minimums
    // (MIB total, MIB/4 per step) and the >=5-samples-per-segment gate above
    // stay local to this wrapper.
    //
    // `first_mean`/`middle_mean`/`last_mean` above are recomputed a second
    // time inside `classify_trend` (in `f64`, from the same three windows).
    // That's intentional duplication, not an oversight: this function needs
    // the `u128`-summed, precision-preserving means for the reported MB
    // evidence fields below, while `classify_trend` only needs `f64` means
    // for its own shape decision -- collapsing the two would mean threading
    // collector-specific mean-computation details into a shared primitive
    // meant to stay generic.
    let points: Vec<TrendPoint> = history
        .iter()
        .map(|point| TrendPoint {
            at_ms: point.timestamp_ms,
            value: point.working_set_bytes as f64,
        })
        .collect();
    let TrendShape::Monotonic { total_growth } = classify_trend(&points, 4 * 60_000, MIB / 4.0)
    else {
        return None;
    };
    if total_growth < MIB {
        return None;
    }

    Some(CollectorGrowth {
        growth_mb: total_growth / MIB,
        first_mean_mb: first_mean / MIB,
        middle_mean_mb: middle_mean / MIB,
        last_mean_mb: last_mean / MIB,
        window_seconds: span_ms as f64 / 1_000.0,
    })
}

fn mean_working_set<'a>(points: impl Iterator<Item = &'a ProcessPoint>) -> (f64, usize) {
    let (sum, count) = points.fold((0_u128, 0_usize), |(sum, count), point| {
        (sum + u128::from(point.working_set_bytes), count + 1)
    });
    if count == 0 {
        (0.0, 0)
    } else {
        (sum as f64 / count as f64, count)
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
        // No detector sets this yet; Phase D does.
        material_change: false,
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
                    0.25,
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
        let mut engine = AlertEngine::default();
        let settings = Settings {
            sustained_samples: 2,
            ..Settings::default()
        };
        let mut system = SystemMetric::default();
        for index in 0..160 {
            system.timestamp_ms = 10 * 60_000 + index * 2_000;
            let working_set = 18 * 1024 * 1024 + index as u64 * 18 * 1024;
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
        let mut history = VecDeque::new();
        for index in 0..151 {
            history.push_back(ProcessPoint {
                timestamp_ms: index * 2_000,
                working_set_bytes: if index < 30 {
                    18 * 1024 * 1024
                } else {
                    20 * 1024 * 1024
                },
                handles: 210,
                threads: 8,
            });
        }
        assert!(collector_working_set_growth(&history).is_none());
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
