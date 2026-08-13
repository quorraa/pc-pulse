use crate::{
    baselines::RunningStats,
    config::Settings,
    models::{Alert, AlertQuality, Evidence, IncidentState, ProcessMetric, Severity, SystemMetric},
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
    pool_baseline: RunningStats,
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

    pub fn evaluate(
        &mut self,
        system: &SystemMetric,
        processes: &[ProcessMetric],
        settings: &Settings,
        calibration: Calibration,
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
                if handle_growth >= settings.handle_growth {
                    candidates.push(process_candidate(
                        process,
                        "handleGrowth",
                        Severity::Warning,
                        settings.sustained_samples,
                        "Handle count is growing",
                        format!("{} is opening handles faster than it releases them.", process.name),
                        vec![
                            evidence("New handles", handle_growth.to_string()),
                            evidence("Current handles", process.handle_count.to_string()),
                            evidence("Window", format!("{window_seconds:.0} seconds")),
                        ],
                        "Inspect the process and its plug-ins. A confirmed restart is safer than force-ending it; update the app if the pattern repeats.",
                    ).with_entry(f64::from(settings.handle_growth)));
                }
                if thread_growth >= settings.thread_growth {
                    candidates.push(process_candidate(
                        process,
                        "threadGrowth",
                        Severity::Warning,
                        settings.sustained_samples,
                        "Thread count is growing",
                        format!("{} is creating threads without returning to its normal range.", process.name),
                        vec![
                            evidence("New threads", thread_growth.to_string()),
                            evidence("Current threads", process.thread_count.to_string()),
                            evidence("Window", format!("{window_seconds:.0} seconds")),
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
            if !self.condition_cleared(&key, &readings, system.timestamp_ms) {
                continue;
            }
            if let Some(mut alert) = self.active.remove(&key) {
                alert.resolved_at_ms = Some(system.timestamp_ms);
                alert.state = IncidentState::Resolved;
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
                terms.material_change,
            );
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
}
