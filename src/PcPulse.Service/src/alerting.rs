use crate::{
    baselines::RunningStats,
    config::Settings,
    models::{Alert, Evidence, IncidentState, ProcessMetric, Severity, SystemMetric},
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
    baselines: HashMap<(u32, i64), ProcessBaseline>,
    history: HashMap<(u32, i64), VecDeque<ProcessPoint>>,
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
    ) -> Evaluation {
        let mut candidates = Vec::new();
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
            });
        }

        let present: HashSet<String> = candidates
            .iter()
            .map(|candidate| candidate.key.clone())
            .collect();
        let mut changed = Vec::new();
        for candidate in candidates {
            // The condition is present again, so any exit clock it had
            // started is void.
            self.below_exit_since.remove(&candidate.key);
            let streak = self.streaks.entry(candidate.key.clone()).or_default();
            *streak = streak.saturating_add(1);
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
                changed.push(alert.clone());
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
                    quality: crate::models::AlertQuality::default(),
                    notify: true,
                    notify_generation: reopened.as_ref().map_or(0, |prior| prior.notify_generation),
                };
                changed.push(alert.clone());
                self.active.insert(candidate.key, alert);
            }
        }

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
                    },
                );
                changed.push(alert);
            }
            self.guards.remove(&key);
            self.below_exit_since.remove(&key);
            self.streaks.remove(&key);
        }
        // Streaks survive for still-open incidents: a condition held open by
        // hysteresis must not have to re-earn its sustained window when its
        // value crosses back above the entry threshold.
        let active = &self.active;
        self.streaks
            .retain(|key, _| present.contains(key) || active.contains_key(key));

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
        let evaluation = engine.evaluate(&system, &[process(1_000, 99.0, 20)], &settings);
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
            );
        }
        assert_eq!(engine.active.len(), 1);
        // Recovery clears the exit threshold immediately, but the finding
        // still has to hold for one full sustained window (3 x 2 s) before it
        // closes -- see `resolution_requires_the_exit_threshold_and_hold_window`.
        let mut resolved = None;
        for _ in 0..4 {
            system.timestamp_ms += 2_000;
            let evaluation =
                engine.evaluate(&system, &[process(system.timestamp_ms, 1.0, 20)], &settings);
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
        (0..count)
            .map(|index| {
                let timestamp_ms = start_ms + index * settings.sample_interval_ms as i64;
                let system = SystemMetric {
                    timestamp_ms,
                    ..SystemMetric::default()
                };
                engine.evaluate(&system, &[process(timestamp_ms, cpu, 20)], settings)
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
            engine.evaluate(&system, &[slow], &settings);
        }
        let opened = only_active(&engine);
        assert_eq!(opened.kind, "slowLaunch");
        assert_eq!(opened.fingerprint, "slowLaunch:42:1");

        system.timestamp_ms += 2_000;
        let evaluation =
            engine.evaluate(&system, &[process(system.timestamp_ms, 1.0, 20)], &settings);
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
}
