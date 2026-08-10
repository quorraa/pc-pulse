use crate::{
    config::Settings,
    models::{Alert, Evidence, ProcessMetric, Severity, SystemMetric},
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

#[derive(Debug, Clone, Default)]
struct RunningStats {
    samples: u64,
    mean: f64,
    variance: f64,
}

impl RunningStats {
    fn observe(&mut self, value: f64) {
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

    fn deviates(&self, value: f64, sigma: f64, minimum_delta: f64) -> bool {
        if self.samples < 15 {
            return true;
        }
        let deviation = self.variance.max(0.0).sqrt();
        value > self.mean + (sigma * deviation).max(minimum_delta)
    }
}

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
    baselines: HashMap<(u32, i64), ProcessBaseline>,
    history: HashMap<(u32, i64), VecDeque<ProcessPoint>>,
    pool_baseline: RunningStats,
}

impl AlertEngine {
    pub fn evaluate(
        &mut self,
        system: &SystemMetric,
        processes: &[ProcessMetric],
        settings: &Settings,
    ) -> Evaluation {
        let mut candidates = Vec::new();
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
                ));
            }

            if let Some(prior) = prior {
                let memory_growth = process
                    .working_set_bytes
                    .saturating_sub(prior.working_set_bytes);
                let handle_growth = process.handle_count.saturating_sub(prior.handles);
                let thread_growth = process.thread_count.saturating_sub(prior.threads);
                let window_seconds =
                    ((process.timestamp_ms - prior.timestamp_ms) as f64 / 1_000.0).max(1.0);
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
                    ));
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
                    ));
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
                    ));
                }
            }

            let io_mb = (process.read_bytes_per_sec + process.write_bytes_per_sec) / MIB;
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
                ));
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
                    ));
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

        if system.disk_latency_ms >= settings.disk_latency_ms {
            let owner = processes.iter().max_by(|a, b| {
                (a.read_bytes_per_sec + a.write_bytes_per_sec)
                    .total_cmp(&(b.read_bytes_per_sec + b.write_bytes_per_sec))
            });
            candidates.push(Candidate {
                key: format!("diskLatency:{}", owner.map_or(0, |p| p.pid)),
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
            });
        }

        let present: HashSet<String> = candidates
            .iter()
            .map(|candidate| candidate.key.clone())
            .collect();
        let mut changed = Vec::new();
        for candidate in candidates {
            let streak = self.streaks.entry(candidate.key.clone()).or_default();
            *streak = streak.saturating_add(1);
            if *streak < candidate.required_samples {
                continue;
            }
            if let Some(alert) = self.active.get_mut(&candidate.key) {
                alert.last_seen_ms = system.timestamp_ms;
                alert.occurrence_count = alert.occurrence_count.saturating_add(1);
                alert.evidence = candidate.evidence;
                changed.push(alert.clone());
            } else {
                let alert = Alert {
                    id: Uuid::new_v4().to_string(),
                    kind: candidate.kind.into(),
                    severity: candidate.severity,
                    first_seen_ms: system.timestamp_ms,
                    last_seen_ms: system.timestamp_ms,
                    process_id: candidate.pid,
                    process_name: candidate.process_name,
                    title: candidate.title,
                    explanation: candidate.explanation,
                    evidence: candidate.evidence,
                    recommendation: candidate.recommendation,
                    acknowledged: false,
                    occurrence_count: 1,
                    resolved_at_ms: None,
                    archived: false,
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
            if let Some(mut alert) = self.active.remove(&key) {
                alert.resolved_at_ms = Some(system.timestamp_ms);
                changed.push(alert);
            }
            self.streaks.remove(&key);
        }
        self.streaks.retain(|key, _| present.contains(key));

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
    let growth = last_mean - first_mean;
    let first_step = middle_mean - first_mean;
    let second_step = last_mean - middle_mean;
    if growth < MIB || first_step < MIB / 4.0 || second_step < MIB / 4.0 {
        return None;
    }
    Some(CollectorGrowth {
        growth_mb: growth / MIB,
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
        key: format!("{kind}:{}:{}", process.pid, process.started_at_ms),
        kind,
        severity,
        required_samples,
        pid: Some(process.pid),
        process_name: Some(process.name.clone()),
        title: title.into(),
        explanation,
        evidence,
        recommendation: recommendation.into(),
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
                    &[collector_process(system.timestamp_ms, 0, 1.0, 16 << 20, 200)],
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
                    &[collector_process(system.timestamp_ms, 0, 1.0, 40 << 20, 200)],
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
        system.timestamp_ms += 2_000;
        let evaluation =
            engine.evaluate(&system, &[process(system.timestamp_ms, 1.0, 20)], &settings);
        assert!(evaluation.active.is_empty());
        assert!(
            evaluation
                .changed
                .iter()
                .any(|alert| alert.resolved_at_ms.is_some())
        );
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
        let evaluation =
            engine.evaluate(&system, &[process(system.timestamp_ms, 95.0, 20)], &settings);
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
