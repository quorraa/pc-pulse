use crate::{
    config::Settings,
    models::{
        AgentContext, AgentLogRollup, AgentProcessRollup, AgentSystemRollup, Alert,
        DiagnosticLevel, DiagnosticLog, DiagnosticLogStatus, HistoryResponse, ProcessMetric,
        RatingOffset, Snapshot,
    },
};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

const MAX_CURRENT_PROCESSES: usize = 96;
const MAX_PROCESS_SUSPECTS: usize = 40;
const MAX_LOG_ROLLUPS: usize = 50;
const MAX_RECENT_ALERTS: usize = 100;

pub struct AgentContextSource<'a> {
    pub now_ms: i64,
    pub window_hours: u32,
    pub snapshot: &'a Snapshot,
    pub settings: &'a Settings,
    pub history: HistoryResponse,
    pub logs: Vec<DiagnosticLog>,
    pub log_status: DiagnosticLogStatus,
    pub alerts: Vec<Alert>,
    /// Non-zero notify-floor adjustments the user's ratings have earned.
    /// Empty on a machine nobody has rated, which is also what every caller
    /// that does not care about ratings passes.
    pub rating_offsets: Vec<RatingOffset>,
}

pub fn build_agent_context(source: AgentContextSource<'_>) -> AgentContext {
    let AgentContextSource {
        now_ms,
        window_hours,
        snapshot,
        settings,
        history,
        logs,
        log_status,
        mut alerts,
        rating_offsets,
    } = source;
    let system_rollup = rollup_system(&history);
    let process_suspects = rollup_processes(&history.processes, snapshot, settings);
    let diagnostic_log_rollups = rollup_logs(logs);
    // Archived findings are deliberately kept out of the evidence bundle —
    // the user has filed them away, so they must stop reaching the analyzer
    // as noise. Investigating one explicitly still works: the client injects
    // the focused finding into the bundle itself.
    alerts.retain(|alert| !alert.archived);
    alerts.truncate(MAX_RECENT_ALERTS);
    let effective_history_from_ms = history
        .system
        .first()
        .map(|sample| sample.timestamp_ms)
        .into_iter()
        .chain(history.processes.first().map(|sample| sample.timestamp_ms))
        .min();
    let mut current = snapshot.clone();
    current.active_alerts.retain(|alert| !alert.archived);
    current.processes = compact_current_processes(&current.processes, &alerts, settings);
    for process in &mut current.processes {
        process.executable_path = redact_user_profile(&process.executable_path);
    }
    let mut limitations = vec![
        "Windows diagnostic logs contain warning/error/critical records from Application and System only; Security is deliberately excluded.".into(),
        "Localized event message rendering is not collected; provider, event ID, level, ownership hints, and bounded XML EventData fields are supplied.".into(),
        "Process command lines and environment variables are deliberately not collected.".into(),
        "Persisted process history contains the 64 highest-pressure processes per 30-second write, not every process.".into(),
        "Correlation is evidence-based but does not prove causation; validate every recommendation before applying it.".into(),
    ];
    if !snapshot.system.etw_active {
        limitations.push(
            "ETW is currently degraded, so launch and process-lifecycle attribution may be incomplete."
                .into(),
        );
    }
    if !rating_offsets.is_empty() {
        limitations.push(
            "Performance ratings have adjusted the notification floors for the listed alert kinds and demand buckets; they never modify baselines, detector thresholds, or severities."
                .into(),
        );
    }
    if log_status.last_error.is_some() {
        limitations.push(
            "The Windows diagnostic log collector reports a current error; treat event-log coverage as incomplete."
                .into(),
        );
    }
    AgentContext {
        schema_version: 1,
        context_id: Uuid::new_v4().to_string(),
        generated_at_ms: now_ms,
        requested_window_hours: window_hours,
        effective_history_from_ms,
        privacy: vec![
            "User-profile path segments are replaced with %USERPROFILE%.".into(),
            "Event fields whose names indicate credentials, tokens, cookies, authorization, passwords, or secrets are replaced with <redacted>.".into(),
            "No command lines, file contents, keystrokes, browser data, or Security event log records are collected.".into(),
        ],
        safety_constraints: vec![
            "Never terminate a process automatically; exact user confirmation is mandatory.".into(),
            "Never execute an optimization-plan command automatically.".into(),
            "Prefer reversible observation and validation before mutation.".into(),
            "Every mutating recommendation must include risk, confirmation, validation, and rollback.".into(),
        ],
        collector_status: log_status,
        current,
        settings: settings.clone(),
        system_rollup,
        process_suspects,
        diagnostic_log_rollups,
        recent_alerts: alerts,
        rating_offsets,
        limitations,
    }
}

fn compact_current_processes(
    processes: &[ProcessMetric],
    alerts: &[Alert],
    settings: &Settings,
) -> Vec<ProcessMetric> {
    let alert_pids: HashSet<u32> = alerts.iter().filter_map(|alert| alert.process_id).collect();
    let mut ranked = processes.to_vec();
    ranked.sort_by(|left, right| {
        current_pressure(right, settings).total_cmp(&current_pressure(left, settings))
    });
    let mut result = Vec::new();
    let mut seen = HashSet::new();
    for process in ranked
        .iter()
        .filter(|process| process.is_agent_candidate || alert_pids.contains(&process.pid))
    {
        if seen.insert((process.pid, process.started_at_ms)) {
            result.push(process.clone());
        }
    }
    for process in ranked {
        if result.len() >= MAX_CURRENT_PROCESSES {
            break;
        }
        if seen.insert((process.pid, process.started_at_ms)) {
            result.push(process);
        }
    }
    result.truncate(MAX_CURRENT_PROCESSES);
    result
}

fn current_pressure(process: &ProcessMetric, settings: &Settings) -> f64 {
    process.cpu_percent / settings.cpu_percent.max(1.0) * 50.0
        + (process.read_bytes_per_sec + process.write_bytes_per_sec)
            / (settings.io_mb_per_sec.max(1.0) * 1_048_576.0)
            * 25.0
        + process.working_set_bytes as f64 / (256.0 * 1_048_576.0)
        + f64::from(process.handle_count) / 1_000.0
        + f64::from(process.thread_count) / 100.0
        + if process.is_agent_candidate { 5.0 } else { 0.0 }
        + if !process.responsive { 25.0 } else { 0.0 }
}

/// `pub(crate)` (rather than private) so `ratings.rs` can build the same
/// trailing-window system percentiles for a rating's performance digest
/// instead of duplicating this logic -- the digest is a compacted sibling of
/// the agent-context evidence bundle.
pub(crate) fn rollup_system(history: &HistoryResponse) -> AgentSystemRollup {
    let cpu: Vec<f64> = history
        .system
        .iter()
        .map(|sample| sample.cpu_percent)
        .collect();
    let memory: Vec<f64> = history
        .system
        .iter()
        .map(|sample| {
            if sample.memory_total_bytes == 0 {
                0.0
            } else {
                sample.memory_used_bytes as f64 / sample.memory_total_bytes as f64 * 100.0
            }
        })
        .collect();
    let disk: Vec<f64> = history
        .system
        .iter()
        .map(|sample| sample.disk_latency_ms)
        .collect();
    let dpc: Vec<f64> = history
        .system
        .iter()
        .map(|sample| sample.dpc_rate)
        .collect();
    let interrupts: Vec<f64> = history
        .system
        .iter()
        .map(|sample| sample.interrupt_rate)
        .collect();
    AgentSystemRollup {
        sample_count: history.system.len(),
        first_sample_ms: history.system.first().map(|sample| sample.timestamp_ms),
        last_sample_ms: history.system.last().map(|sample| sample.timestamp_ms),
        cpu_average_percent: average(&cpu),
        cpu_p95_percent: percentile(&cpu, 0.95),
        cpu_max_percent: maximum(&cpu),
        memory_average_percent: average(&memory),
        memory_p95_percent: percentile(&memory, 0.95),
        memory_max_percent: maximum(&memory),
        disk_latency_p95_ms: percentile(&disk, 0.95),
        disk_latency_max_ms: maximum(&disk),
        dpc_p95_per_sec: percentile(&dpc, 0.95),
        interrupt_p95_per_sec: percentile(&interrupts, 0.95),
    }
}

#[derive(Clone)]
struct ProcessAccumulator {
    first: ProcessMetric,
    last: ProcessMetric,
    count: usize,
    cpu_sum: f64,
    cpu_max: f64,
    io_sum: f64,
    io_max: f64,
    working_set_max: u64,
}

/// `pub(crate)` for the same reason as [`rollup_system`]: `ratings.rs` reuses
/// this pressure-scored, redacted process rollup for the top-processes
/// section of a rating's performance digest.
pub(crate) fn rollup_processes(
    processes: &[ProcessMetric],
    snapshot: &Snapshot,
    settings: &Settings,
) -> Vec<AgentProcessRollup> {
    let mut accumulators: HashMap<(u32, i64), ProcessAccumulator> = HashMap::new();
    for process in processes {
        let io = process.read_bytes_per_sec + process.write_bytes_per_sec;
        accumulators
            .entry((process.pid, process.started_at_ms))
            .and_modify(|item| {
                if process.timestamp_ms < item.first.timestamp_ms {
                    item.first = process.clone();
                }
                if process.timestamp_ms >= item.last.timestamp_ms {
                    item.last = process.clone();
                }
                item.count += 1;
                item.cpu_sum += process.cpu_percent;
                item.cpu_max = item.cpu_max.max(process.cpu_percent);
                item.io_sum += io;
                item.io_max = item.io_max.max(io);
                item.working_set_max = item.working_set_max.max(process.working_set_bytes);
            })
            .or_insert_with(|| ProcessAccumulator {
                first: process.clone(),
                last: process.clone(),
                count: 1,
                cpu_sum: process.cpu_percent,
                cpu_max: process.cpu_percent,
                io_sum: io,
                io_max: io,
                working_set_max: process.working_set_bytes,
            });
    }
    let current_identities: HashSet<(u32, i64)> = snapshot
        .processes
        .iter()
        .map(|process| (process.pid, process.started_at_ms))
        .collect();
    let mut result: Vec<AgentProcessRollup> = accumulators
        .into_values()
        .map(|item| {
            let count = item.count.max(1) as f64;
            let cpu_average = item.cpu_sum / count;
            let io_average = item.io_sum / count;
            let working_set_delta =
                signed_delta(item.last.working_set_bytes, item.first.working_set_bytes);
            let handle_delta =
                i64::from(item.last.handle_count) - i64::from(item.first.handle_count);
            let thread_delta =
                i64::from(item.last.thread_count) - i64::from(item.first.thread_count);
            let pressure_score = cpu_average / settings.cpu_percent.max(1.0) * 40.0
                + item.cpu_max / settings.cpu_percent.max(1.0) * 15.0
                + io_average / (settings.io_mb_per_sec.max(1.0) * 1_048_576.0) * 20.0
                + working_set_delta.max(0) as f64
                    / (settings.memory_growth_mb.max(1.0) * 1_048_576.0)
                    * 15.0
                + handle_delta.max(0) as f64 / f64::from(settings.handle_growth.max(1)) * 5.0
                + thread_delta.max(0) as f64 / f64::from(settings.thread_growth.max(1)) * 5.0
                + if item.last.is_agent_candidate {
                    8.0
                } else {
                    0.0
                }
                + if !item.last.responsive { 25.0 } else { 0.0 }
                + if !current_identities.contains(&(item.last.pid, item.last.started_at_ms)) {
                    0.0
                } else {
                    2.0
                };
            AgentProcessRollup {
                evidence_ref: format!("process:{}:{}", item.last.pid, item.last.started_at_ms),
                pid: item.last.pid,
                parent_pid: item.last.parent_pid,
                name: item.last.name.clone(),
                executable_path: redact_user_profile(&item.last.executable_path),
                started_at_ms: item.last.started_at_ms,
                sample_count: item.count,
                first_sample_ms: item.first.timestamp_ms,
                last_sample_ms: item.last.timestamp_ms,
                cpu_average_percent: cpu_average,
                cpu_max_percent: item.cpu_max,
                working_set_first_bytes: item.first.working_set_bytes,
                working_set_last_bytes: item.last.working_set_bytes,
                working_set_max_bytes: item.working_set_max,
                working_set_delta_bytes: working_set_delta,
                handle_first: item.first.handle_count,
                handle_last: item.last.handle_count,
                handle_delta,
                thread_first: item.first.thread_count,
                thread_last: item.last.thread_count,
                thread_delta,
                io_average_bytes_per_sec: io_average,
                io_max_bytes_per_sec: item.io_max,
                responsive: item.last.responsive,
                has_visible_window: item.last.has_visible_window,
                is_agent_candidate: item.last.is_agent_candidate,
                pressure_score,
            }
        })
        .collect();
    result.sort_by(|left, right| right.pressure_score.total_cmp(&left.pressure_score));
    result.truncate(MAX_PROCESS_SUSPECTS);
    result
}

fn rollup_logs(logs: Vec<DiagnosticLog>) -> Vec<AgentLogRollup> {
    let mut grouped: HashMap<String, AgentLogRollup> = HashMap::new();
    for log in logs {
        grouped
            .entry(log.fingerprint.clone())
            .and_modify(|item| {
                item.count = item.count.saturating_add(1);
                item.first_seen_ms = item.first_seen_ms.min(log.timestamp_ms);
                item.last_seen_ms = item.last_seen_ms.max(log.timestamp_ms);
            })
            .or_insert_with(|| AgentLogRollup {
                evidence_ref: format!("log:{}:{}", log.channel, log.record_id),
                fingerprint: log.fingerprint,
                category: log.category,
                level: log.level,
                provider: log.provider,
                event_id: log.event_id,
                count: 1,
                first_seen_ms: log.timestamp_ms,
                last_seen_ms: log.timestamp_ms,
                related_process: log.related_process,
                representative_fields: log.fields,
            });
    }
    let mut result: Vec<AgentLogRollup> = grouped.into_values().collect();
    result.sort_by(|left, right| {
        log_weight(right)
            .cmp(&log_weight(left))
            .then_with(|| right.last_seen_ms.cmp(&left.last_seen_ms))
    });
    result.truncate(MAX_LOG_ROLLUPS);
    result
}

fn log_weight(log: &AgentLogRollup) -> u64 {
    let severity = match log.level {
        DiagnosticLevel::Critical => 3_u64,
        DiagnosticLevel::Error => 2,
        DiagnosticLevel::Warning => 1,
    };
    severity * 1_000_000 + u64::from(log.count.min(999_999))
}

fn average(values: &[f64]) -> f64 {
    if values.is_empty() {
        0.0
    } else {
        values.iter().sum::<f64>() / values.len() as f64
    }
}

fn maximum(values: &[f64]) -> f64 {
    values.iter().copied().fold(0.0, f64::max)
}

fn percentile(values: &[f64], fraction: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let index = ((sorted.len() - 1) as f64 * fraction).round() as usize;
    sorted[index.min(sorted.len() - 1)]
}

fn signed_delta(current: u64, previous: u64) -> i64 {
    let value = i128::from(current) - i128::from(previous);
    value.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64
}

fn redact_user_profile(value: &str) -> String {
    let lower = value.to_ascii_lowercase();
    let Some(marker) = lower.find(":\\users\\") else {
        return value.to_string();
    };
    let username_start = marker + ":\\users\\".len();
    let Some(relative_end) = value[username_start..].find('\\') else {
        return "%USERPROFILE%".into();
    };
    let username_end = username_start + relative_end;
    format!("%USERPROFILE%{}", &value[username_end..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{DiagnosticCategory, DiagnosticField};

    fn process(timestamp_ms: i64, cpu: f64, working_set: u64) -> ProcessMetric {
        ProcessMetric {
            timestamp_ms,
            pid: 42,
            parent_pid: 7,
            name: "codex.exe".into(),
            executable_path: r"C:\Users\xavier\bin\codex.exe".into(),
            cpu_percent: cpu,
            working_set_bytes: working_set,
            private_bytes: working_set,
            handle_count: 100 + timestamp_ms as u32,
            thread_count: 10,
            read_bytes_per_sec: 1_000.0,
            write_bytes_per_sec: 2_000.0,
            total_read_bytes: 0,
            total_write_bytes: 0,
            started_at_ms: 1,
            session_id: 1,
            responsive: true,
            has_visible_window: false,
            launch_duration_ms: None,
            is_agent_candidate: true,
        }
    }

    #[test]
    fn builds_bounded_redacted_process_rollup() {
        let history = vec![process(10, 20.0, 100), process(20, 40.0, 300)];
        let snapshot = Snapshot {
            processes: vec![process(20, 40.0, 300)],
            ..Snapshot::default()
        };
        let rollups = rollup_processes(&history, &snapshot, &Settings::default());
        assert_eq!(rollups.len(), 1);
        assert_eq!(rollups[0].cpu_average_percent, 30.0);
        assert_eq!(rollups[0].working_set_delta_bytes, 200);
        assert_eq!(rollups[0].executable_path, r"%USERPROFILE%\bin\codex.exe");
    }

    #[test]
    fn groups_repeated_diagnostic_events() {
        let log = DiagnosticLog {
            timestamp_ms: 100,
            channel: "System".into(),
            provider: "disk".into(),
            event_id: 153,
            record_id: 9,
            level: DiagnosticLevel::Warning,
            category: DiagnosticCategory::Storage,
            process_id: None,
            thread_id: None,
            related_process: None,
            fingerprint: "disk:153:system".into(),
            fields: vec![DiagnosticField {
                name: "Device".into(),
                value: r"\Device\Harddisk0".into(),
            }],
        };
        let mut second = log.clone();
        second.timestamp_ms = 200;
        second.record_id = 10;
        let grouped = rollup_logs(vec![log, second]);
        assert_eq!(grouped.len(), 1);
        assert_eq!(grouped[0].count, 2);
        assert_eq!(grouped[0].last_seen_ms, 200);
    }

    #[test]
    fn archived_findings_are_excluded_from_the_evidence_bundle() {
        use crate::models::{Alert, DiagnosticLogStatus, HistoryResponse, Severity};
        let alert = |id: &str, archived: bool| Alert {
            id: id.into(),
            kind: "sustainedCpu".into(),
            severity: Severity::Warning,
            first_seen_ms: 1,
            last_seen_ms: 2,
            process_id: None,
            process_name: None,
            title: "t".into(),
            explanation: "e".into(),
            evidence: Vec::new(),
            recommendation: "r".into(),
            acknowledged: false,
            occurrence_count: 1,
            resolved_at_ms: None,
            archived,
            fingerprint: String::new(),
            state: crate::models::IncidentState::Open,
            quality: crate::models::AlertQuality::default(),
            notify: true,
            notify_generation: 0,
        };
        let snapshot = Snapshot {
            active_alerts: vec![alert("live", false), alert("filed", true)],
            ..Snapshot::default()
        };
        let context = build_agent_context(AgentContextSource {
            now_ms: 1_000,
            window_hours: 1,
            snapshot: &snapshot,
            settings: &Settings::default(),
            history: HistoryResponse {
                system: Vec::new(),
                processes: Vec::new(),
            },
            logs: Vec::new(),
            log_status: DiagnosticLogStatus::default(),
            alerts: vec![alert("recent", false), alert("recent-filed", true)],
            rating_offsets: Vec::new(),
        });
        assert_eq!(
            context
                .recent_alerts
                .iter()
                .map(|alert| alert.id.as_str())
                .collect::<Vec<_>>(),
            vec!["recent"]
        );
        assert_eq!(
            context
                .current
                .active_alerts
                .iter()
                .map(|alert| alert.id.as_str())
                .collect::<Vec<_>>(),
            vec!["live"]
        );
    }

    #[test]
    fn percentile_uses_nearest_rank_position() {
        assert_eq!(percentile(&[1.0, 2.0, 3.0, 4.0, 100.0], 0.95), 100.0);
        assert_eq!(percentile(&[], 0.95), 0.0);
    }
}
