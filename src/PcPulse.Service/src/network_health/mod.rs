//! Service-owned, sparse network diagnostics. No shells, child processes,
//! packet trace, unbounded queue, or blocking work on the collector loop.
pub mod native;

use crate::models::{DiagnosticLog, Evidence, Severity};
use crossbeam_channel::{Receiver, Sender, bounded};
use native::{ProbeReport, ProbeTiming, TcpPortUsage};
use serde::{Deserialize, Serialize};
use std::{
    collections::VecDeque,
    thread,
    time::{Duration, Instant},
};

const STARTUP_DELAY: Duration = Duration::from_secs(60);
const HEALTHY_INTERVAL: Duration = Duration::from_secs(300);
const CONFIRM_INTERVAL: Duration = Duration::from_secs(60);
const BACKOFF_INTERVAL: Duration = Duration::from_secs(900);
const STALL_LIMIT: Duration = Duration::from_secs(30);
const EVENT_WINDOW_MS: i64 = 15 * 60_000;
const SLOW_DNS_MS: u64 = 1_500;

#[derive(Debug, Clone)]
pub struct NetworkFinding {
    pub observed_at_ms: i64,
    pub kind: &'static str,
    pub severity: Severity,
    pub title: String,
    pub explanation: String,
    pub evidence: Vec<Evidence>,
    pub recommendation: String,
    pub corroborating_signals: u32,
    pub notify: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, rename_all = "camelCase")]
pub struct NetworkHealthStatus {
    pub enabled: bool,
    pub state: String,
    pub last_probe_ms: Option<i64>,
    pub next_probe_ms: Option<i64>,
    pub completed_probes: u64,
    pub last_duration_ms: u64,
    pub consecutive_failures: u32,
    pub topology_changes: u64,
    pub recovered_at_ms: Option<i64>,
    pub worker_stalled: bool,
    pub latest: Option<ProbeReport>,
    pub last_port_event_ms: Option<i64>,
    pub port_snapshot: Option<TcpPortUsage>,
}

impl Default for NetworkHealthStatus {
    fn default() -> Self {
        Self {
            enabled: false,
            state: "disabled".into(),
            last_probe_ms: None,
            next_probe_ms: None,
            completed_probes: 0,
            last_duration_ms: 0,
            consecutive_failures: 0,
            topology_changes: 0,
            recovered_at_ms: None,
            worker_stalled: false,
            latest: None,
            last_port_event_ms: None,
            port_snapshot: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fault {
    Dns,
    Ipv6,
    Connectivity,
}

fn passed(value: &Option<ProbeTiming>) -> bool {
    value.as_ref().is_some_and(|v| v.success)
}
fn failed(value: &Option<ProbeTiming>) -> bool {
    value.as_ref().is_some_and(|v| !v.success)
}
fn normal_slow(report: &ProbeReport) -> bool {
    report
        .normal_dns
        .iter()
        .any(|v| !v.success || v.elapsed_ms >= SLOW_DNS_MS)
}
fn healthy(report: &ProbeReport) -> bool {
    report.detail_error.is_none()
        && report.normal_dns.len() == 2
        && report
            .normal_dns
            .iter()
            .all(|v| v.success && v.elapsed_ms < 1_000)
}
fn recovery_confirmed(report: &ProbeReport, active: Option<&NetworkFinding>) -> bool {
    if !healthy(report) || report.route_mismatch {
        return false;
    }
    match active.map(|finding| finding.kind) {
        Some("networkIpv6") => {
            report.has_ipv6_route
                && passed(&report.public_ipv6_dns)
                && passed(&report.ipv6_tcp)
                && (report.configured_ipv6_dns_count == 0 || passed(&report.configured_ipv6_dns))
        }
        Some("networkConnectivity") => passed(&report.ipv4_dns) && passed(&report.ipv4_tcp),
        _ => true,
    }
}
fn classify(report: &ProbeReport) -> Option<Fault> {
    if report.detail_error.is_some() || report.route_mismatch {
        return None;
    }
    // A missing route is normal on IPv4-only networks. Public DNS alone can
    // be blocked by policy, so also require the independent TCP comparison.
    if report.has_ipv6_route
        && report.configured_ipv6_dns_count > 0
        && passed(&report.ipv4_dns)
        && passed(&report.ipv4_tcp)
        && failed(&report.configured_ipv6_dns)
        && failed(&report.public_ipv6_dns)
        && failed(&report.ipv6_tcp)
    {
        Some(Fault::Ipv6)
    } else if normal_slow(report) && passed(&report.ipv4_dns) {
        Some(Fault::Dns)
    } else if normal_slow(report) && failed(&report.ipv4_tcp) && failed(&report.ipv4_dns) {
        Some(Fault::Connectivity)
    } else {
        None
    }
}

fn timing(value: &Option<ProbeTiming>) -> String {
    match value {
        None => "not tested / not configured".into(),
        Some(v) if v.success => format!("{} ms", v.elapsed_ms),
        Some(v) if v.timed_out => format!("timed out after {} ms", v.elapsed_ms),
        Some(v) => format!("failed after {} ms", v.elapsed_ms),
    }
}
fn row(label: &str, value: impl Into<String>) -> Evidence {
    Evidence {
        label: label.into(),
        value: value.into(),
    }
}
fn finding(fault: Fault, report: &ProbeReport, confirmations: u32) -> NetworkFinding {
    let (kind, title, explanation, recommendation) = match fault {
        Fault::Ipv6 => (
            "networkIpv6",
            "IPv6 DNS and connections repeatedly fail",
            "IPv4 controls work, while configured and public IPv6 DNS plus an IPv6 connection fail. An unreachable IPv6 resolver can delay Windows name lookups. One PC cannot identify the router, ISP, VPN, or local filter responsible.",
            "Compare a second device on the same network with cellular fallback and VPN paused for that test. Restore the VPN afterward. If both devices fail, save work and restart the router when a brief outage is acceptable, then recheck. If it persists, ask the ISP to check IPv6 prefix routing. Keep security protection enabled; changing DNS servers alone cannot repair an unreachable IPv6 path.",
        ),
        Fault::Dns => (
            "networkDns",
            "Windows DNS is repeatedly slow",
            "Windows name lookups are slow or fail while a direct public IPv4 DNS query responds. This establishes a resolver-path difference, not which DNS server or application caused it. Service-context checks can differ from a user's VPN or browser DNS.",
            "Review the active adapter's DNS servers and VPN or managed-network DNS policy. Compare another device. Browser encrypted DNS can provide temporary relief, but does not repair other apps. Recheck after a network change; avoid flushing or rewriting settings repeatedly without measured improvement.",
        ),
        Fault::Connectivity => (
            "networkConnectivity",
            "Public network checks repeatedly failed",
            "Windows DNS and the public IPv4 DNS/connection controls failed in repeated checks. An offline network, captive portal, VPN, firewall policy, or upstream outage can produce this result; no app is identified as responsible.",
            "Check the connection and any sign-in portal, then compare another device. On a managed network, public probe endpoints may be intentionally blocked. Do not disable protection or reset networking automatically.",
        ),
    };
    let native_dns = report
        .normal_dns
        .iter()
        .map(|v| {
            if v.success {
                format!("{} ms", v.elapsed_ms)
            } else {
                format!("failed/timeout at {} ms", v.elapsed_ms)
            }
        })
        .collect::<Vec<_>>()
        .join(", ");
    NetworkFinding {
        observed_at_ms: report.observed_at_ms,
        kind,
        severity: Severity::Warning,
        title: title.into(),
        explanation: explanation.into(),
        recommendation: recommendation.into(),
        evidence: vec![
            row("Windows DNS (fixed public names)", native_dns),
            row("Independent checks", confirmations.to_string()),
            row("IPv4 DNS control", timing(&report.ipv4_dns)),
            row("Configured IPv6 DNS", timing(&report.configured_ipv6_dns)),
            row("Public IPv6 DNS", timing(&report.public_ipv6_dns)),
            row("IPv4 TCP control", timing(&report.ipv4_tcp)),
            row("IPv6 TCP control", timing(&report.ipv6_tcp)),
            row("VPN/tunnel detected", report.vpn_present.to_string()),
            row(
                "Scope",
                "DNS and TCP checks, not full page loading or upload processing",
            ),
        ],
        corroborating_signals: if fault == Fault::Ipv6 { 3 } else { 1 },
        notify: confirmations >= 2,
    }
}

#[derive(Default)]
struct Detector {
    pending: Option<Fault>,
    failures: u32,
    successes: u32,
    topology: Option<u64>,
    last_observed: Option<i64>,
    /// At most three complete observations on the current topology. A
    /// neutral observation occupies a slot without voting for a fault.
    recent: VecDeque<(i64, Option<Fault>)>,
    active: Option<NetworkFinding>,
}
impl Detector {
    const CONFIRM_WINDOW_MS: i64 = 10 * 60_000;
    const CONFIRM_OBSERVATIONS: usize = 3;

    fn observe(&mut self, report: &ProbeReport, status: &mut NetworkHealthStatus) -> Duration {
        if self
            .last_observed
            .is_some_and(|last| report.observed_at_ms <= last)
        {
            return HEALTHY_INTERVAL;
        }
        self.last_observed = Some(report.observed_at_ms);
        if self
            .topology
            .is_some_and(|prior| prior != report.topology_id)
        {
            self.pending = None;
            self.failures = 0;
            self.successes = 0;
            self.recent.clear();
            status.topology_changes = status.topology_changes.saturating_add(1);
        }
        self.topology = Some(report.topology_id);
        // Prune even an incomplete observation: missing data must not leave
        // an ancient failure available to confirm a later, unrelated one.
        self.recent
            .retain(|(at, _)| report.observed_at_ms.saturating_sub(*at) <= Self::CONFIRM_WINDOW_MS);
        let complete =
            report.detail_error.is_none() && !report.route_mismatch && report.normal_dns.len() == 2;
        let fault = complete.then(|| classify(report)).flatten();
        if complete {
            self.recent.push_back((report.observed_at_ms, fault));
            while self.recent.len() > Self::CONFIRM_OBSERVATIONS {
                self.recent.pop_front();
            }
        }
        if let Some(fault) = fault {
            self.successes = 0;
            let uninterrupted = self.pending == Some(fault);
            self.failures = if uninterrupted {
                self.failures.saturating_add(1)
            } else {
                1
            };
            self.pending = Some(fault);
            let matching = self
                .recent
                .iter()
                .filter(|(_, observed)| *observed == Some(fault))
                .count() as u32;
            let kind = match fault {
                Fault::Dns => "networkDns",
                Fault::Ipv6 => "networkIpv6",
                Fault::Connectivity => "networkConnectivity",
            };
            // Persistent faults back off to fifteen minutes between probes,
            // outside the initial confirmation window. Keep a confirmed fault
            // current on uninterrupted matching failures; a healthy/unknown
            // observation or topology change breaks this continuation.
            let continuing = uninterrupted
                && self
                    .active
                    .as_ref()
                    .is_some_and(|active| active.kind == kind && active.notify);
            let confirmed = matching >= 2 || continuing;
            status.consecutive_failures = self.failures;
            status.state = if confirmed { "degraded" } else { "confirming" }.into();
            if confirmed {
                let mut active = finding(fault, report, matching);
                active.notify = true;
                active
                    .evidence
                    .retain(|entry| entry.label != "Independent checks");
                active.evidence.push(row(
                    "Matching recent observations",
                    format!(
                        "{matching} of {} complete checks in the last 10 minutes (maximum 3)",
                        self.recent.len()
                    ),
                ));
                active.evidence.push(row(
                    "Consecutive matching faults",
                    self.failures.to_string(),
                ));
                if matching < 2 {
                    active.evidence.push(row(
                        "Confirmation",
                        "Previously confirmed fault; uninterrupted failures continue after probe backoff",
                    ));
                } else if self.failures == 1 {
                    active.title = match fault {
                        Fault::Dns => "Windows DNS is intermittently slow",
                        Fault::Ipv6 => "IPv6 DNS and connections fail intermittently",
                        Fault::Connectivity => "Public network checks fail intermittently",
                    }
                    .into();
                }
                self.active = Some(active);
            } else if let Some(active) = &mut self.active {
                active.notify = false;
            }
            if self.failures >= 3 {
                BACKOFF_INTERVAL
            } else {
                CONFIRM_INTERVAL
            }
        } else if recovery_confirmed(report, self.active.as_ref()) {
            self.failures = 0;
            self.pending = None;
            self.successes = self.successes.saturating_add(1);
            status.consecutive_failures = 0;
            if self.active.is_some() && self.successes < 2 {
                status.state = "verifyingRecovery".into();
                if let Some(active) = &mut self.active {
                    active.observed_at_ms = report.observed_at_ms;
                    active.notify = false;
                    active.evidence.retain(|v| v.label != "Recovery check");
                    active.evidence.push(row(
                        "Recovery check",
                        "First successful Windows DNS check; waiting for confirmation",
                    ));
                }
                CONFIRM_INTERVAL
            } else {
                if self.active.take().is_some() {
                    status.recovered_at_ms = Some(report.observed_at_ms);
                }
                status.state = "healthy".into();
                HEALTHY_INTERVAL
            }
        } else {
            // Unsupported, transient, incomplete or missing observations do
            // not count as recovery or as another failed confirmation.
            self.pending = None;
            self.failures = 0;
            self.successes = 0;
            status.consecutive_failures = 0;
            status.state = "inconclusive".into();
            if let Some(active) = &mut self.active {
                active.notify = false;
                active.observed_at_ms = report.observed_at_ms;
            }
            HEALTHY_INTERVAL
        }
    }
}

struct Job {
    epoch: u64,
    force_comparison: bool,
    sample_ports: bool,
}
struct Finished {
    epoch: u64,
    report: ProbeReport,
    ports: Option<TcpPortUsage>,
    elapsed_ms: u64,
}
struct Worker {
    requests: Option<Sender<Job>>,
    results: Receiver<Finished>,
    thread: Option<thread::JoinHandle<()>>,
}
impl Worker {
    fn start() -> std::io::Result<Self> {
        let (tx, jobs) = bounded::<Job>(1);
        let (results, rx) = bounded(1);
        let handle = thread::Builder::new()
            .name("pcpulse-network".into())
            .stack_size(512 * 1024)
            .spawn(move || {
                while let Ok(job) = jobs.recv() {
                    let started = Instant::now();
                    let ports = if job.sample_ports {
                        native::tcp_port_usage()
                    } else {
                        None
                    };
                    let report = native::probe(job.force_comparison);
                    if results
                        .try_send(Finished {
                            epoch: job.epoch,
                            report,
                            ports,
                            elapsed_ms: started.elapsed().as_millis().min(u64::MAX as u128) as u64,
                        })
                        .is_err()
                    {
                        break;
                    }
                }
            })?;
        Ok(Self {
            requests: Some(tx),
            results: rx,
            thread: Some(handle),
        })
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        self.requests.take();
        // Do not block service shutdown on a damaged Windows network API.
        // There is exactly one worker; it is never replaced after a stall.
        if let Some(handle) = self.thread.take()
            && handle.is_finished()
        {
            let _ = handle.join();
        }
    }
}

pub struct NetworkMonitor {
    status: NetworkHealthStatus,
    detector: Detector,
    worker: Option<Worker>,
    flight: Option<Instant>,
    next_due: Instant,
    last_started: Option<Instant>,
    epoch: u64,
    force: bool,
    ports_pending: bool,
    port_events: VecDeque<(i64, u64)>,
    dirty: bool,
    stall_at_ms: i64,
}
impl Default for NetworkMonitor {
    fn default() -> Self {
        Self::new(Instant::now())
    }
}
impl NetworkMonitor {
    fn new(now: Instant) -> Self {
        Self {
            status: NetworkHealthStatus::default(),
            detector: Detector::default(),
            worker: None,
            flight: None,
            next_due: now + STARTUP_DELAY,
            last_started: None,
            epoch: 0,
            force: false,
            ports_pending: false,
            port_events: VecDeque::new(),
            dirty: false,
            stall_at_ms: 0,
        }
    }
    pub fn status(&self) -> NetworkHealthStatus {
        self.status.clone()
    }
    pub fn observe_logs(&mut self, logs: &[DiagnosticLog], now_ms: i64, now: Instant) {
        if !self.status.enabled {
            return;
        }
        for log in logs {
            if log.channel != "System"
                || log.timestamp_ms > now_ms
                || now_ms - log.timestamp_ms > 120_000
            {
                continue;
            }
            let provider = log.provider.to_ascii_lowercase();
            let port = (provider == "tcpip" || provider == "microsoft-windows-tcpip")
                && matches!(log.event_id, 4227 | 4231);
            let dns = provider == "microsoft-windows-dns-client" && log.event_id == 1014;
            if port
                && !self
                    .port_events
                    .contains(&(log.timestamp_ms, log.record_id))
            {
                if self.port_events.len() == 32 {
                    self.port_events.pop_front();
                }
                self.port_events
                    .push_back((log.timestamp_ms, log.record_id));
                self.status.last_port_event_ms = Some(
                    self.status
                        .last_port_event_ms
                        .unwrap_or(0)
                        .max(log.timestamp_ms),
                );
                self.status.port_snapshot = None;
                self.ports_pending = true;
                self.dirty = true;
            }
            if port || dns {
                self.force = true;
                let earliest = self
                    .last_started
                    .map_or(self.next_due, |last| last + CONFIRM_INTERVAL);
                self.next_due = self.next_due.min(earliest.max(now));
            }
        }
    }
    pub fn tick(
        &mut self,
        now_ms: i64,
        now: Instant,
        enabled: bool,
        pressure: bool,
    ) -> Option<Vec<NetworkFinding>> {
        if enabled != self.status.enabled {
            self.epoch = self.epoch.wrapping_add(1);
            self.status.enabled = enabled;
            self.status.state = if enabled { "waiting" } else { "disabled" }.into();
            self.detector = Detector::default();
            self.port_events.clear();
            self.status.consecutive_failures = 0;
            self.force = false;
            self.ports_pending = false;
            self.dirty = true;
            self.next_due = now + STARTUP_DELAY;
        }
        let result = self.worker.as_ref().and_then(|w| w.results.try_recv().ok());
        if let Some(result) = result {
            self.flight = None;
            if result.elapsed_ms >= STALL_LIMIT.as_millis() as u64 {
                // The sampler may have been delayed or suspended when the
                // deadline passed. Judge execution time, not queue age.
                self.status.worker_stalled = true;
                self.stall_at_ms = now_ms;
                if enabled {
                    self.status.state = "unavailable".into();
                }
                if let Some(worker) = &mut self.worker {
                    worker.requests.take();
                }
                self.dirty = true;
            } else if enabled && result.epoch == self.epoch && !self.status.worker_stalled {
                self.status.completed_probes = self.status.completed_probes.saturating_add(1);
                self.status.last_probe_ms = Some(result.report.observed_at_ms);
                self.status.last_duration_ms = result.elapsed_ms;
                self.next_due = now + self.detector.observe(&result.report, &mut self.status);
                if result.ports.as_ref().is_some_and(|ports| {
                    ports.observed_at_ms >= self.status.last_port_event_ms.unwrap_or(0)
                }) {
                    self.status.port_snapshot = result.ports;
                }
                self.status.latest = Some(result.report);
                self.dirty = true;
            }
        }
        if self
            .flight
            .is_some_and(|since| now.duration_since(since) >= STALL_LIMIT)
            && !self.status.worker_stalled
        {
            self.status.worker_stalled = true;
            self.stall_at_ms = now_ms;
            self.status.state = "unavailable".into();
            if let Some(w) = &mut self.worker {
                w.requests.take();
            }
            self.dirty = true;
        }
        let previous_count = self.port_events.len();
        self.port_events
            .retain(|(at, _)| now_ms.saturating_sub(*at) < EVENT_WINDOW_MS);
        if previous_count != self.port_events.len() {
            self.dirty = true;
        }
        if enabled && !self.status.worker_stalled && self.flight.is_none() && now >= self.next_due {
            if pressure {
                self.status.state = "deferredForLoad".into();
                self.next_due = now + CONFIRM_INTERVAL;
            } else {
                if self.worker.is_none() {
                    match Worker::start() {
                        Ok(worker) => self.worker = Some(worker),
                        Err(_) => {
                            self.status.worker_stalled = true;
                            self.stall_at_ms = now_ms;
                            self.status.state = "unavailable".into();
                            self.dirty = true;
                        }
                    }
                }
                if let Some(worker) = &self.worker {
                    let job = Job {
                        epoch: self.epoch,
                        force_comparison: self.force || self.detector.active.is_some(),
                        sample_ports: self.ports_pending,
                    };
                    if worker
                        .requests
                        .as_ref()
                        .is_some_and(|tx| tx.try_send(job).is_ok())
                    {
                        self.flight = Some(now);
                        self.last_started = Some(now);
                        self.force = false;
                        self.ports_pending = false;
                        self.status.state = "checking".into();
                    } else {
                        self.status.worker_stalled = true;
                        self.stall_at_ms = now_ms;
                        self.status.state = "unavailable".into();
                        self.dirty = true;
                    }
                }
            }
        }
        self.status.next_probe_ms =
            if enabled && !self.status.worker_stalled && self.flight.is_none() {
                Some(
                    now_ms.saturating_add(
                        self.next_due
                            .saturating_duration_since(now)
                            .as_millis()
                            .min(i64::MAX as u128) as i64,
                    ),
                )
            } else {
                None
            };
        if self.dirty {
            self.dirty = false;
            Some(self.findings())
        } else {
            None
        }
    }
    fn findings(&self) -> Vec<NetworkFinding> {
        if !self.status.enabled {
            return Vec::new();
        }
        let mut findings: Vec<_> = self.detector.active.iter().cloned().collect();
        if !self.port_events.is_empty() {
            let count = if self.port_events.len() == 32 {
                "at least 32".into()
            } else {
                self.port_events.len().to_string()
            };
            let mut evidence = vec![
                row("Windows TCP/IP failures in the last 15 minutes", count),
                row(
                    "Attribution",
                    "The event's requester is not proof of which process holds ports",
                ),
            ];
            if let Some(ports) = &self.status.port_snapshot {
                evidence.push(row(
                    "Later TCP snapshot",
                    format!(
                        "{} TCP rows; {} distinct local ports; {} TIME_WAIT rows",
                        ports.tcp_rows, ports.distinct_local_ports, ports.time_wait_rows
                    ),
                ));
                evidence.push(row(
                    "Snapshot time (UTC milliseconds)",
                    ports.observed_at_ms.to_string(),
                ));
            }
            findings.push(NetworkFinding { observed_at_ms: self.status.last_port_event_ms.unwrap_or(0).max(self.status.port_snapshot.as_ref().map_or(0, |v| v.observed_at_ms)), kind: "networkPorts", severity: Severity::Warning,
                title: "Windows reported a TCP port allocation failure".into(),
                explanation: "A recent TCP/IP event reported that a connection could not obtain or reuse a local port. This is separate from DNS delay. A later low port count does not disprove a brief failure or identify a kernel reservation problem.".into(),
                recommendation: "Correlate repeated failures with a bounded socket-ownership capture. Do not blame the app making the failed request, disable security, or change the port range from this event alone. This finding closes after 15 minutes without a new event; that means quiet, not a proven repair.".into(),
                evidence, corroborating_signals: 0, notify: self.port_events.len() >= 2 });
        }
        if self.status.worker_stalled {
            for finding in &mut findings {
                finding.notify = false;
            }
            findings.push(NetworkFinding { observed_at_ms: self.stall_at_ms, kind: "networkMonitor", severity: Severity::Info,
                title: "Network checks are unavailable".into(), explanation: "The single network worker did not finish within its 30-second watchdog or could not start. Further probes are stopped for this service run; no replacement threads are created and missing data is not reported as recovery.".into(),
                recommendation: "Review service health. Restart PC Pulse's service when convenient to rearm checks; this finding does not call for restarting Windows or the router.".into(),
                evidence: vec![row("Probe worker", "stopped scheduling; collector sampling continues")], corroborating_signals: 0, notify: false });
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn ok(ms: u64) -> ProbeTiming {
        ProbeTiming {
            success: true,
            elapsed_ms: ms,
            timed_out: false,
        }
    }
    fn timeout() -> ProbeTiming {
        ProbeTiming {
            success: false,
            elapsed_ms: 2_000,
            timed_out: true,
        }
    }
    fn report(at: i64, bad: bool) -> ProbeReport {
        ProbeReport {
            observed_at_ms: at,
            topology_id: 1,
            interface_index: 16,
            has_ipv6_route: true,
            configured_ipv6_dns_count: 2,
            normal_dns: vec![if bad { timeout() } else { ok(100) }; 2],
            ipv4_dns: Some(ok(50)),
            configured_ipv6_dns: Some(if bad { timeout() } else { ok(20) }),
            public_ipv6_dns: Some(if bad { timeout() } else { ok(50) }),
            ipv4_tcp: Some(ok(50)),
            ipv6_tcp: Some(if bad { timeout() } else { ok(50) }),
            ..ProbeReport::default()
        }
    }
    fn dns_report(at: i64, slow: bool) -> ProbeReport {
        let mut value = report(at, false);
        if slow {
            value.normal_dns = vec![timeout(), ok(80)];
        }
        value
    }

    #[test]
    fn intermittent_slow_fast_slow_dns_confirms_without_inventing_a_streak() {
        let mut detector = Detector::default();
        let mut status = NetworkHealthStatus::default();
        detector.observe(&dns_report(1, true), &mut status);
        assert!(detector.active.is_none());
        detector.observe(&dns_report(60_001, false), &mut status);
        assert_eq!(status.consecutive_failures, 0);
        assert!(detector.active.is_none());
        let delay = detector.observe(&dns_report(360_001, true), &mut status);
        let active = detector.active.as_ref().unwrap();
        assert_eq!(active.kind, "networkDns");
        assert!(active.notify);
        assert!(active.title.contains("intermittently"));
        assert_eq!(status.state, "degraded");
        assert_eq!(status.consecutive_failures, 1);
        assert_eq!(delay, CONFIRM_INTERVAL);
        assert!(active.evidence.iter().any(|entry| {
            entry.label == "Matching recent observations" && entry.value.starts_with("2 of 3")
        }));
        // Recovery remains two positive checks even after an intermittent
        // rather than consecutive confirmation.
        detector.observe(&dns_report(420_001, false), &mut status);
        assert!(detector.active.is_some());
        detector.observe(&dns_report(480_001, false), &mut status);
        assert!(detector.active.is_none());
    }

    #[test]
    fn one_slow_dns_check_and_two_healthy_checks_cannot_confirm_a_later_blip() {
        let mut detector = Detector::default();
        let mut status = NetworkHealthStatus::default();
        for (at, slow) in [
            (1, true),
            (60_001, false),
            (120_001, false),
            (180_001, true),
        ] {
            detector.observe(&dns_report(at, slow), &mut status);
            assert!(detector.active.is_none());
            assert!(detector.recent.len() <= Detector::CONFIRM_OBSERVATIONS);
        }
        assert_eq!(detector.recent.len(), 3);
        assert_eq!(status.consecutive_failures, 1);
    }

    #[test]
    fn expired_or_different_topology_dns_failures_cannot_be_reused() {
        for topology_change in [false, true] {
            let mut detector = Detector::default();
            let mut status = NetworkHealthStatus::default();
            detector.observe(&dns_report(1, true), &mut status);
            detector.observe(&dns_report(60_001, false), &mut status);
            let mut next = dns_report(
                if topology_change {
                    120_001
                } else {
                    Detector::CONFIRM_WINDOW_MS + 2
                },
                true,
            );
            if topology_change {
                next.topology_id = 2;
            }
            detector.observe(&next, &mut status);
            assert!(detector.active.is_none());
            assert_eq!(status.state, "confirming");
            assert_eq!(status.consecutive_failures, 1);
            assert_eq!(status.topology_changes, u64::from(topology_change));
        }
        // An incomplete report still expires the history, but supplies no
        // fault or recovery vote of its own.
        let mut detector = Detector::default();
        let mut status = NetworkHealthStatus::default();
        detector.observe(&dns_report(1, true), &mut status);
        let mut missing = dns_report(Detector::CONFIRM_WINDOW_MS + 2, true);
        missing.detail_error = Some("probe incomplete".into());
        detector.observe(&missing, &mut status);
        assert!(detector.recent.is_empty());
        assert_eq!(status.consecutive_failures, 0);
        detector.observe(
            &dns_report(Detector::CONFIRM_WINDOW_MS + 60_002, true),
            &mut status,
        );
        assert!(detector.active.is_none());
    }

    #[test]
    fn sparse_copies_and_partial_dns_reports_cannot_supply_confirmation() {
        let mut detector = Detector::default();
        let mut status = NetworkHealthStatus::default();
        for _ in 0..100 {
            detector.observe(&dns_report(1, true), &mut status);
        }
        detector.observe(&dns_report(0, true), &mut status);
        assert!(detector.active.is_none());
        assert_eq!(detector.recent.len(), 1);
        assert_eq!(status.consecutive_failures, 1);
        let mut partial = dns_report(60_001, true);
        partial.normal_dns.pop();
        detector.observe(&partial, &mut status);
        assert!(detector.active.is_none());
        assert_eq!(detector.recent.len(), 1);
        assert_eq!(status.consecutive_failures, 0);
        detector.observe(&dns_report(120_001, true), &mut status);
        assert!(detector.active.as_ref().unwrap().notify);
        assert_eq!(status.consecutive_failures, 1);
    }

    #[test]
    fn confirmed_persistent_fault_survives_fifteen_minute_probe_backoff() {
        let mut detector = Detector::default();
        let mut status = NetworkHealthStatus::default();
        detector.observe(&dns_report(1, true), &mut status);
        detector.observe(&dns_report(60_001, true), &mut status);
        assert_eq!(
            detector.observe(&dns_report(120_001, true), &mut status),
            BACKOFF_INTERVAL
        );
        assert_eq!(
            detector.observe(&dns_report(1_020_001, true), &mut status),
            BACKOFF_INTERVAL
        );
        assert_eq!(detector.recent.len(), 1);
        assert_eq!(status.consecutive_failures, 4);
        let active = detector.active.as_ref().unwrap();
        assert!(active.notify);
        assert_eq!(active.observed_at_ms, 1_020_001);
        assert!(
            active
                .evidence
                .iter()
                .any(|entry| entry.label == "Confirmation")
        );
    }

    #[test]
    fn needs_two_real_checks_and_two_recovery_checks() {
        let mut d = Detector::default();
        let mut s = NetworkHealthStatus::default();
        assert_eq!(d.observe(&report(1, true), &mut s), CONFIRM_INTERVAL);
        assert!(d.active.is_none());
        d.observe(&report(1, true), &mut s);
        assert_eq!(d.failures, 1);
        d.observe(&report(60_001, true), &mut s);
        assert_eq!(d.active.as_ref().unwrap().kind, "networkIpv6");
        assert_eq!(d.observe(&report(120_001, true), &mut s), BACKOFF_INTERVAL);
        d.observe(&report(180_001, false), &mut s);
        assert!(d.active.is_some());
        d.observe(&report(240_001, false), &mut s);
        assert!(d.active.is_none());
        assert_eq!(s.recovered_at_ms, Some(240_001));
    }
    #[test]
    fn absent_ipv6_and_blocked_public_dns_are_not_ipv6_faults() {
        let mut r = report(1, true);
        r.has_ipv6_route = false;
        assert_eq!(classify(&r), Some(Fault::Dns));
        r.normal_dns = vec![ok(40), ok(70)];
        r.ipv4_dns = Some(timeout());
        assert_eq!(classify(&r), None);
    }
    #[test]
    fn missing_data_does_not_recover_and_topology_changes_reset_confirmation() {
        let mut d = Detector::default();
        let mut s = NetworkHealthStatus::default();
        d.observe(&report(1, true), &mut s);
        let mut r = report(60_001, true);
        r.topology_id = 2;
        d.observe(&r, &mut s);
        assert!(d.active.is_none());
        r.observed_at_ms += 60_000;
        d.observe(&r, &mut s);
        assert!(d.active.is_some());
        r.observed_at_ms += 60_000;
        r.detail_error = Some("unavailable".into());
        d.observe(&r, &mut s);
        assert!(d.active.is_some());
        assert!(!d.active.as_ref().unwrap().notify);
    }
    #[test]
    fn startup_and_pressure_never_launch_worker() {
        let now = Instant::now();
        let mut monitor = NetworkMonitor::new(now);
        monitor.tick(0, now, true, false);
        for i in 1..60 {
            monitor.tick(i * 1000, now + Duration::from_secs(i as u64), true, false);
        }
        assert!(monitor.worker.is_none());
        monitor.tick(60_000, now + STARTUP_DELAY, true, true);
        assert!(monitor.worker.is_none());
        assert_eq!(monitor.status.state, "deferredForLoad");
    }

    #[test]
    fn in_flight_job_prevents_overlapping_requests_on_repeated_ticks() {
        let now = Instant::now();
        let mut monitor = NetworkMonitor::new(now);
        monitor.tick(0, now, true, false);
        let (requests, jobs) = bounded(1);
        let (finished, results) = bounded(1);
        monitor.worker = Some(Worker {
            requests: Some(requests),
            results,
            thread: None,
        });

        let started = now + STARTUP_DELAY;
        monitor.tick(60_000, started, true, false);
        // Removing the queued request simulates a worker that has begun work.
        // An empty queue must not be mistaken for an idle worker.
        let job = jobs.try_recv().unwrap();
        assert_eq!(monitor.flight, Some(started));
        assert_eq!(job.epoch, monitor.epoch);
        for seconds in 1..30 {
            monitor.tick(
                60_000 + seconds * 1_000,
                started + Duration::from_secs(seconds as u64),
                true,
                false,
            );
            assert!(jobs.is_empty(), "a second request overlapped a running job");
            assert_eq!(monitor.flight, Some(started));
            assert_eq!(monitor.last_started, Some(started));
            assert!(!monitor.status.worker_stalled);
            assert_eq!(monitor.status.completed_probes, 0);
        }

        assert!(
            finished
                .try_send(Finished {
                    epoch: job.epoch,
                    report: report(89_500, false),
                    ports: None,
                    elapsed_ms: 29_500,
                })
                .is_ok()
        );
        monitor.tick(89_500, started + Duration::from_millis(29_500), true, false);
        assert!(monitor.flight.is_none());
        assert_eq!(monitor.status.completed_probes, 1);
        assert!(
            jobs.is_empty(),
            "completion must retain the scheduled interval"
        );
    }

    #[test]
    fn disabling_in_flight_job_rejects_its_late_result_even_after_reenable() {
        for reenable in [false, true] {
            let now = Instant::now();
            let mut monitor = NetworkMonitor::new(now);
            monitor.tick(0, now, true, false);
            let (requests, jobs) = bounded(1);
            let (finished, results) = bounded(1);
            monitor.worker = Some(Worker {
                requests: Some(requests),
                results,
                thread: None,
            });
            monitor.tick(60_000, now + STARTUP_DELAY, true, false);
            let job = jobs.try_recv().unwrap();
            let cleared = monitor
                .tick(61_000, now + Duration::from_secs(61), false, false)
                .unwrap();
            assert!(cleared.is_empty());
            assert_eq!(monitor.status.state, "disabled");
            assert_ne!(monitor.epoch, job.epoch);
            if reenable {
                monitor.tick(62_000, now + Duration::from_secs(62), true, false);
            }

            assert!(
                finished
                    .try_send(Finished {
                        epoch: job.epoch,
                        report: report(62_500, false),
                        ports: Some(TcpPortUsage {
                            observed_at_ms: 62_500,
                            tcp_rows: 100,
                            distinct_local_ports: 80,
                            time_wait_rows: 20,
                        }),
                        elapsed_ms: 2_500,
                    })
                    .is_ok()
            );
            let update = monitor.tick(63_000, now + Duration::from_secs(63), reenable, false);
            assert!(update.is_none_or(|findings| findings.is_empty()));
            assert!(monitor.findings().is_empty());
            assert!(monitor.flight.is_none());
            assert!(monitor.status.latest.is_none());
            assert!(monitor.status.last_probe_ms.is_none());
            assert!(monitor.status.port_snapshot.is_none());
            assert_eq!(monitor.status.completed_probes, 0);
            assert_eq!(
                monitor.status.state,
                if reenable { "waiting" } else { "disabled" }
            );
            assert!(jobs.is_empty());
        }
    }

    #[test]
    fn ipv6_recovery_requires_positive_path_checks_not_cached_dns() {
        let mut d = Detector::default();
        let mut s = NetworkHealthStatus::default();
        d.observe(&report(1, true), &mut s);
        d.observe(&report(60_001, true), &mut s);
        let mut r = report(120_001, false);
        r.public_ipv6_dns = None;
        r.configured_ipv6_dns = None;
        r.ipv6_tcp = Some(timeout());
        d.observe(&r, &mut s);
        r.observed_at_ms += 60_000;
        d.observe(&r, &mut s);
        assert!(d.active.is_some());
        assert!(!d.active.as_ref().unwrap().notify);
        assert_eq!(s.state, "inconclusive");
        r = report(240_001, false);
        r.route_mismatch = true;
        d.observe(&r, &mut s);
        assert!(d.active.is_some());
    }
    #[test]
    fn changed_network_vetoes_old_attribution_until_reconfirmed() {
        let mut d = Detector::default();
        let mut s = NetworkHealthStatus::default();
        d.observe(&report(1, true), &mut s);
        d.observe(&report(60_001, true), &mut s);
        let mut r = report(120_001, true);
        r.topology_id = 2;
        d.observe(&r, &mut s);
        assert!(!d.active.as_ref().unwrap().notify);
        assert_eq!(s.state, "confirming");
    }
    #[test]
    fn stale_worker_is_not_replaced_and_disabled_clears_findings() {
        let now = Instant::now();
        let mut m = NetworkMonitor::new(now);
        m.tick(0, now, true, false);
        m.flight = Some(now);
        m.tick(31_000, now + Duration::from_secs(31), true, false);
        assert!(m.status.worker_stalled);
        assert!(m.worker.is_none());
        m.tick(3_000_000, now + Duration::from_secs(3_000), true, false);
        assert!(m.worker.is_none());
        assert!(
            m.tick(3_001_000, now + Duration::from_secs(3_001), false, false)
                .unwrap()
                .is_empty()
        );
    }
    #[test]
    fn completed_worker_uses_execution_time_not_result_queue_age() {
        for elapsed_ms in [100, 30_000] {
            let now = Instant::now();
            let mut monitor = NetworkMonitor::new(now);
            monitor.tick(0, now, true, false);
            let (requests, _jobs) = bounded(1);
            let (finished, results) = bounded(1);
            monitor.worker = Some(Worker {
                requests: Some(requests),
                results,
                thread: None,
            });
            monitor.flight = Some(now);
            finished
                .try_send(Finished {
                    epoch: monitor.epoch,
                    report: report(31_000, false),
                    ports: None,
                    elapsed_ms,
                })
                .ok()
                .unwrap();
            monitor.tick(31_000, now + Duration::from_secs(31), true, false);
            assert_eq!(monitor.status.worker_stalled, elapsed_ms >= 30_000);
            assert_eq!(
                monitor.status.completed_probes,
                if elapsed_ms >= 30_000 { 0 } else { 1 }
            );
        }
    }
    #[test]
    fn new_port_event_cannot_reuse_an_older_snapshot_or_blame_requester() {
        let now = Instant::now();
        let mut m = NetworkMonitor::new(now);
        m.tick(0, now, true, false);
        m.status.port_snapshot = Some(TcpPortUsage {
            observed_at_ms: 1,
            ..Default::default()
        });
        let event = DiagnosticLog {
            timestamp_ms: 100,
            channel: "System".into(),
            provider: "Tcpip".into(),
            event_id: 4231,
            record_id: 42,
            level: crate::models::DiagnosticLevel::Warning,
            category: crate::models::DiagnosticCategory::Network,
            process_id: Some(123),
            thread_id: None,
            related_process: Some("requester.exe".into()),
            fingerprint: String::new(),
            fields: Vec::new(),
        };
        m.observe_logs(std::slice::from_ref(&event), 100, now);
        m.observe_logs(&[event], 100, now);
        assert!(m.status.port_snapshot.is_none());
        assert_eq!(m.port_events.len(), 1);
        let findings = m.findings();
        assert_eq!(findings.len(), 1);
        assert!(!findings[0].notify);
        assert!(!format!("{:?}", findings).contains("requester.exe"));
        m.tick(EVENT_WINDOW_MS + 101, now, true, false);
        assert!(m.findings().is_empty());
    }
}
