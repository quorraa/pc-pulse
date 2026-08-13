use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SystemMetric {
    pub timestamp_ms: i64,
    pub cpu_percent: f64,
    pub memory_used_bytes: u64,
    pub memory_total_bytes: u64,
    pub disk_latency_ms: f64,
    pub disk_read_bytes_per_sec: f64,
    pub disk_write_bytes_per_sec: f64,
    /// `\Network Interface(*)\Bytes Total/sec` summed across instances.
    /// Absent in snapshots persisted by services older than the interrupt
    /// root-cause monitor; the default keeps old JSON deserializing and the
    /// protocol version is unchanged.
    #[serde(default)]
    pub network_bytes_per_sec: f64,
    pub paged_pool_bytes: u64,
    pub nonpaged_pool_bytes: u64,
    pub dpc_rate: f64,
    pub interrupt_rate: f64,
    pub process_count: u32,
    pub thread_count: u32,
    pub handle_count: u32,
    pub collector_working_set_bytes: u64,
    pub collector_cpu_percent: f64,
    pub collector_handle_count: u32,
    pub etw_events_per_sec: f64,
    pub dropped_etw_events: u64,
    pub etw_active: bool,
}

impl Default for SystemMetric {
    fn default() -> Self {
        Self {
            timestamp_ms: 0,
            cpu_percent: 0.0,
            memory_used_bytes: 0,
            memory_total_bytes: 0,
            disk_latency_ms: 0.0,
            disk_read_bytes_per_sec: 0.0,
            disk_write_bytes_per_sec: 0.0,
            network_bytes_per_sec: 0.0,
            paged_pool_bytes: 0,
            nonpaged_pool_bytes: 0,
            dpc_rate: 0.0,
            interrupt_rate: 0.0,
            process_count: 0,
            thread_count: 0,
            handle_count: 0,
            collector_working_set_bytes: 0,
            collector_cpu_percent: 0.0,
            collector_handle_count: 0,
            etw_events_per_sec: 0.0,
            dropped_etw_events: 0,
            etw_active: false,
        }
    }
}

/// One high-rate system-level telemetry sample for smooth-mode clients.
///
/// Produced by the dedicated live PDH query (no process enumeration) at up
/// to 8 Hz while a client keeps requesting `live`. `available` is `false`
/// when the sampler has not yet warmed — rate counters need a prior
/// collection, so the first ~125 ms after the live loop starts honestly
/// report no data instead of fabricated zero rates.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LiveSample {
    pub available: bool,
    pub timestamp_ms: i64,
    pub cpu_percent: f64,
    pub memory_used_bytes: u64,
    pub memory_total_bytes: u64,
    pub disk_read_bytes_per_sec: f64,
    pub disk_write_bytes_per_sec: f64,
    pub disk_latency_ms: f64,
    pub network_bytes_per_sec: f64,
    pub dpc_rate: f64,
    pub interrupt_rate: f64,
}

impl LiveSample {
    /// The honest "not warmed up yet" payload served before the live loop
    /// holds a rate-valid collection.
    pub fn unavailable(timestamp_ms: i64) -> Self {
        Self {
            available: false,
            timestamp_ms,
            cpu_percent: 0.0,
            memory_used_bytes: 0,
            memory_total_bytes: 0,
            disk_read_bytes_per_sec: 0.0,
            disk_write_bytes_per_sec: 0.0,
            disk_latency_ms: 0.0,
            network_bytes_per_sec: 0.0,
            dpc_rate: 0.0,
            interrupt_rate: 0.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ProcessMetric {
    pub timestamp_ms: i64,
    pub pid: u32,
    pub parent_pid: u32,
    pub name: String,
    pub executable_path: String,
    pub cpu_percent: f64,
    pub working_set_bytes: u64,
    pub private_bytes: u64,
    pub handle_count: u32,
    pub thread_count: u32,
    pub read_bytes_per_sec: f64,
    pub write_bytes_per_sec: f64,
    pub total_read_bytes: u64,
    pub total_write_bytes: u64,
    pub started_at_ms: i64,
    pub session_id: u32,
    pub responsive: bool,
    pub has_visible_window: bool,
    pub launch_duration_ms: Option<u64>,
    pub is_agent_candidate: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

/// Lifecycle state of an incident (the durable identity behind a
/// fingerprint), independent of the per-sample `Alert.resolved_at_ms`.
/// Absent in alerts persisted before incident lifecycle tracking existed;
/// the default treats them as open, matching prior behavior.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub enum IncidentState {
    #[default]
    Open,
    Reopened,
    Resolved,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Evidence {
    pub label: String,
    pub value: String,
}

/// Calibration signals the alert engine used to decide whether an incident
/// was worth notifying about. `Default` treats an alert as fully trusted
/// (all `1.0`) — correct for pre-calibration records, since the engine only
/// overwrites this for live incidents it is actively scoring.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AlertQuality {
    pub confidence: f64,
    pub persistence: f64,
    pub corroboration: f64,
    pub user_impact: f64,
    pub novelty: f64,
}

impl Default for AlertQuality {
    fn default() -> Self {
        Self {
            confidence: 1.0,
            persistence: 1.0,
            corroboration: 1.0,
            user_impact: 1.0,
            novelty: 1.0,
        }
    }
}

fn default_notify() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Alert {
    pub id: String,
    pub kind: String,
    pub severity: Severity,
    pub first_seen_ms: i64,
    pub last_seen_ms: i64,
    pub process_id: Option<u32>,
    pub process_name: Option<String>,
    pub title: String,
    pub explanation: String,
    pub evidence: Vec<Evidence>,
    pub recommendation: String,
    pub acknowledged: bool,
    pub occurrence_count: u32,
    pub resolved_at_ms: Option<i64>,
    /// Presentation-only archive flag: clients hide archived findings from
    /// their default surfaces, but detector semantics are untouched — an
    /// archived active finding keeps updating and resolving normally.
    /// Absent in alerts persisted by pre-archive services; the default
    /// keeps old JSON deserializing and the protocol version is unchanged.
    #[serde(default)]
    pub archived: bool,
    /// Stable identity for the underlying incident, shared across the
    /// reopen/resolve cycle. Absent in alerts persisted before incident
    /// fingerprints existed; the default empty string keeps old JSON
    /// deserializing and the protocol version is unchanged.
    #[serde(default)]
    pub fingerprint: String,
    /// Lifecycle state of the incident this alert represents. Absent in
    /// pre-upgrade alerts; the default keeps old JSON deserializing.
    #[serde(default)]
    pub state: IncidentState,
    /// Calibration signals behind the `notify` decision. Absent in
    /// pre-upgrade alerts; the default keeps old JSON deserializing.
    #[serde(default)]
    pub quality: AlertQuality,
    /// Whether this alert should surface a notification. Absent in
    /// pre-upgrade alerts; the default is `true` so old records keep
    /// notifying exactly like they did before quality gating existed.
    #[serde(default = "default_notify")]
    pub notify: bool,
    /// Monotonic counter bumped whenever this incident's notification
    /// eligibility is recomputed (e.g. on reopen). Absent in pre-upgrade
    /// alerts; the default `0` keeps old JSON deserializing.
    #[serde(default)]
    pub notify_generation: u32,
}

/// One ACPI thermal zone reading, converted from decikelvin to Celsius.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ThermalZone {
    pub name: String,
    pub temperature_c: f64,
}

/// Best-effort GPU telemetry (NVML today). Every reading is optional: a
/// driver that answers the name query but refuses a sensor yields `None`
/// for that sensor, never a fabricated zero.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GpuMetrics {
    pub name: String,
    pub temperature_c: Option<f64>,
    pub core_clock_mhz: Option<f64>,
    pub memory_clock_mhz: Option<f64>,
    pub utilization_percent: Option<f64>,
}

/// Temperatures and clocks, sampled at most every few seconds and cached
/// between snapshots. `available` is false when no source produced data;
/// `detail` then carries the human-readable reason (and notes partial
/// degradation even when other sources still report).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, rename_all = "camelCase")]
pub struct HardwareMetrics {
    pub sampled_at_ms: i64,
    pub cpu_frequency_mhz: Option<f64>,
    pub thermal_zones: Vec<ThermalZone>,
    pub gpus: Vec<GpuMetrics>,
    pub available: bool,
    pub detail: String,
}

impl Default for HardwareMetrics {
    fn default() -> Self {
        Self {
            sampled_at_ms: 0,
            cpu_frequency_mhz: None,
            thermal_zones: Vec::new(),
            gpus: Vec::new(),
            available: false,
            detail: "no hardware telemetry in this snapshot".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    pub protocol_version: u32,
    pub service_version: String,
    pub system: SystemMetric,
    pub processes: Vec<ProcessMetric>,
    pub active_alerts: Vec<Alert>,
    /// Absent in snapshots from services older than the GAUGES page; the
    /// default keeps old JSON deserializing and old clients simply ignore
    /// the extra field.
    #[serde(default)]
    pub hardware: HardwareMetrics,
}

impl Default for Snapshot {
    fn default() -> Self {
        Self {
            protocol_version: crate::PROTOCOL_VERSION,
            service_version: env!("CARGO_PKG_VERSION").to_string(),
            system: SystemMetric::default(),
            processes: Vec::new(),
            active_alerts: Vec::new(),
            hardware: HardwareMetrics::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ProcessNode {
    pub process: ProcessMetric,
    pub children: Vec<ProcessNode>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum DiagnosticLevel {
    Critical,
    Error,
    Warning,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum DiagnosticCategory {
    Hardware,
    Storage,
    Graphics,
    ApplicationCrash,
    ApplicationHang,
    ResourceExhaustion,
    Power,
    Service,
    Network,
    AgentRuntime,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticField {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticLog {
    pub timestamp_ms: i64,
    pub channel: String,
    pub provider: String,
    pub event_id: u32,
    pub record_id: u64,
    pub level: DiagnosticLevel,
    pub category: DiagnosticCategory,
    pub process_id: Option<u32>,
    pub thread_id: Option<u32>,
    pub related_process: Option<String>,
    pub fingerprint: String,
    pub fields: Vec<DiagnosticField>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, rename_all = "camelCase")]
pub struct DiagnosticLogStatus {
    pub enabled: bool,
    pub last_poll_ms: Option<i64>,
    pub last_success_ms: Option<i64>,
    pub last_error: Option<String>,
    pub events_seen: u64,
    pub events_stored: u64,
    pub duplicate_events: u64,
    pub malformed_events: u64,
    pub truncated_polls: u64,
}

impl Default for DiagnosticLogStatus {
    fn default() -> Self {
        Self {
            enabled: true,
            last_poll_ms: None,
            last_success_ms: None,
            last_error: None,
            events_seen: 0,
            events_stored: 0,
            duplicate_events: 0,
            malformed_events: 0,
            truncated_polls: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticLogResponse {
    pub status: DiagnosticLogStatus,
    pub logs: Vec<DiagnosticLog>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AgentSystemRollup {
    pub sample_count: usize,
    pub first_sample_ms: Option<i64>,
    pub last_sample_ms: Option<i64>,
    pub cpu_average_percent: f64,
    pub cpu_p95_percent: f64,
    pub cpu_max_percent: f64,
    pub memory_average_percent: f64,
    pub memory_p95_percent: f64,
    pub memory_max_percent: f64,
    pub disk_latency_p95_ms: f64,
    pub disk_latency_max_ms: f64,
    pub dpc_p95_per_sec: f64,
    pub interrupt_p95_per_sec: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AgentProcessRollup {
    pub evidence_ref: String,
    pub pid: u32,
    pub parent_pid: u32,
    pub name: String,
    pub executable_path: String,
    pub started_at_ms: i64,
    pub sample_count: usize,
    pub first_sample_ms: i64,
    pub last_sample_ms: i64,
    pub cpu_average_percent: f64,
    pub cpu_max_percent: f64,
    pub working_set_first_bytes: u64,
    pub working_set_last_bytes: u64,
    pub working_set_max_bytes: u64,
    pub working_set_delta_bytes: i64,
    pub handle_first: u32,
    pub handle_last: u32,
    pub handle_delta: i64,
    pub thread_first: u32,
    pub thread_last: u32,
    pub thread_delta: i64,
    pub io_average_bytes_per_sec: f64,
    pub io_max_bytes_per_sec: f64,
    pub responsive: bool,
    pub has_visible_window: bool,
    pub is_agent_candidate: bool,
    pub pressure_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AgentLogRollup {
    pub evidence_ref: String,
    pub fingerprint: String,
    pub category: DiagnosticCategory,
    pub level: DiagnosticLevel,
    pub provider: String,
    pub event_id: u32,
    pub count: u32,
    pub first_seen_ms: i64,
    pub last_seen_ms: i64,
    pub related_process: Option<String>,
    pub representative_fields: Vec<DiagnosticField>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AgentContext {
    pub schema_version: u32,
    pub context_id: String,
    pub generated_at_ms: i64,
    pub requested_window_hours: u32,
    pub effective_history_from_ms: Option<i64>,
    pub privacy: Vec<String>,
    pub safety_constraints: Vec<String>,
    pub collector_status: DiagnosticLogStatus,
    pub current: Snapshot,
    pub settings: crate::config::Settings,
    pub system_rollup: AgentSystemRollup,
    pub process_suspects: Vec<AgentProcessRollup>,
    pub diagnostic_log_rollups: Vec<AgentLogRollup>,
    pub recent_alerts: Vec<Alert>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PlanAgent {
    pub name: String,
    pub model: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PlanDataPoint {
    pub label: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PlanDiagnosis {
    pub id: String,
    pub severity: Severity,
    pub title: String,
    pub explanation: String,
    pub responsible_process: Option<String>,
    pub evidence_refs: Vec<String>,
    pub supporting_data: Vec<PlanDataPoint>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum PlanRisk {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum PlanActionCategory {
    Observe,
    Contain,
    Optimize,
    Repair,
    Verify,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum PlanStepKind {
    Command,
    PcPulse,
    Manual,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PlanStep {
    pub kind: PlanStepKind,
    pub description: String,
    pub command: Option<String>,
    pub mutates_system: bool,
    pub requires_elevation: bool,
    pub confirmation_prompt: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PlanAction {
    pub id: String,
    pub priority: u32,
    pub title: String,
    pub category: PlanActionCategory,
    pub target: String,
    pub reason: String,
    pub risk: PlanRisk,
    pub requires_confirmation: bool,
    pub prerequisites: Vec<String>,
    pub steps: Vec<PlanStep>,
    pub validation: Vec<String>,
    pub rollback: Vec<String>,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PlanConstraints {
    pub never_auto_terminate: bool,
    pub never_auto_apply: bool,
    pub confirmation_required_for_mutations: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OptimizationPlan {
    pub schema_version: u32,
    pub plan_id: String,
    pub context_id: String,
    pub generated_at_ms: i64,
    pub agent: PlanAgent,
    pub summary: String,
    pub confidence: String,
    pub diagnoses: Vec<PlanDiagnosis>,
    pub actions: Vec<PlanAction>,
    pub constraints: PlanConstraints,
}

impl OptimizationPlan {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1 {
            return Err("unsupported optimization-plan schema version".into());
        }
        if self.plan_id.is_empty() || self.context_id.is_empty() || self.summary.is_empty() {
            return Err("planId, contextId, and summary are required".into());
        }
        if self.summary.len() > 4_000 || self.diagnoses.len() > 20 || self.actions.len() > 20 {
            return Err("optimization plan exceeds bounded limits".into());
        }
        if !matches!(self.confidence.as_str(), "low" | "medium" | "high") {
            return Err("confidence must be low, medium, or high".into());
        }
        if self.agent.name != "pcpulse-systems-analyzer" {
            return Err("unexpected optimization-plan agent identity".into());
        }
        if !self.constraints.never_auto_terminate
            || !self.constraints.never_auto_apply
            || !self.constraints.confirmation_required_for_mutations
        {
            return Err("required PC Pulse safety constraints are missing".into());
        }
        for action in &self.actions {
            if action.steps.len() > 12
                || action.validation.len() > 12
                || action.rollback.len() > 12
                || action.evidence_refs.len() > 32
            {
                return Err(format!("action {} exceeds bounded limits", action.id));
            }
            if action.steps.iter().any(|step| step.mutates_system)
                && (!action.requires_confirmation
                    || action
                        .steps
                        .iter()
                        .filter(|step| step.mutates_system)
                        .any(|step| step.confirmation_prompt.as_deref().unwrap_or("").is_empty()))
            {
                return Err(format!(
                    "action {} mutates the system without explicit confirmation",
                    action.id
                ));
            }
            if action.steps.iter().any(|step| {
                let command = step
                    .command
                    .as_deref()
                    .unwrap_or_default()
                    .to_ascii_lowercase();
                [
                    "stop-process",
                    "taskkill",
                    "terminateprocess",
                    "wmic process",
                ]
                .iter()
                .any(|forbidden| command.contains(forbidden))
            }) {
                return Err(format!(
                    "action {} contains a forbidden direct termination command",
                    action.id
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "camelCase")]
pub enum PipeRequest {
    Ping,
    GetSnapshot,
    /// Most recent high-rate system sample. Also marks live-channel
    /// liveness: the sampler starts on the first request and stops after
    /// ten seconds without one.
    Live,
    GetHistory {
        from_ms: i64,
        to_ms: i64,
        limit: u32,
    },
    GetSystemHistory {
        from_ms: i64,
        to_ms: i64,
        limit: u32,
    },
    GetAlerts {
        from_ms: i64,
        limit: u32,
    },
    GetDiagnosticLogs {
        from_ms: i64,
        limit: u32,
    },
    GetAgentContext {
        window_hours: u32,
    },
    GetOptimizationPlans {
        limit: u32,
    },
    SaveOptimizationPlan {
        plan: OptimizationPlan,
    },
    GetSettings,
    UpdateSettings {
        settings: crate::config::Settings,
    },
    GetProcessTree,
    AcknowledgeAlert {
        alert_id: String,
    },
    /// Set or clear an alert's presentation-only archive flag; `archived:
    /// false` recovers a previously archived finding. Validation mirrors
    /// `acknowledgeAlert` exactly.
    ArchiveAlert {
        alert_id: String,
        archived: bool,
    },
    TerminateProcess {
        pid: u32,
        confirmed: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryResponse {
    pub system: Vec<SystemMetric>,
    pub processes: Vec<ProcessMetric>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "camelCase")]
pub enum PipeResponse {
    Ok { data: serde_json::Value },
    Error { code: String, message: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_round_trips_with_hardware_metrics() {
        let snapshot = Snapshot {
            hardware: HardwareMetrics {
                sampled_at_ms: 1_800_000_000_000,
                cpu_frequency_mhz: Some(4_212.5),
                thermal_zones: vec![ThermalZone {
                    name: "TZ00".into(),
                    temperature_c: 48.9,
                }],
                gpus: vec![GpuMetrics {
                    name: "NVIDIA GeForce RTX 4080".into(),
                    temperature_c: Some(62.0),
                    core_clock_mhz: Some(2_550.0),
                    memory_clock_mhz: Some(10_500.0),
                    utilization_percent: Some(34.0),
                }],
                available: true,
                detail: String::new(),
            },
            ..Snapshot::default()
        };
        let json = serde_json::to_string(&snapshot).unwrap();
        assert!(json.contains("\"cpuFrequencyMhz\""), "camelCase wire names");
        assert!(json.contains("\"thermalZones\""));
        let restored: Snapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, snapshot);
    }

    #[test]
    fn snapshot_without_hardware_field_still_deserializes() {
        // A snapshot serialized by a pre-GAUGES service has no `hardware`
        // key; the default must report an honest unavailable state.
        let json = serde_json::json!({
            "protocolVersion": crate::PROTOCOL_VERSION,
            "serviceVersion": "1.4.0",
            "system": serde_json::to_value(SystemMetric::default()).unwrap(),
            "processes": [],
            "activeAlerts": [],
        });
        let snapshot: Snapshot = serde_json::from_value(json).unwrap();
        assert!(!snapshot.hardware.available);
        assert!(snapshot.hardware.thermal_zones.is_empty());
        assert!(snapshot.hardware.gpus.is_empty());
        assert!(!snapshot.hardware.detail.is_empty());
    }

    #[test]
    fn system_metric_without_network_counter_still_deserializes() {
        // A system sample persisted before the network counter existed has no
        // `networkBytesPerSec` key; it must parse to an honest zero, and the
        // new field must ride the wire in camelCase.
        let mut old = serde_json::to_value(SystemMetric::default()).unwrap();
        let map = old.as_object_mut().unwrap();
        assert!(map.remove("networkBytesPerSec").is_some(), "wire name");
        let restored: SystemMetric = serde_json::from_value(old).unwrap();
        assert_eq!(restored.network_bytes_per_sec, 0.0);
        let json = serde_json::to_string(&SystemMetric {
            network_bytes_per_sec: 1_500_000.0,
            ..SystemMetric::default()
        })
        .unwrap();
        assert!(json.contains("\"networkBytesPerSec\":1500000.0"));
    }

    #[test]
    fn live_sample_round_trips_in_camel_case() {
        let sample = LiveSample {
            available: true,
            timestamp_ms: 1_800_000_000_000,
            cpu_percent: 37.5,
            memory_used_bytes: 17_179_869_184,
            memory_total_bytes: 34_359_738_368,
            disk_read_bytes_per_sec: 1_048_576.0,
            disk_write_bytes_per_sec: 524_288.0,
            disk_latency_ms: 1.4,
            network_bytes_per_sec: 250_000.0,
            dpc_rate: 1_200.0,
            interrupt_rate: 9_500.0,
        };
        let json = serde_json::to_string(&sample).unwrap();
        for key in [
            "\"available\"",
            "\"timestampMs\"",
            "\"cpuPercent\"",
            "\"memoryUsedBytes\"",
            "\"memoryTotalBytes\"",
            "\"diskReadBytesPerSec\"",
            "\"diskWriteBytesPerSec\"",
            "\"diskLatencyMs\"",
            "\"networkBytesPerSec\"",
            "\"dpcRate\"",
            "\"interruptRate\"",
        ] {
            assert!(json.contains(key), "wire name {key} missing from {json}");
        }
        let restored: LiveSample = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, sample);
    }

    fn test_alert() -> Alert {
        Alert {
            id: "a-1".into(),
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
            archived: false,
            fingerprint: String::new(),
            state: IncidentState::Open,
            quality: AlertQuality::default(),
            notify: true,
            notify_generation: 0,
        }
    }

    #[test]
    fn alert_without_archived_field_still_deserializes() {
        // An alert persisted (or served) by a pre-archive service has no
        // `archived` key; it must parse as unarchived, and the flag must
        // ride the wire in camelCase for current alerts.
        let alert = Alert {
            archived: true,
            ..test_alert()
        };
        let mut old = serde_json::to_value(&alert).unwrap();
        assert!(
            old.as_object_mut().unwrap().remove("archived").is_some(),
            "wire name"
        );
        let restored: Alert = serde_json::from_value(old).unwrap();
        assert!(!restored.archived);
        assert!(serde_json::to_string(&alert).unwrap().contains("\"archived\":true"));
    }

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
        let alert = Alert {
            fingerprint: "dpcInterrupt".into(),
            notify: false,
            notify_generation: 2,
            ..test_alert()
        };
        let json = serde_json::to_string(&alert).unwrap();
        assert!(json.contains("\"fingerprint\":\"dpcInterrupt\""));
        assert!(json.contains("\"notifyGeneration\":2"));
        assert!(json.contains("\"state\":\"open\""));
    }

    #[test]
    fn archive_command_round_trips_on_the_same_wire_shape_as_acknowledge() {
        // Field spelling must match acknowledgeAlert exactly: the container
        // rename_all camelCases the command tag, and struct-variant fields
        // keep the same convention acknowledge already ships.
        let acknowledge = serde_json::to_string(&PipeRequest::AcknowledgeAlert {
            alert_id: "finding-1".into(),
        })
        .unwrap();
        let archive = serde_json::to_string(&PipeRequest::ArchiveAlert {
            alert_id: "finding-1".into(),
            archived: true,
        })
        .unwrap();
        assert!(archive.contains(r#""command":"archiveAlert""#));
        // The documented wire contract (docs/protocol.md): command tags are
        // camelCase (container rename_all), struct-variant FIELDS are
        // snake_case — serde's container rename_all does not reach them.
        assert!(acknowledge.contains("\"alert_id\""), "wire: {acknowledge}");
        assert!(archive.contains("\"alert_id\""), "wire: {archive}");
        let request: PipeRequest = serde_json::from_str(&archive).unwrap();
        match request {
            PipeRequest::ArchiveAlert { alert_id, archived } => {
                assert_eq!(alert_id, "finding-1");
                assert!(archived);
            }
            other => panic!("unexpected parse: {other:?}"),
        }
    }

    #[test]
    fn request_fields_are_snake_case_on_the_wire_as_documented() {
        let history: PipeRequest = serde_json::from_str(
            r#"{"command":"getHistory","from_ms":1,"to_ms":2,"limit":10}"#,
        )
        .expect("documented snake_case fields must parse");
        assert!(matches!(history, PipeRequest::GetHistory { .. }));
        let context: PipeRequest =
            serde_json::from_str(r#"{"command":"getAgentContext","window_hours":2}"#)
                .expect("documented snake_case fields must parse");
        assert!(matches!(context, PipeRequest::GetAgentContext { .. }));
        // The camelCase spelling protocol.md previously documented never
        // worked; keep it failing loudly rather than silently half-working.
        assert!(
            serde_json::from_str::<PipeRequest>(
                r#"{"command":"acknowledgeAlert","alertId":"x"}"#
            )
            .is_err()
        );
    }

    #[test]
    fn live_command_parses_from_its_wire_name() {
        let request: PipeRequest = serde_json::from_str(r#"{"command":"live"}"#).unwrap();
        assert!(matches!(request, PipeRequest::Live));
        let json = serde_json::to_string(&PipeRequest::Live).unwrap();
        assert_eq!(json, r#"{"command":"live"}"#);
    }

    fn plan() -> OptimizationPlan {
        OptimizationPlan {
            schema_version: 1,
            plan_id: "plan-1".into(),
            context_id: "context-1".into(),
            generated_at_ms: 123,
            agent: PlanAgent {
                name: "pcpulse-systems-analyzer".into(),
                model: "codex".into(),
            },
            summary: "Observe before changing anything.".into(),
            confidence: "low".into(),
            diagnoses: Vec::new(),
            actions: Vec::new(),
            constraints: PlanConstraints {
                never_auto_terminate: true,
                never_auto_apply: true,
                confirmation_required_for_mutations: true,
            },
        }
    }

    #[test]
    fn plan_requires_non_execution_safety_contract() {
        let mut value = plan();
        assert!(value.validate().is_ok());
        value.constraints.never_auto_apply = false;
        assert!(value.validate().is_err());
    }

    #[test]
    fn plan_rejects_direct_termination_commands() {
        let mut value = plan();
        value.actions.push(PlanAction {
            id: "kill".into(),
            priority: 100,
            title: "Terminate".into(),
            category: PlanActionCategory::Contain,
            target: "PID 42".into(),
            reason: "test".into(),
            risk: PlanRisk::High,
            requires_confirmation: true,
            prerequisites: Vec::new(),
            steps: vec![PlanStep {
                kind: PlanStepKind::Command,
                description: "direct kill".into(),
                command: Some("Stop-Process -Id 42".into()),
                mutates_system: true,
                requires_elevation: false,
                confirmation_prompt: Some("confirm".into()),
            }],
            validation: vec!["validate".into()],
            rollback: Vec::new(),
            evidence_refs: vec!["process:42:1".into()],
        });
        assert!(value.validate().is_err());
    }
}
