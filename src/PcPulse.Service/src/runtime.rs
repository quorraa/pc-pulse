use crate::{
    alerting::AlertEngine,
    analysis::{AgentContextSource, build_agent_context},
    config::Settings,
    etw::EtwCollector,
    eventlog::EventLogCollector,
    metrics::{
        MetricCollector,
        forensics::{ForensicsEngine, WindowsForensicsSource},
        interrupts::{InterruptEngine, WindowsInterruptSource},
    },
    models::{
        DiagnosticLogResponse, DiagnosticLogStatus, PipeRequest, PipeResponse, ProcessMetric,
        ProcessNode, Snapshot,
    },
    pipe,
    storage::Storage,
};
use anyhow::{Result, anyhow};
use chrono::Utc;
use serde_json::json;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

pub struct AppState {
    pub snapshot: RwLock<Snapshot>,
    pub settings: RwLock<Settings>,
    pub storage: Arc<Storage>,
    pub alerts: Mutex<AlertEngine>,
    pub log_status: Mutex<DiagnosticLogStatus>,
    issued_contexts: Mutex<VecDeque<IssuedContext>>,
    pub settings_path: PathBuf,
}

impl AppState {
    pub fn handle(&self, request: PipeRequest) -> PipeResponse {
        match self.handle_inner(request) {
            Ok(data) => PipeResponse::Ok { data },
            Err(error) => PipeResponse::Error {
                code: "requestFailed".into(),
                message: format!("{error:#}"),
            },
        }
    }

    fn handle_inner(&self, request: PipeRequest) -> Result<serde_json::Value> {
        match request {
            PipeRequest::Ping => Ok(json!({
                "protocolVersion": crate::PROTOCOL_VERSION,
                "serviceVersion": env!("CARGO_PKG_VERSION")
            })),
            PipeRequest::GetSnapshot => Ok(serde_json::to_value(
                self.snapshot
                    .read()
                    .map_err(|_| anyhow!("snapshot lock poisoned"))?
                    .clone(),
            )?),
            PipeRequest::GetHistory {
                from_ms,
                to_ms,
                limit,
            } => {
                if from_ms > to_ms {
                    return Err(anyhow!("fromMs must not be after toMs"));
                }
                Ok(serde_json::to_value(self.storage.history(
                    from_ms,
                    to_ms,
                    limit.min(750),
                )?)?)
            }
            PipeRequest::GetSystemHistory {
                from_ms,
                to_ms,
                limit,
            } => {
                if from_ms > to_ms {
                    return Err(anyhow!("fromMs must not be after toMs"));
                }
                Ok(serde_json::to_value(
                    self.storage
                        .system_history_downsampled(from_ms, to_ms, limit.min(800))?,
                )?)
            }
            PipeRequest::GetAlerts { from_ms, limit } => Ok(serde_json::to_value(
                self.storage.alerts(from_ms, limit.min(300))?,
            )?),
            PipeRequest::GetDiagnosticLogs { from_ms, limit } => {
                let response = DiagnosticLogResponse {
                    status: self
                        .log_status
                        .lock()
                        .map_err(|_| anyhow!("diagnostic-log status lock poisoned"))?
                        .clone(),
                    logs: self.storage.diagnostic_logs(from_ms, limit.min(200))?,
                };
                Ok(serde_json::to_value(response)?)
            }
            PipeRequest::GetAgentContext { window_hours } => {
                if !(1..=24).contains(&window_hours) {
                    return Err(anyhow!("windowHours must be between 1 and 24"));
                }
                let now_ms = Utc::now().timestamp_millis();
                let from_ms = now_ms - i64::from(window_hours) * 3_600_000;
                let history = self
                    .storage
                    .recent_history(from_ms, now_ms, 10_000, 20_000)?;
                let logs = self.storage.diagnostic_logs(from_ms, 5_000)?;
                let alerts = self.storage.alerts(from_ms, 500)?;
                let snapshot = self
                    .snapshot
                    .read()
                    .map_err(|_| anyhow!("snapshot lock poisoned"))?
                    .clone();
                let settings = self
                    .settings
                    .read()
                    .map_err(|_| anyhow!("settings lock poisoned"))?
                    .clone();
                let status = self
                    .log_status
                    .lock()
                    .map_err(|_| anyhow!("diagnostic-log status lock poisoned"))?
                    .clone();
                let context = build_agent_context(AgentContextSource {
                    now_ms,
                    window_hours,
                    snapshot: &snapshot,
                    settings: &settings,
                    history,
                    logs,
                    log_status: status,
                    alerts,
                });
                self.remember_context(&context)?;
                Ok(serde_json::to_value(context)?)
            }
            PipeRequest::GetOptimizationPlans { limit } => Ok(serde_json::to_value(
                self.storage.optimization_plans(limit.min(5))?,
            )?),
            PipeRequest::SaveOptimizationPlan { plan } => {
                plan.validate().map_err(anyhow::Error::msg)?;
                self.validate_plan_context(&plan)?;
                self.storage.save_optimization_plan(&plan)?;
                Ok(json!({ "saved": true, "planId": plan.plan_id }))
            }
            PipeRequest::GetSettings => Ok(serde_json::to_value(
                self.settings
                    .read()
                    .map_err(|_| anyhow!("settings lock poisoned"))?
                    .clone(),
            )?),
            PipeRequest::UpdateSettings { settings } => {
                settings.validate()?;
                settings.save(&self.settings_path)?;
                *self
                    .settings
                    .write()
                    .map_err(|_| anyhow!("settings lock poisoned"))? = settings.clone();
                Ok(serde_json::to_value(settings)?)
            }
            PipeRequest::GetProcessTree => {
                let processes = self
                    .snapshot
                    .read()
                    .map_err(|_| anyhow!("snapshot lock poisoned"))?
                    .processes
                    .clone();
                Ok(serde_json::to_value(build_process_tree(&processes))?)
            }
            PipeRequest::AcknowledgeAlert { alert_id } => {
                let active = self
                    .alerts
                    .lock()
                    .map_err(|_| anyhow!("alert lock poisoned"))?
                    .acknowledge(&alert_id);
                let persisted = self.storage.acknowledge_alert(&alert_id)?;
                if let Some(alert) = active {
                    let mut snapshot = self
                        .snapshot
                        .write()
                        .map_err(|_| anyhow!("snapshot lock poisoned"))?;
                    if let Some(item) = snapshot
                        .active_alerts
                        .iter_mut()
                        .find(|item| item.id == alert_id)
                    {
                        *item = alert;
                    }
                }
                Ok(json!({ "acknowledged": persisted }))
            }
            PipeRequest::TerminateProcess { pid, confirmed } => {
                crate::metrics::terminate_process(pid, confirmed)?;
                Ok(json!({ "terminated": true, "pid": pid }))
            }
        }
    }
}

#[derive(Debug)]
struct IssuedContext {
    id: String,
    generated_at_ms: i64,
    evidence_refs: HashSet<String>,
}

impl AppState {
    fn remember_context(&self, context: &crate::models::AgentContext) -> Result<()> {
        let evidence_refs = context
            .process_suspects
            .iter()
            .map(|item| item.evidence_ref.clone())
            .chain(
                context
                    .diagnostic_log_rollups
                    .iter()
                    .map(|item| item.evidence_ref.clone()),
            )
            .chain(
                context
                    .recent_alerts
                    .iter()
                    .map(|alert| format!("alert:{}", alert.id)),
            )
            .collect();
        let mut issued = self
            .issued_contexts
            .lock()
            .map_err(|_| anyhow!("issued-context lock poisoned"))?;
        issued.retain(|item| item.id != context.context_id);
        issued.push_back(IssuedContext {
            id: context.context_id.clone(),
            generated_at_ms: context.generated_at_ms,
            evidence_refs,
        });
        while issued.len() > 32 {
            issued.pop_front();
        }
        Ok(())
    }

    fn validate_plan_context(&self, plan: &crate::models::OptimizationPlan) -> Result<()> {
        let now_ms = Utc::now().timestamp_millis();
        let mut issued = self
            .issued_contexts
            .lock()
            .map_err(|_| anyhow!("issued-context lock poisoned"))?;
        issued.retain(|item| now_ms.saturating_sub(item.generated_at_ms) <= 24 * 3_600_000);
        let context = issued
            .iter()
            .find(|item| item.id == plan.context_id)
            .ok_or_else(|| {
                anyhow!(
                    "plan context is unknown or expired; request a fresh agent context before importing"
                )
            })?;
        if context.generated_at_ms != plan.generated_at_ms {
            return Err(anyhow!(
                "plan timestamp does not match its evidence context"
            ));
        }
        for reference in plan
            .diagnoses
            .iter()
            .flat_map(|diagnosis| &diagnosis.evidence_refs)
            .chain(plan.actions.iter().flat_map(|action| &action.evidence_refs))
        {
            if !context.evidence_refs.contains(reference) {
                return Err(anyhow!(
                    "plan cites unknown evidence reference {reference} for its context"
                ));
            }
        }
        Ok(())
    }
}

pub fn run(data_dir: &Path, stop: crossbeam_channel::Receiver<()>) -> Result<()> {
    std::fs::create_dir_all(data_dir)?;
    let settings_path = data_dir.join("settings.json");
    let settings = Settings::load(&settings_path)?;
    let storage = Arc::new(Storage::open(&data_dir.join("history.db"))?);
    // A restart breaks monitoring continuity. Close persisted open findings so the
    // fresh sustained detector can reacquire only conditions that are still present.
    storage.resolve_open_alerts(Utc::now().timestamp_millis())?;
    let state = Arc::new(AppState {
        snapshot: RwLock::new(Snapshot::default()),
        settings: RwLock::new(settings),
        storage,
        alerts: Mutex::new(AlertEngine::default()),
        log_status: Mutex::new(DiagnosticLogStatus::default()),
        issued_contexts: Mutex::new(VecDeque::new()),
        settings_path,
    });
    let pipe_stop = Arc::new(AtomicBool::new(false));
    let pipe_state = Arc::clone(&state);
    let pipe_stop_worker = Arc::clone(&pipe_stop);
    let pipe_worker = thread::Builder::new()
        .name("pcpulse-pipe".into())
        .spawn(move || {
            if let Err(error) = pipe::serve(pipe_state, pipe_stop_worker) {
                eprintln!("named-pipe server stopped: {error:#}");
            }
        })?;
    let result = sampling_loop(&state, stop);
    pipe_stop.store(true, Ordering::Release);
    pipe::wake();
    let _ = pipe_worker.join();
    result
}

fn sampling_loop(state: &Arc<AppState>, stop: crossbeam_channel::Receiver<()>) -> Result<()> {
    let mut etw = match EtwCollector::start() {
        Ok(collector) => Some(collector),
        Err(error) => {
            eprintln!("ETW unavailable; continuing in degraded mode and retrying: {error:#}");
            None
        }
    };
    let mut next_etw_retry = Instant::now() + Duration::from_secs(60);
    let mut collector = MetricCollector::new()?;
    // Leak forensics is a strict no-op (zero syscalls) until a handle- or
    // thread-growth finding is active; then it captures at most once a minute.
    let mut forensics = ForensicsEngine::new(WindowsForensicsSource::default());
    // ISR/DPC attribution is likewise a strict no-op (its per-sample
    // activity ring is pure memory work) until a dpcInterrupt finding is
    // active; then it runs one bounded kernel trace when the finding fires,
    // re-captures on a two-minute cadence until it holds three successful
    // traces, and backs off to every ten minutes.
    let mut interrupts = InterruptEngine::new(WindowsInterruptSource::default());
    let mut event_logs = EventLogCollector::default();
    let mut next_system_write = Instant::now();
    let mut next_process_write = Instant::now();
    let mut next_prune = Instant::now();
    let mut next_event_log_poll = Instant::now();
    loop {
        let started = Instant::now();
        let settings = state
            .settings
            .read()
            .map_err(|_| anyhow!("settings lock poisoned"))?
            .clone();
        if etw.is_none() && Instant::now() >= next_etw_retry {
            match EtwCollector::start() {
                Ok(collector) => etw = Some(collector),
                Err(error) => {
                    eprintln!("ETW retry failed: {error:#}");
                    next_etw_retry = Instant::now() + Duration::from_secs(60);
                }
            }
        }
        let timestamp_ms = Utc::now().timestamp_millis();
        let etw_snapshot = etw
            .as_ref()
            .map_or_else(crate::etw::EtwSnapshot::default, EtwCollector::snapshot);
        let (system, processes, hardware) =
            collector.collect(timestamp_ms, &settings, &etw_snapshot)?;
        let mut evaluation = state
            .alerts
            .lock()
            .map_err(|_| anyhow!("alert lock poisoned"))?
            .evaluate(&system, &processes, &settings);
        forensics.observe(&evaluation.active, timestamp_ms);
        forensics.decorate(&mut evaluation.active);
        forensics.decorate(&mut evaluation.changed);
        // The correlation window rides on every sample: system rates plus
        // the freshest GPU utilization the hardware sampler produced.
        let gpu_utilization = hardware
            .gpus
            .iter()
            .filter_map(|gpu| gpu.utilization_percent)
            .fold(None, |best: Option<f64>, value| {
                Some(best.map_or(value, |current| current.max(value)))
            });
        interrupts.record_activity(&system, gpu_utilization);
        interrupts.observe(&evaluation.active, timestamp_ms);
        interrupts.decorate(&mut evaluation.active);
        interrupts.decorate(&mut evaluation.changed);
        state.storage.upsert_alerts(&evaluation.changed)?;
        {
            let mut snapshot = state
                .snapshot
                .write()
                .map_err(|_| anyhow!("snapshot lock poisoned"))?;
            snapshot.system = system.clone();
            snapshot.processes = processes.clone();
            snapshot.active_alerts = evaluation.active;
            snapshot.hardware = hardware;
        }
        if Instant::now() >= next_system_write {
            state.storage.insert_system(&system)?;
            next_system_write = Instant::now() + Duration::from_secs(10);
        }
        if Instant::now() >= next_process_write {
            state.storage.insert_processes(&processes, 64)?;
            next_process_write = Instant::now() + Duration::from_secs(30);
        }
        if Instant::now() >= next_event_log_poll {
            let logs = event_logs.poll(timestamp_ms, &settings.agent_process_patterns);
            if let Err(error) = state.storage.insert_diagnostic_logs(&logs) {
                let message = format!("failed to persist Windows diagnostic logs: {error:#}");
                eprintln!("{message}");
                event_logs.note_storage_error(message);
            }
            *state
                .log_status
                .lock()
                .map_err(|_| anyhow!("diagnostic-log status lock poisoned"))? = event_logs.status();
            next_event_log_poll = Instant::now() + Duration::from_secs(30);
        }
        if Instant::now() >= next_prune {
            state.storage.prune(&settings, timestamp_ms)?;
            next_prune = Instant::now() + Duration::from_secs(24 * 60 * 60);
        }
        let delay =
            Duration::from_millis(settings.sample_interval_ms).saturating_sub(started.elapsed());
        match stop.recv_timeout(delay) {
            Ok(()) | Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {}
        }
    }
    Ok(())
}

pub fn default_data_dir() -> PathBuf {
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("PcPulse")
}

pub fn build_process_tree(processes: &[ProcessMetric]) -> Vec<ProcessNode> {
    let by_pid: HashMap<u32, &ProcessMetric> = processes
        .iter()
        .map(|process| (process.pid, process))
        .collect();
    let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
    for process in processes {
        children
            .entry(process.parent_pid)
            .or_default()
            .push(process.pid);
    }
    for list in children.values_mut() {
        list.sort_unstable();
    }
    let roots: Vec<u32> = processes
        .iter()
        .filter(|process| {
            process.parent_pid == process.pid || !by_pid.contains_key(&process.parent_pid)
        })
        .map(|process| process.pid)
        .collect();
    let mut visited = HashSet::new();
    let mut result = Vec::new();
    for pid in roots {
        if let Some(node) = build_node(pid, &by_pid, &children, &mut visited) {
            result.push(node);
        }
    }
    for process in processes {
        if let Some(node) = build_node(process.pid, &by_pid, &children, &mut visited) {
            result.push(node);
        }
    }
    result
}

fn build_node(
    pid: u32,
    by_pid: &HashMap<u32, &ProcessMetric>,
    children: &HashMap<u32, Vec<u32>>,
    visited: &mut HashSet<u32>,
) -> Option<ProcessNode> {
    if !visited.insert(pid) {
        return None;
    }
    let process = (*by_pid.get(&pid)?).clone();
    let nodes = children
        .get(&pid)
        .into_iter()
        .flatten()
        .filter_map(|child| build_node(*child, by_pid, children, visited))
        .collect();
    Some(ProcessNode {
        process,
        children: nodes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        DiagnosticLogStatus, HistoryResponse, OptimizationPlan, PlanAgent, PlanConstraints,
    };

    fn process(pid: u32, parent_pid: u32) -> ProcessMetric {
        ProcessMetric {
            timestamp_ms: 0,
            pid,
            parent_pid,
            name: pid.to_string(),
            executable_path: String::new(),
            cpu_percent: 0.0,
            working_set_bytes: 0,
            private_bytes: 0,
            handle_count: 0,
            thread_count: 0,
            read_bytes_per_sec: 0.0,
            write_bytes_per_sec: 0.0,
            total_read_bytes: 0,
            total_write_bytes: 0,
            started_at_ms: i64::from(pid),
            session_id: 0,
            responsive: true,
            has_visible_window: false,
            launch_duration_ms: None,
            is_agent_candidate: false,
        }
    }

    #[test]
    fn builds_parent_child_tree() {
        let tree = build_process_tree(&[process(10, 0), process(11, 10), process(12, 11)]);
        assert_eq!(tree.len(), 1);
        assert_eq!(tree[0].children[0].children[0].process.pid, 12);
    }

    #[test]
    fn saved_plan_must_match_a_recent_issued_context() {
        let directory = tempfile::tempdir().unwrap();
        let state = AppState {
            snapshot: RwLock::new(Snapshot::default()),
            settings: RwLock::new(Settings::default()),
            storage: Arc::new(Storage::open(&directory.path().join("history.db")).unwrap()),
            alerts: Mutex::new(AlertEngine::default()),
            log_status: Mutex::new(DiagnosticLogStatus::default()),
            issued_contexts: Mutex::new(VecDeque::new()),
            settings_path: directory.path().join("settings.json"),
        };
        let now_ms = Utc::now().timestamp_millis();
        let snapshot = Snapshot::default();
        let settings = Settings::default();
        let context = build_agent_context(AgentContextSource {
            now_ms,
            window_hours: 1,
            snapshot: &snapshot,
            settings: &settings,
            history: HistoryResponse {
                system: Vec::new(),
                processes: Vec::new(),
            },
            logs: Vec::new(),
            log_status: DiagnosticLogStatus::default(),
            alerts: Vec::new(),
        });
        state.remember_context(&context).unwrap();
        let mut plan = OptimizationPlan {
            schema_version: 1,
            plan_id: "plan".into(),
            context_id: context.context_id,
            generated_at_ms: context.generated_at_ms,
            agent: PlanAgent {
                name: "pcpulse-systems-analyzer".into(),
                model: "codex".into(),
            },
            summary: "No defensible issue.".into(),
            confidence: "low".into(),
            diagnoses: Vec::new(),
            actions: Vec::new(),
            constraints: PlanConstraints {
                never_auto_terminate: true,
                never_auto_apply: true,
                confirmation_required_for_mutations: true,
            },
        };
        assert!(state.validate_plan_context(&plan).is_ok());
        plan.context_id = "substituted".into();
        assert!(state.validate_plan_context(&plan).is_err());
    }
}
