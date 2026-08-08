use crate::{
    analyzer::{ChatMessage, ChatResponse, ChatRole},
    chat_history::{ChatHistoryStore, ChatSession},
    client::PipeClient,
};
use chrono::Utc;
use crossbeam_channel::{Receiver, Sender, bounded, select};
use pcpulse_service::{
    config::Settings,
    models::{
        Alert, DiagnosticLogResponse, DiagnosticLogStatus, HistoryResponse, OptimizationPlan,
        ProcessMetric, ProcessNode, Severity, Snapshot, SystemMetric,
    },
};
use ratatui::{
    crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    widgets::{ListState, TableState},
};
use std::{
    collections::VecDeque,
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const LIVE_HISTORY_CAPACITY: usize = 180;
static CHAT_SEQUENCE: AtomicU64 = AtomicU64::new(1);

fn new_conversation_id() -> String {
    format!(
        "chat-{}-{}-{}",
        std::process::id(),
        Utc::now().timestamp_millis(),
        CHAT_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Page {
    Overview,
    Processes,
    Tree,
    Alerts,
    Timeline,
    Analyzer,
    Settings,
    Help,
}

impl Page {
    pub const ALL: [Self; 8] = [
        Self::Overview,
        Self::Processes,
        Self::Tree,
        Self::Alerts,
        Self::Timeline,
        Self::Analyzer,
        Self::Settings,
        Self::Help,
    ];

    pub const fn title(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Processes => "Processes",
            Self::Tree => "Tree",
            Self::Alerts => "Findings",
            Self::Timeline => "Timeline",
            Self::Analyzer => "Analyzer",
            Self::Settings => "Settings",
            Self::Help => "Keys",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessSort {
    Pid,
    Cpu,
    Memory,
    Io,
    Handles,
    Threads,
    Age,
    Name,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TreeSort {
    Lineage,
    Pid,
    Name,
    Cpu,
    Memory,
    Io,
}

impl TreeSort {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Lineage => "lineage",
            Self::Pid => "PID",
            Self::Name => "name",
            Self::Cpu => "CPU",
            Self::Memory => "memory",
            Self::Io => "I/O",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertSort {
    Severity,
    Title,
    Owner,
    State,
    FirstSeen,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingSort {
    Name,
    Value,
    Unit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuspectSort {
    Heat,
    Name,
    Cpu,
    Memory,
    Io,
    HandlesThreads,
}

impl ProcessSort {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Pid => "PID",
            Self::Cpu => "CPU",
            Self::Memory => "memory",
            Self::Io => "I/O",
            Self::Handles => "handles",
            Self::Threads => "threads",
            Self::Age => "age",
            Self::Name => "name",
        }
    }

    fn next(self) -> Self {
        match self {
            Self::Pid => Self::Name,
            Self::Name => Self::Cpu,
            Self::Cpu => Self::Memory,
            Self::Memory => Self::Io,
            Self::Io => Self::Handles,
            Self::Handles => Self::Threads,
            Self::Threads => Self::Age,
            Self::Age => Self::Pid,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TreeRow {
    pub depth: usize,
    pub process: ProcessMetric,
}

#[derive(Debug, Clone)]
pub enum InputMode {
    Normal,
    Search(String),
    Chat(String),
    ConfirmTerminate {
        pid: u32,
        process_name: String,
        typed: String,
    },
    EditSetting {
        field: SettingField,
        typed: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingField {
    SampleInterval,
    Retention,
    Sustained,
    BaselineSigma,
    Cpu,
    MemoryGrowth,
    HandleGrowth,
    ThreadGrowth,
    DiskLatency,
    Io,
    KernelPool,
    Dpc,
    Interrupt,
    Unresponsive,
    SlowLaunch,
    AgentAge,
    Notifications,
    AgentPatterns,
}

impl SettingField {
    pub const ALL: [Self; 18] = [
        Self::SampleInterval,
        Self::Retention,
        Self::Sustained,
        Self::BaselineSigma,
        Self::Cpu,
        Self::MemoryGrowth,
        Self::HandleGrowth,
        Self::ThreadGrowth,
        Self::DiskLatency,
        Self::Io,
        Self::KernelPool,
        Self::Dpc,
        Self::Interrupt,
        Self::Unresponsive,
        Self::SlowLaunch,
        Self::AgentAge,
        Self::Notifications,
        Self::AgentPatterns,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::SampleInterval => "Sample interval",
            Self::Retention => "History retention",
            Self::Sustained => "Sustained samples",
            Self::BaselineSigma => "Baseline deviation",
            Self::Cpu => "Process CPU",
            Self::MemoryGrowth => "Memory growth",
            Self::HandleGrowth => "Handle growth",
            Self::ThreadGrowth => "Thread growth",
            Self::DiskLatency => "Disk latency",
            Self::Io => "Process I/O",
            Self::KernelPool => "Kernel pool growth",
            Self::Dpc => "DPC rate",
            Self::Interrupt => "Interrupt rate",
            Self::Unresponsive => "Unresponsive duration",
            Self::SlowLaunch => "Slow launch",
            Self::AgentAge => "Abandoned agent age",
            Self::Notifications => "Native notifications",
            Self::AgentPatterns => "Agent patterns",
        }
    }

    pub const fn unit(self) -> &'static str {
        match self {
            Self::SampleInterval | Self::SlowLaunch => "ms",
            Self::Retention => "days",
            Self::BaselineSigma => "sigma",
            Self::Cpu => "%",
            Self::MemoryGrowth | Self::KernelPool => "MB",
            Self::DiskLatency => "ms",
            Self::Io => "MB/s",
            Self::Dpc | Self::Interrupt => "/s",
            Self::Unresponsive => "seconds",
            Self::AgentAge => "minutes",
            _ => "",
        }
    }

    pub fn value(self, settings: &Settings) -> String {
        match self {
            Self::SampleInterval => settings.sample_interval_ms.to_string(),
            Self::Retention => settings.retention_days.to_string(),
            Self::Sustained => settings.sustained_samples.to_string(),
            Self::BaselineSigma => settings.baseline_sigma.to_string(),
            Self::Cpu => settings.cpu_percent.to_string(),
            Self::MemoryGrowth => settings.memory_growth_mb.to_string(),
            Self::HandleGrowth => settings.handle_growth.to_string(),
            Self::ThreadGrowth => settings.thread_growth.to_string(),
            Self::DiskLatency => settings.disk_latency_ms.to_string(),
            Self::Io => settings.io_mb_per_sec.to_string(),
            Self::KernelPool => settings.kernel_pool_growth_mb.to_string(),
            Self::Dpc => settings.dpc_rate.to_string(),
            Self::Interrupt => settings.interrupt_rate.to_string(),
            Self::Unresponsive => settings.unresponsive_seconds.to_string(),
            Self::SlowLaunch => settings.slow_launch_ms.to_string(),
            Self::AgentAge => settings.abandoned_agent_minutes.to_string(),
            Self::Notifications => if settings.notifications_enabled {
                "on"
            } else {
                "off"
            }
            .into(),
            Self::AgentPatterns => settings.agent_process_patterns.join(", "),
        }
    }

    pub fn assign(self, settings: &mut Settings, input: &str) -> Result<(), String> {
        match self {
            Self::SampleInterval => {
                settings.sample_interval_ms = parse_range(input, 1_000, 60_000)?
            }
            Self::Retention => settings.retention_days = parse_range(input, 1, 365)?,
            Self::Sustained => settings.sustained_samples = parse_range(input, 2, 120)?,
            Self::BaselineSigma => settings.baseline_sigma = parse_float(input, 1.0, 10.0)?,
            Self::Cpu => settings.cpu_percent = parse_float(input, 1.0, 100.0)?,
            Self::MemoryGrowth => settings.memory_growth_mb = parse_float(input, 16.0, 65_536.0)?,
            Self::HandleGrowth => settings.handle_growth = parse_range(input, 10, 100_000)?,
            Self::ThreadGrowth => settings.thread_growth = parse_range(input, 5, 10_000)?,
            Self::DiskLatency => settings.disk_latency_ms = parse_float(input, 1.0, 1_000.0)?,
            Self::Io => settings.io_mb_per_sec = parse_float(input, 1.0, 10_000.0)?,
            Self::KernelPool => {
                settings.kernel_pool_growth_mb = parse_float(input, 16.0, 65_536.0)?
            }
            Self::Dpc => settings.dpc_rate = parse_float(input, 1.0, 1_000_000.0)?,
            Self::Interrupt => settings.interrupt_rate = parse_float(input, 1.0, 10_000_000.0)?,
            Self::Unresponsive => settings.unresponsive_seconds = parse_range(input, 2, 300)?,
            Self::SlowLaunch => settings.slow_launch_ms = parse_range(input, 1_000, 120_000)?,
            Self::AgentAge => settings.abandoned_agent_minutes = parse_range(input, 5, 1_440)?,
            Self::Notifications => {
                settings.notifications_enabled = match input.trim().to_ascii_lowercase().as_str() {
                    "on" | "true" | "yes" | "1" => true,
                    "off" | "false" | "no" | "0" => false,
                    _ => return Err("enter on or off".into()),
                }
            }
            Self::AgentPatterns => {
                let values: Vec<String> = input
                    .split(',')
                    .map(str::trim)
                    .filter(|item| !item.is_empty())
                    .map(str::to_string)
                    .collect();
                if values.len() > 32 || values.iter().any(|item| item.len() > 64) {
                    return Err("use at most 32 patterns of 64 characters each".into());
                }
                settings.agent_process_patterns = values;
            }
        }
        Ok(())
    }
}

fn parse_range<T>(input: &str, minimum: T, maximum: T) -> Result<T, String>
where
    T: FromStr + PartialOrd + std::fmt::Display + Copy,
{
    let value = input
        .trim()
        .parse::<T>()
        .map_err(|_| format!("enter a number from {minimum} to {maximum}"))?;
    if value < minimum || value > maximum {
        return Err(format!("value must be from {minimum} to {maximum}"));
    }
    Ok(value)
}

fn parse_float(input: &str, minimum: f64, maximum: f64) -> Result<f64, String> {
    let value = parse_range(input, minimum, maximum)?;
    if !value.is_finite() {
        return Err("value must be finite".into());
    }
    Ok(value)
}

#[derive(Debug)]
pub enum WorkerCommand {
    RefreshAlerts,
    RefreshHistory {
        hours: u32,
    },
    RefreshTree,
    RefreshAnalyzer,
    RunChat {
        conversation_id: String,
        history: Vec<ChatMessage>,
        hours: u32,
    },
    CancelAnalyzer,
    LoadSettings,
    SaveSettings(Settings),
    Acknowledge(String),
    Terminate(u32),
    Stop,
}

#[derive(Debug)]
pub enum WorkerEvent {
    Snapshot(Result<Snapshot, String>),
    Alerts(Result<Vec<Alert>, String>),
    History(Result<HistoryResponse, String>),
    Tree(Result<Vec<ProcessNode>, String>),
    Diagnostics(Result<DiagnosticLogResponse, String>),
    Plans(Result<Vec<OptimizationPlan>, String>),
    CodexAuth(Result<String, String>),
    Chat(Result<ChatResponse, String>),
    Settings(Result<Settings, String>),
    Action(Result<String, String>),
}

pub struct Worker {
    pub commands: Sender<WorkerCommand>,
    pub events: Receiver<WorkerEvent>,
    handle: Option<JoinHandle<()>>,
}

impl Worker {
    pub fn start() -> Self {
        let (command_tx, command_rx) = bounded(32);
        let (event_tx, event_rx) = bounded(64);
        let handle = thread::Builder::new()
            .name("pcpulse-tui-client".into())
            .spawn(move || worker_loop(command_rx, event_tx))
            .ok();
        Self {
            commands: command_tx,
            events: event_rx,
            handle,
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.commands.send(WorkerCommand::Stop);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn worker_loop(commands: Receiver<WorkerCommand>, events: Sender<WorkerEvent>) {
    let client = PipeClient;
    let mut next_snapshot = Instant::now();
    let mut analyzer: Option<(JoinHandle<()>, Arc<AtomicBool>)> = None;
    loop {
        if analyzer
            .as_ref()
            .is_some_and(|(handle, _)| handle.is_finished())
            && let Some((handle, _)) = analyzer.take()
        {
            let _ = handle.join();
        }
        let wait = next_snapshot.saturating_duration_since(Instant::now());
        select! {
            recv(commands) -> command => {
                match command {
                    Ok(WorkerCommand::RefreshAlerts) => {
                        let from = Utc::now().timestamp_millis() - 30 * 86_400_000;
                        let _ = events.send(WorkerEvent::Alerts(client.alerts(from, 300).map_err(error_text)));
                    }
                    Ok(WorkerCommand::RefreshHistory { hours }) => {
                        let to = Utc::now().timestamp_millis();
                        let from = to - i64::from(hours) * 3_600_000;
                        let result = client.system_history(from, to, 800).map(|system| HistoryResponse {
                            system,
                            processes: Vec::new(),
                        }).map_err(error_text);
                        let _ = events.send(WorkerEvent::History(result));
                    }
                    Ok(WorkerCommand::RefreshTree) => {
                        let _ = events.send(WorkerEvent::Tree(client.process_tree().map_err(error_text)));
                    }
                    Ok(WorkerCommand::RefreshAnalyzer) => {
                        let from = Utc::now().timestamp_millis() - 24 * 3_600_000;
                        let _ = events.send(WorkerEvent::Diagnostics(
                            client.diagnostic_logs(from, 250).map_err(error_text),
                        ));
                        let _ = events.send(WorkerEvent::Plans(
                            client.optimization_plans(20).map_err(error_text),
                        ));
                        let _ = events.send(WorkerEvent::CodexAuth(
                            crate::analyzer::chatgpt_subscription_status().map_err(error_text),
                        ));
                    }
                    Ok(WorkerCommand::RunChat { conversation_id, history, hours }) if analyzer.is_none() => {
                        let cancellation = Arc::new(AtomicBool::new(false));
                        let worker_cancellation = Arc::clone(&cancellation);
                        let worker_events = events.clone();
                        match thread::Builder::new()
                            .name("pcpulse-systems-analyzer".into())
                            .spawn(move || {
                                let result = crate::analyzer::chat(
                                    &conversation_id,
                                    &history,
                                    hours,
                                    worker_cancellation,
                                )
                                    .map_err(error_text);
                                let _ = worker_events.send(WorkerEvent::Chat(result));
                            })
                        {
                            Ok(handle) => analyzer = Some((handle, cancellation)),
                            Err(error) => {
                                let _ = events.send(WorkerEvent::Chat(Err(format!(
                                    "failed to start systems analyzer: {error}"
                                ))));
                            }
                        }
                    }
                    Ok(WorkerCommand::RunChat { .. }) => {}
                    Ok(WorkerCommand::CancelAnalyzer) => {
                        if let Some((_, cancellation)) = &analyzer {
                            cancellation.store(true, Ordering::Release);
                        }
                    }
                    Ok(WorkerCommand::LoadSettings) => {
                        let _ = events.send(WorkerEvent::Settings(client.settings().map_err(error_text)));
                    }
                    Ok(WorkerCommand::SaveSettings(settings)) => {
                        let result = client.update_settings(settings).map_err(error_text);
                        let action = result.as_ref().map(|_| "Settings saved".into()).map_err(Clone::clone);
                        let _ = events.send(WorkerEvent::Settings(result));
                        let _ = events.send(WorkerEvent::Action(action));
                    }
                    Ok(WorkerCommand::Acknowledge(id)) => {
                        let result = client.acknowledge(id).map(|_| "Finding acknowledged".into()).map_err(error_text);
                        let _ = events.send(WorkerEvent::Action(result));
                    }
                    Ok(WorkerCommand::Terminate(pid)) => {
                        let result = client.terminate(pid, true).map(|_| format!("Termination request completed for PID {pid}")).map_err(error_text);
                        let _ = events.send(WorkerEvent::Action(result));
                        next_snapshot = Instant::now();
                    }
                    Ok(WorkerCommand::Stop) | Err(_) => {
                        if let Some((handle, cancellation)) = analyzer.take() {
                            cancellation.store(true, Ordering::Release);
                            let _ = handle.join();
                        }
                        break;
                    },
                }
            }
            default(wait) => {
                let _ = events.send(WorkerEvent::Snapshot(client.snapshot().map_err(error_text)));
                next_snapshot = Instant::now() + Duration::from_secs(2);
            }
        }
    }
}

fn error_text(error: anyhow::Error) -> String {
    format!("{error:#}")
}

pub struct App {
    pub page: Page,
    pub snapshot: Option<Snapshot>,
    pub connected: bool,
    pub last_error: Option<String>,
    pub status: String,
    pub status_is_error: bool,
    pub live_history: VecDeque<SystemMetric>,
    pub persisted_history: HistoryResponse,
    pub alerts: Vec<Alert>,
    pub diagnostics: DiagnosticLogResponse,
    pub plans: Vec<OptimizationPlan>,
    pub analyzer_running: bool,
    pub analyzer_window_hours: u32,
    pub conversation_id: String,
    pub chat_messages: VecDeque<ChatMessage>,
    pub latest_chat: Option<ChatResponse>,
    pub chat_scroll_from_bottom: u16,
    pub chat_sessions: Vec<ChatSession>,
    pub chat_history_focused: bool,
    pub chat_session_state: ListState,
    pub codex_auth_status: Option<String>,
    pub codex_auth_error: Option<String>,
    pub tree: Vec<TreeRow>,
    pub settings: Settings,
    pub settings_dirty: bool,
    pub process_sort: ProcessSort,
    pub tree_sort: TreeSort,
    pub alert_sort: AlertSort,
    pub setting_sort: SettingSort,
    pub suspect_sort: SuspectSort,
    pub process_filter: String,
    pub agents_only: bool,
    pub timeline_hours: u32,
    pub mode: InputMode,
    pub process_state: TableState,
    pub tree_state: TableState,
    pub alert_state: TableState,
    pub plan_action_state: ListState,
    pub setting_state: TableState,
    pub worker: Worker,
    chat_store: Option<ChatHistoryStore>,
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl App {
    pub fn new() -> Self {
        let worker = Worker::start();
        let _ = worker.commands.try_send(WorkerCommand::LoadSettings);
        let _ = worker.commands.try_send(WorkerCommand::RefreshAlerts);
        Self::with_worker(worker, true)
    }

    fn with_worker(worker: Worker, load_chat_history: bool) -> Self {
        let chat_store = load_chat_history.then(ChatHistoryStore::discover).flatten();
        let (chat_sessions, history_error) = match &chat_store {
            Some(store) => match store.load() {
                Ok(sessions) => (sessions, None),
                Err(error) => (
                    Vec::new(),
                    Some(format!("Chat history unavailable: {error:#}")),
                ),
            },
            None => (Vec::new(), None),
        };
        Self {
            page: Page::Overview,
            snapshot: None,
            connected: false,
            last_error: None,
            status: history_error
                .clone()
                .unwrap_or_else(|| "Connecting to collector…".into()),
            status_is_error: history_error.is_some(),
            live_history: VecDeque::with_capacity(LIVE_HISTORY_CAPACITY),
            persisted_history: HistoryResponse {
                system: Vec::new(),
                processes: Vec::new(),
            },
            alerts: Vec::new(),
            diagnostics: DiagnosticLogResponse {
                status: DiagnosticLogStatus::default(),
                logs: Vec::new(),
            },
            plans: Vec::new(),
            analyzer_running: false,
            analyzer_window_hours: 1,
            conversation_id: new_conversation_id(),
            chat_messages: VecDeque::with_capacity(16),
            latest_chat: None,
            chat_scroll_from_bottom: 0,
            chat_sessions,
            chat_history_focused: false,
            chat_session_state: ListState::default().with_selected(Some(0)),
            codex_auth_status: None,
            codex_auth_error: None,
            tree: Vec::new(),
            settings: Settings::default(),
            settings_dirty: false,
            process_sort: ProcessSort::Cpu,
            tree_sort: TreeSort::Lineage,
            alert_sort: AlertSort::FirstSeen,
            setting_sort: SettingSort::Name,
            suspect_sort: SuspectSort::Heat,
            process_filter: String::new(),
            agents_only: false,
            timeline_hours: 3,
            mode: InputMode::Normal,
            process_state: TableState::default().with_selected(0),
            tree_state: TableState::default().with_selected(0),
            alert_state: TableState::default().with_selected(0),
            plan_action_state: ListState::default().with_selected(Some(0)),
            setting_state: TableState::default().with_selected(0),
            worker,
            chat_store,
        }
    }

    #[cfg(test)]
    pub(crate) fn new_inert() -> Self {
        let (commands, command_sink) = bounded(1);
        let (event_source, events) = bounded(1);
        drop(command_sink);
        drop(event_source);
        Self::with_worker(
            Worker {
                commands,
                events,
                handle: None,
            },
            false,
        )
    }

    pub fn drain_events(&mut self) -> bool {
        let mut changed = false;
        while let Ok(event) = self.worker.events.try_recv() {
            changed = true;
            match event {
                WorkerEvent::Snapshot(Ok(snapshot)) => {
                    let reconnected = !self.connected;
                    self.connected = true;
                    self.last_error = None;
                    if reconnected {
                        self.status.clear();
                        self.status_is_error = false;
                    }
                    if self.live_history.back().map(|item| item.timestamp_ms)
                        != Some(snapshot.system.timestamp_ms)
                    {
                        self.live_history.push_back(snapshot.system.clone());
                        while self.live_history.len() > LIVE_HISTORY_CAPACITY {
                            self.live_history.pop_front();
                        }
                    }
                    self.snapshot = Some(snapshot);
                    self.clamp_selection();
                }
                WorkerEvent::Snapshot(Err(error)) => {
                    self.connected = false;
                    self.last_error = Some(error);
                }
                WorkerEvent::Alerts(Ok(alerts)) => {
                    self.alerts = alerts;
                    self.clamp_selection();
                }
                WorkerEvent::Alerts(Err(error))
                | WorkerEvent::History(Err(error))
                | WorkerEvent::Tree(Err(error))
                | WorkerEvent::Diagnostics(Err(error))
                | WorkerEvent::Plans(Err(error))
                | WorkerEvent::Settings(Err(error)) => self.set_error(error),
                WorkerEvent::History(Ok(history)) => self.persisted_history = history,
                WorkerEvent::Tree(Ok(nodes)) => {
                    self.tree.clear();
                    flatten_tree(&nodes, 0, &mut self.tree);
                    self.clamp_selection();
                }
                WorkerEvent::Diagnostics(Ok(diagnostics)) => {
                    self.diagnostics = diagnostics;
                }
                WorkerEvent::Plans(Ok(plans)) => {
                    self.plans = plans;
                    self.clamp_selection();
                }
                WorkerEvent::CodexAuth(Ok(status)) => {
                    self.codex_auth_status = Some(status);
                    self.codex_auth_error = None;
                }
                WorkerEvent::CodexAuth(Err(error)) => {
                    self.codex_auth_status = None;
                    self.codex_auth_error = Some(error);
                }
                WorkerEvent::Chat(Ok(response)) => {
                    self.analyzer_running = false;
                    self.chat_messages.push_back(ChatMessage {
                        role: ChatRole::Assistant,
                        timestamp_ms: Utc::now().timestamp_millis(),
                        text: response.answer.clone(),
                        evidence_refs: response.evidence_refs.clone(),
                    });
                    self.bound_chat_history();
                    self.latest_chat = Some(response);
                    self.chat_scroll_from_bottom = 0;
                    match self.persist_current_chat() {
                        Ok(()) => {
                            self.status =
                                "Systems analyzer answered from current PC Pulse evidence".into();
                            self.status_is_error = false;
                        }
                        Err(error) => self.set_error(error),
                    }
                }
                WorkerEvent::Chat(Err(error)) => {
                    self.analyzer_running = false;
                    self.set_error(error);
                }
                WorkerEvent::Settings(Ok(settings)) => {
                    self.settings = settings;
                    self.settings_dirty = false;
                }
                WorkerEvent::Action(Ok(message)) => {
                    self.status = message;
                    self.status_is_error = false;
                    let _ = self.worker.commands.try_send(WorkerCommand::RefreshAlerts);
                }
                WorkerEvent::Action(Err(error)) => self.set_error(error),
            }
        }
        changed
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> bool {
        if key.kind == KeyEventKind::Release {
            return false;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            return true;
        }
        match self.mode.clone() {
            InputMode::Normal => self.handle_normal_key(key),
            InputMode::Search(value) => self.handle_search_key(key, value),
            InputMode::Chat(value) => self.handle_chat_key(key, value),
            InputMode::ConfirmTerminate {
                pid,
                process_name,
                typed,
            } => self.handle_confirm_key(key, pid, process_name, typed),
            InputMode::EditSetting { field, typed } => self.handle_setting_input(key, field, typed),
        }
    }

    fn handle_normal_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char('q') => return true,
            KeyCode::Tab | KeyCode::Right if self.page != Page::Settings => self.change_page(1),
            KeyCode::BackTab | KeyCode::Left if self.page != Page::Settings => self.change_page(-1),
            KeyCode::Char('?') => self.select_page(Page::Help),
            KeyCode::Char(value @ '1'..='8') => {
                self.select_page(Page::ALL[(value as u8 - b'1') as usize]);
            }
            KeyCode::Esc if self.page == Page::Analyzer && self.analyzer_running => {
                let _ = self.worker.commands.try_send(WorkerCommand::CancelAnalyzer);
                self.status = "Cancelling systems analyzer…".into();
                self.status_is_error = false;
            }
            KeyCode::Esc if self.page == Page::Analyzer && self.chat_history_focused => {
                self.chat_history_focused = false;
            }
            KeyCode::Enter if self.page == Page::Analyzer && self.chat_history_focused => {
                self.activate_selected_chat();
            }
            KeyCode::Char('h') if self.page == Page::Analyzer && !self.analyzer_running => {
                self.chat_history_focused = !self.chat_history_focused;
            }
            KeyCode::Char('n' | 'c') if self.page == Page::Analyzer && !self.analyzer_running => {
                self.begin_new_chat();
            }
            KeyCode::Char('r') if self.page == Page::Tree => {
                self.tree_sort = TreeSort::Lineage;
                self.refresh_page();
            }
            KeyCode::Up | KeyCode::Char('k') => self.move_selection(-1),
            KeyCode::Down | KeyCode::Char('j') => self.move_selection(1),
            KeyCode::PageUp => self.move_selection(-10),
            KeyCode::PageDown => self.move_selection(10),
            KeyCode::Char('/') if self.page == Page::Processes => {
                self.mode = InputMode::Search(self.process_filter.clone());
            }
            KeyCode::Char('o') if self.page == Page::Processes => {
                self.process_sort = self.process_sort.next();
                self.process_state.select(Some(0));
            }
            KeyCode::Char('g') if self.page == Page::Processes => {
                self.agents_only = !self.agents_only;
                self.process_state.select(Some(0));
            }
            KeyCode::Char('x') if matches!(self.page, Page::Processes | Page::Tree) => {
                self.begin_termination();
            }
            KeyCode::Char('a') if self.page == Page::Alerts => self.acknowledge_selected(),
            KeyCode::Enter | KeyCode::Char('/')
                if self.page == Page::Analyzer
                    && !self.analyzer_running
                    && !self.chat_history_focused =>
            {
                self.mode = InputMode::Chat(String::new());
            }
            KeyCode::Char('r') => self.refresh_page(),
            KeyCode::Char('[') if self.page == Page::Timeline => {
                self.timeline_hours = (self.timeline_hours / 2).max(1);
                self.refresh_page();
            }
            KeyCode::Char(']') if self.page == Page::Timeline => {
                self.timeline_hours = (self.timeline_hours * 2).min(336);
                self.refresh_page();
            }
            KeyCode::Char('[') if self.page == Page::Analyzer && !self.analyzer_running => {
                self.analyzer_window_hours = (self.analyzer_window_hours / 2).max(1);
            }
            KeyCode::Char(']') if self.page == Page::Analyzer && !self.analyzer_running => {
                self.analyzer_window_hours = (self.analyzer_window_hours * 2).min(24);
            }
            KeyCode::Enter | KeyCode::Char('e') if self.page == Page::Settings => {
                self.begin_setting_edit();
            }
            KeyCode::Char('s') if self.page == Page::Settings => {
                let _ = self
                    .worker
                    .commands
                    .try_send(WorkerCommand::SaveSettings(self.settings.clone()));
            }
            _ => {}
        }
        false
    }

    fn handle_search_key(&mut self, key: KeyEvent, mut value: String) -> bool {
        match key.code {
            KeyCode::Esc => self.mode = InputMode::Normal,
            KeyCode::Enter => {
                self.process_filter = value;
                self.process_state.select(Some(0));
                self.mode = InputMode::Normal;
            }
            KeyCode::Backspace => {
                value.pop();
                self.mode = InputMode::Search(value);
            }
            KeyCode::Char(character) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                value.push(character);
                self.mode = InputMode::Search(value);
            }
            _ => {}
        }
        false
    }

    fn handle_chat_key(&mut self, key: KeyEvent, mut value: String) -> bool {
        match key.code {
            KeyCode::Esc => self.mode = InputMode::Normal,
            KeyCode::Backspace => {
                value.pop();
                self.mode = InputMode::Chat(value);
            }
            KeyCode::Char(character)
                if !key.modifiers.contains(KeyModifiers::CONTROL) && value.len() < 1_000 =>
            {
                value.push(character);
                self.mode = InputMode::Chat(value);
            }
            KeyCode::Enter if !value.trim().is_empty() => {
                let message = ChatMessage {
                    role: ChatRole::User,
                    timestamp_ms: Utc::now().timestamp_millis(),
                    text: value.trim().to_string(),
                    evidence_refs: Vec::new(),
                };
                self.chat_messages.push_back(message);
                self.bound_chat_history();
                let history_result = self.persist_current_chat();
                self.analyzer_running = true;
                self.chat_scroll_from_bottom = 0;
                self.status = format!(
                    "Systems analyzer is reading {} hour(s) of live evidence…",
                    self.analyzer_window_hours
                );
                self.status_is_error = false;
                let command = WorkerCommand::RunChat {
                    conversation_id: self.conversation_id.clone(),
                    history: self.chat_messages.iter().cloned().collect(),
                    hours: self.analyzer_window_hours,
                };
                if self.worker.commands.try_send(command).is_err() {
                    self.analyzer_running = false;
                    self.set_error("systems-analyzer command queue is busy".into());
                }
                if let Err(error) = history_result {
                    self.set_error(error);
                }
                self.mode = InputMode::Normal;
            }
            _ => {}
        }
        false
    }

    fn handle_confirm_key(
        &mut self,
        key: KeyEvent,
        pid: u32,
        process_name: String,
        mut typed: String,
    ) -> bool {
        match key.code {
            KeyCode::Esc => self.mode = InputMode::Normal,
            KeyCode::Backspace => {
                typed.pop();
                self.mode = InputMode::ConfirmTerminate {
                    pid,
                    process_name,
                    typed,
                };
            }
            KeyCode::Char(character) if character.is_ascii_digit() => {
                typed.push(character);
                self.mode = InputMode::ConfirmTerminate {
                    pid,
                    process_name,
                    typed,
                };
            }
            KeyCode::Enter => {
                if typed == pid.to_string() {
                    let _ = self.worker.commands.try_send(WorkerCommand::Terminate(pid));
                    self.status = format!("Sending confirmed request for PID {pid}…");
                    self.status_is_error = false;
                    self.mode = InputMode::Normal;
                } else {
                    self.set_error(format!("Confirmation must exactly match PID {pid}"));
                    self.mode = InputMode::ConfirmTerminate {
                        pid,
                        process_name,
                        typed,
                    };
                }
            }
            _ => {}
        }
        false
    }

    fn handle_setting_input(
        &mut self,
        key: KeyEvent,
        field: SettingField,
        mut typed: String,
    ) -> bool {
        match key.code {
            KeyCode::Esc => self.mode = InputMode::Normal,
            KeyCode::Backspace => {
                typed.pop();
                self.mode = InputMode::EditSetting { field, typed };
            }
            KeyCode::Char(character) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                typed.push(character);
                self.mode = InputMode::EditSetting { field, typed };
            }
            KeyCode::Enter => match field.assign(&mut self.settings, &typed) {
                Ok(()) => {
                    self.settings_dirty = true;
                    self.status = "Setting changed locally; press s to save".into();
                    self.status_is_error = false;
                    self.mode = InputMode::Normal;
                }
                Err(error) => {
                    self.set_error(error);
                    self.mode = InputMode::EditSetting { field, typed };
                }
            },
            _ => {}
        }
        false
    }

    pub(crate) fn select_page(&mut self, page: Page) {
        self.page = page;
        self.refresh_page();
    }

    fn change_page(&mut self, delta: i32) {
        let current = Page::ALL
            .iter()
            .position(|page| *page == self.page)
            .unwrap_or(0) as i32;
        let length = Page::ALL.len() as i32;
        let index = (current + delta).rem_euclid(length) as usize;
        self.select_page(Page::ALL[index]);
    }

    pub(crate) fn refresh_page(&self) {
        let command = match self.page {
            Page::Tree => Some(WorkerCommand::RefreshTree),
            Page::Alerts => Some(WorkerCommand::RefreshAlerts),
            Page::Timeline => Some(WorkerCommand::RefreshHistory {
                hours: self.timeline_hours,
            }),
            Page::Analyzer => Some(WorkerCommand::RefreshAnalyzer),
            Page::Settings => Some(WorkerCommand::LoadSettings),
            _ => None,
        };
        if let Some(command) = command {
            let _ = self.worker.commands.try_send(command);
        }
    }

    pub(crate) fn begin_termination(&mut self) {
        let process = match self.page {
            Page::Processes => self.selected_process(),
            Page::Tree => self.selected_tree_process(),
            _ => None,
        };
        if let Some(process) = process {
            if matches!(process.pid, 0 | 4) {
                self.set_error("System and Idle processes cannot be terminated".into());
            } else {
                self.mode = InputMode::ConfirmTerminate {
                    pid: process.pid,
                    process_name: process.name.clone(),
                    typed: String::new(),
                };
            }
        }
    }

    pub(crate) fn acknowledge_selected(&mut self) {
        if let Some(index) = self.alert_state.selected()
            && let Some(alert) = self.visible_alerts().get(index).copied()
        {
            let _ = self
                .worker
                .commands
                .try_send(WorkerCommand::Acknowledge(alert.id.clone()));
        }
    }

    pub(crate) fn begin_setting_edit(&mut self) {
        let index = self.setting_state.selected().unwrap_or(0);
        if let Some(field) = self.visible_setting_fields().get(index).copied() {
            self.mode = InputMode::EditSetting {
                field,
                typed: field.value(&self.settings),
            };
        }
    }

    pub(crate) fn move_selection(&mut self, delta: isize) {
        let process_count = self.process_count();
        match self.page {
            Page::Processes => move_table(&mut self.process_state, process_count, delta),
            Page::Tree => move_table(&mut self.tree_state, self.tree.len(), delta),
            Page::Alerts => move_table(&mut self.alert_state, self.alerts.len(), delta),
            Page::Analyzer => {
                if self.chat_history_focused {
                    move_list(
                        &mut self.chat_session_state,
                        self.chat_sessions.len() + 1,
                        delta,
                    );
                } else if delta < 0 {
                    self.chat_scroll_from_bottom = self
                        .chat_scroll_from_bottom
                        .saturating_add(delta.unsigned_abs().min(u16::MAX as usize) as u16);
                } else {
                    self.chat_scroll_from_bottom = self
                        .chat_scroll_from_bottom
                        .saturating_sub(delta.min(u16::MAX as isize) as u16);
                }
            }
            Page::Settings => move_table(&mut self.setting_state, SettingField::ALL.len(), delta),
            _ => {}
        }
    }

    fn clamp_selection(&mut self) {
        let process_count = self.process_count();
        clamp_table(&mut self.process_state, process_count);
        clamp_table(&mut self.tree_state, self.tree.len());
        clamp_table(&mut self.alert_state, self.alerts.len());
        clamp_list(&mut self.chat_session_state, self.chat_sessions.len() + 1);
        let action_count = self.plans.first().map_or(0, |plan| plan.actions.len());
        clamp_list(&mut self.plan_action_state, action_count);
    }

    fn set_error(&mut self, error: String) {
        self.status = error;
        self.status_is_error = true;
    }

    fn bound_chat_history(&mut self) {
        while self.chat_messages.len() > 16 {
            self.chat_messages.pop_front();
        }
    }

    fn persist_current_chat(&mut self) -> Result<(), String> {
        if self.chat_messages.is_empty() {
            return Ok(());
        }
        let now_ms = Utc::now().timestamp_millis();
        let created_at_ms = self
            .chat_sessions
            .iter()
            .find(|session| session.conversation_id == self.conversation_id)
            .map(|session| session.created_at_ms);
        let session = ChatSession::from_conversation(
            self.conversation_id.clone(),
            self.chat_messages.iter().cloned().collect(),
            self.latest_chat.clone(),
            created_at_ms,
            now_ms,
        );
        if let Some(store) = &self.chat_store {
            store
                .upsert(&mut self.chat_sessions, session)
                .map_err(|error| format!("Failed to save chat history: {error:#}"))?;
        } else if let Some(existing) = self
            .chat_sessions
            .iter_mut()
            .find(|item| item.conversation_id == session.conversation_id)
        {
            *existing = session;
        } else {
            self.chat_sessions.insert(0, session);
        }
        self.chat_session_state.select(Some(1));
        Ok(())
    }

    pub(crate) fn begin_new_chat(&mut self) {
        self.conversation_id = new_conversation_id();
        self.chat_messages.clear();
        self.latest_chat = None;
        self.chat_scroll_from_bottom = 0;
        self.chat_history_focused = false;
        self.chat_session_state.select(Some(0));
        self.status = "New analyzer conversation ready".into();
        self.status_is_error = false;
    }

    pub(crate) fn activate_chat_history_index(&mut self, index: usize) {
        if index == 0 {
            self.begin_new_chat();
            return;
        }
        let Some(session) = self.chat_sessions.get(index - 1).cloned() else {
            return;
        };
        self.conversation_id = session.conversation_id;
        self.chat_messages = session.messages.into();
        self.latest_chat = session.latest_response;
        self.chat_scroll_from_bottom = 0;
        self.chat_history_focused = false;
        self.chat_session_state.select(Some(index));
        self.status = "Previous analyzer conversation restored".into();
        self.status_is_error = false;
    }

    fn activate_selected_chat(&mut self) {
        let index = self.chat_session_state.selected().unwrap_or(0);
        self.activate_chat_history_index(index);
    }

    pub fn visible_processes(&self) -> Vec<&ProcessMetric> {
        let Some(snapshot) = &self.snapshot else {
            return Vec::new();
        };
        let query = self.process_filter.to_ascii_lowercase();
        let mut result: Vec<&ProcessMetric> = snapshot
            .processes
            .iter()
            .filter(|process| {
                (!self.agents_only || process.is_agent_candidate)
                    && (query.is_empty()
                        || process.name.to_ascii_lowercase().contains(&query)
                        || process
                            .executable_path
                            .to_ascii_lowercase()
                            .contains(&query)
                        || process.pid.to_string().contains(&query))
            })
            .collect();
        result.sort_by(|left, right| match self.process_sort {
            ProcessSort::Pid => left.pid.cmp(&right.pid),
            ProcessSort::Cpu => right.cpu_percent.total_cmp(&left.cpu_percent),
            ProcessSort::Memory => right.working_set_bytes.cmp(&left.working_set_bytes),
            ProcessSort::Io => (right.read_bytes_per_sec + right.write_bytes_per_sec)
                .total_cmp(&(left.read_bytes_per_sec + left.write_bytes_per_sec)),
            ProcessSort::Handles => right.handle_count.cmp(&left.handle_count),
            ProcessSort::Threads => right.thread_count.cmp(&left.thread_count),
            ProcessSort::Age => left.started_at_ms.cmp(&right.started_at_ms),
            ProcessSort::Name => left
                .name
                .to_ascii_lowercase()
                .cmp(&right.name.to_ascii_lowercase()),
        });
        result
    }

    pub fn selected_process(&self) -> Option<&ProcessMetric> {
        self.process_state
            .selected()
            .and_then(|index| self.visible_processes().get(index).copied())
    }

    pub fn selected_tree_process(&self) -> Option<&ProcessMetric> {
        self.tree_state
            .selected()
            .and_then(|index| self.visible_tree_rows().get(index).copied())
            .map(|row| &row.process)
    }

    pub fn visible_tree_rows(&self) -> Vec<&TreeRow> {
        let mut rows: Vec<&TreeRow> = self.tree.iter().collect();
        match self.tree_sort {
            TreeSort::Lineage => {}
            TreeSort::Pid => rows.sort_by_key(|row| row.process.pid),
            TreeSort::Name => rows.sort_by(|left, right| {
                left.process
                    .name
                    .to_ascii_lowercase()
                    .cmp(&right.process.name.to_ascii_lowercase())
            }),
            TreeSort::Cpu => rows.sort_by(|left, right| {
                right
                    .process
                    .cpu_percent
                    .total_cmp(&left.process.cpu_percent)
            }),
            TreeSort::Memory => rows.sort_by(|left, right| {
                right
                    .process
                    .working_set_bytes
                    .cmp(&left.process.working_set_bytes)
            }),
            TreeSort::Io => rows.sort_by(|left, right| {
                (right.process.read_bytes_per_sec + right.process.write_bytes_per_sec).total_cmp(
                    &(left.process.read_bytes_per_sec + left.process.write_bytes_per_sec),
                )
            }),
        }
        rows
    }

    pub fn visible_alerts(&self) -> Vec<&Alert> {
        let mut alerts: Vec<&Alert> = self.alerts.iter().collect();
        alerts.sort_by(|left, right| match self.alert_sort {
            AlertSort::Severity => severity_rank(right.severity).cmp(&severity_rank(left.severity)),
            AlertSort::Title => left
                .title
                .to_ascii_lowercase()
                .cmp(&right.title.to_ascii_lowercase()),
            AlertSort::Owner => left
                .process_name
                .as_deref()
                .unwrap_or("system / driver")
                .to_ascii_lowercase()
                .cmp(
                    &right
                        .process_name
                        .as_deref()
                        .unwrap_or("system / driver")
                        .to_ascii_lowercase(),
                ),
            AlertSort::State => alert_state_rank(left).cmp(&alert_state_rank(right)),
            AlertSort::FirstSeen => right.first_seen_ms.cmp(&left.first_seen_ms),
        });
        alerts
    }

    pub fn visible_setting_fields(&self) -> Vec<SettingField> {
        let mut fields = SettingField::ALL.to_vec();
        fields.sort_by(|left, right| match self.setting_sort {
            SettingSort::Name => left.label().cmp(right.label()),
            SettingSort::Value => left
                .value(&self.settings)
                .to_ascii_lowercase()
                .cmp(&right.value(&self.settings).to_ascii_lowercase()),
            SettingSort::Unit => left
                .unit()
                .cmp(right.unit())
                .then_with(|| left.label().cmp(right.label())),
        });
        fields
    }

    pub fn selected_alert(&self) -> Option<&Alert> {
        self.alert_state
            .selected()
            .and_then(|index| self.visible_alerts().get(index).copied())
    }

    pub fn selected_plan_action(&self) -> Option<&pcpulse_service::models::PlanAction> {
        self.plan_action_state
            .selected()
            .and_then(|index| self.plans.first()?.actions.get(index))
    }

    fn process_count(&self) -> usize {
        self.visible_processes().len()
    }
}

fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Info => 0,
        Severity::Warning => 1,
        Severity::Critical => 2,
    }
}

fn alert_state_rank(alert: &Alert) -> u8 {
    if alert.resolved_at_ms.is_some() {
        2
    } else if alert.acknowledged {
        1
    } else {
        0
    }
}

fn flatten_tree(nodes: &[ProcessNode], depth: usize, rows: &mut Vec<TreeRow>) {
    for node in nodes {
        rows.push(TreeRow {
            depth,
            process: node.process.clone(),
        });
        flatten_tree(&node.children, depth + 1, rows);
    }
}

fn next_index(current: usize, length: usize, delta: isize) -> usize {
    if length == 0 {
        return 0;
    }
    current.saturating_add_signed(delta).min(length - 1)
}

fn move_table(state: &mut TableState, length: usize, delta: isize) {
    let selected = next_index(state.selected().unwrap_or(0), length, delta);
    state.select((length > 0).then_some(selected));
}

fn move_list(state: &mut ListState, length: usize, delta: isize) {
    let selected = next_index(state.selected().unwrap_or(0), length, delta);
    state.select((length > 0).then_some(selected));
}

fn clamp_table(state: &mut TableState, length: usize) {
    let selected = state.selected().unwrap_or(0).min(length.saturating_sub(1));
    state.select((length > 0).then_some(selected));
}

fn clamp_list(state: &mut ListState, length: usize) {
    let selected = state.selected().unwrap_or(0).min(length.saturating_sub(1));
    state.select((length > 0).then_some(selected));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_setting_ranges() {
        let mut settings = Settings::default();
        assert!(SettingField::Cpu.assign(&mut settings, "101").is_err());
        assert!(SettingField::Cpu.assign(&mut settings, "75").is_ok());
        assert_eq!(settings.cpu_percent, 75.0);
        assert!(
            SettingField::SampleInterval
                .assign(&mut settings, "999")
                .is_err()
        );
    }

    #[test]
    fn process_sort_cycles_to_origin() {
        let mut sort = ProcessSort::Cpu;
        for _ in 0..8 {
            sort = sort.next();
        }
        assert_eq!(sort, ProcessSort::Cpu);
    }

    #[test]
    fn flattens_process_tree_in_depth_first_order() {
        fn process(pid: u32) -> ProcessMetric {
            ProcessMetric {
                timestamp_ms: 0,
                pid,
                parent_pid: 0,
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
                started_at_ms: 0,
                session_id: 0,
                responsive: true,
                has_visible_window: false,
                launch_duration_ms: None,
                is_agent_candidate: false,
            }
        }
        let nodes = vec![ProcessNode {
            process: process(1),
            children: vec![ProcessNode {
                process: process(2),
                children: Vec::new(),
            }],
        }];
        let mut rows = Vec::new();
        flatten_tree(&nodes, 0, &mut rows);
        assert_eq!((rows[0].process.pid, rows[0].depth), (1, 0));
        assert_eq!((rows[1].process.pid, rows[1].depth), (2, 1));
    }

    #[test]
    fn chat_history_is_bounded_to_recent_turns() {
        let mut app = App::new_inert();
        for timestamp_ms in 0..20 {
            app.chat_messages.push_back(ChatMessage {
                role: ChatRole::User,
                timestamp_ms,
                text: format!("message {timestamp_ms}"),
                evidence_refs: Vec::new(),
            });
        }
        app.bound_chat_history();
        assert_eq!(app.chat_messages.len(), 16);
        assert_eq!(
            app.chat_messages.front().map(|item| item.timestamp_ms),
            Some(4)
        );
    }

    #[test]
    fn enter_opens_internal_chat_prompt_on_analyzer_page() {
        let mut app = App::new_inert();
        app.page = Page::Analyzer;
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(matches!(app.mode, InputMode::Chat(ref value) if value.is_empty()));
    }

    #[test]
    fn previous_chat_can_be_restored_after_beginning_a_new_one() {
        let mut app = App::new_inert();
        let original_id = app.conversation_id.clone();
        app.chat_messages.push_back(ChatMessage {
            role: ChatRole::User,
            timestamp_ms: 10,
            text: "Why did the machine slow down?".into(),
            evidence_refs: Vec::new(),
        });
        app.persist_current_chat().unwrap();
        assert_eq!(app.chat_sessions.len(), 1);

        app.begin_new_chat();
        assert_ne!(app.conversation_id, original_id);
        assert!(app.chat_messages.is_empty());

        app.activate_chat_history_index(1);
        assert_eq!(app.conversation_id, original_id);
        assert_eq!(app.chat_messages.len(), 1);
        assert_eq!(app.chat_messages[0].text, "Why did the machine slow down?");
    }
}
