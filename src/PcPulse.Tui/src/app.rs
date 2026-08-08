use crate::{
    analyzer::{ChatMessage, ChatResponse, ChatRole},
    chat_history::{ChatHistoryStore, ChatSession},
    client::PipeClient,
    prefs::{self, PrefsStore, UiPrefs},
    theme,
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
/// Two left clicks on the same finding row within this window count as a
/// double-click and open an investigation.
const DOUBLE_CLICK_WINDOW: Duration = Duration::from_millis(400);
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
    ClientTheme,
    ClientEffects,
    ClientTimeout,
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
    /// Local terminal preferences: stored per user in `ui-prefs.json` and
    /// never sent to (or validated by) the collector service.
    pub const CLIENT: [Self; 3] = [Self::ClientTheme, Self::ClientEffects, Self::ClientTimeout];

    /// Service-validated detector settings, saved through the pipe with `s`.
    pub const SERVICE: [Self; 18] = [
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

    pub const ALL: [Self; 21] = [
        Self::ClientTheme,
        Self::ClientEffects,
        Self::ClientTimeout,
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

    pub const fn is_client(self) -> bool {
        matches!(
            self,
            Self::ClientTheme | Self::ClientEffects | Self::ClientTimeout
        )
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::ClientTheme => "Theme profile",
            Self::ClientEffects => "Motion effects",
            Self::ClientTimeout => "Oracle time budget",
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
            Self::ClientTheme | Self::ClientEffects => "local",
            Self::ClientTimeout => "seconds",
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

    /// One plain-language sentence per row: what changing this value means
    /// for the person at the keyboard, not how the detector implements it.
    pub const fn description(self) -> &'static str {
        match self {
            Self::ClientTheme => {
                "Which look this terminal uses — vitals (green patient monitor) or avionics \
                 (amber cockpit display). Enter switches immediately and remembers your choice."
            }
            Self::ClientEffects => {
                "Whether brief motion effects play on page changes and new findings. Enter \
                 toggles; off is the reduced-motion mode."
            }
            Self::ClientTimeout => {
                "How many seconds one Oracle analysis may run before it is cancelled. Saved \
                 for your user and applied the next time PC Pulse starts."
            }
            Self::SampleInterval => {
                "How often PC Pulse measures the whole machine, in milliseconds. Shorter \
                 intervals notice problems sooner but check more often."
            }
            Self::Retention => {
                "How many days of history and findings are kept on disk before old records \
                 are cleaned up."
            }
            Self::Sustained => {
                "How many checks in a row a problem must fail before PC Pulse reports it — \
                 higher means fewer, more certain findings."
            }
            Self::BaselineSigma => {
                "How far a process must drift from its own normal behavior before it counts \
                 as abnormal. Higher tolerates more natural variation."
            }
            Self::Cpu => {
                "A process holding at least this share of the CPU for the sustained streak \
                 becomes a finding."
            }
            Self::MemoryGrowth => {
                "How much a process's memory must keep growing over recent minutes before it \
                 is flagged as a possible leak."
            }
            Self::HandleGrowth => {
                "How many extra Windows handles a process must accumulate before it is \
                 flagged — handles that only ever grow usually mean a leak."
            }
            Self::ThreadGrowth => {
                "How many extra threads a process must accumulate before it is flagged — \
                 runaway thread creation often precedes a hang."
            }
            Self::DiskLatency => {
                "The average disk response time that counts as slow. The busiest process is \
                 named as the likely cause, not proven."
            }
            Self::Io => {
                "A process reading or writing the disk at least this fast, sustained, \
                 becomes a finding."
            }
            Self::KernelPool => {
                "How much growth in Windows kernel (driver) memory is tolerated before a \
                 finding — pool leaks usually point at a driver, not an app."
            }
            Self::Dpc => {
                "How much deferred driver work per second counts as excessive — sustained \
                 high rates usually mean a misbehaving driver."
            }
            Self::Interrupt => {
                "How many hardware interrupts per second count as excessive — sustained \
                 storms usually point at a device or its driver."
            }
            Self::Unresponsive => {
                "How long an application window may stay frozen (not responding) before \
                 PC Pulse reports it."
            }
            Self::SlowLaunch => {
                "How long an app may take from launch to its first visible window before it \
                 is reported as a slow start."
            }
            Self::AgentAge => {
                "How old an idle, orphaned AI-agent process must be before it is reported \
                 as abandoned."
            }
            Self::Notifications => {
                "Whether the tray helper pops a Windows notification when a new sustained \
                 finding appears. Enter on or off."
            }
            Self::AgentPatterns => {
                "Comma-separated name or path fragments that identify AI-agent processes, \
                 used by agent focus and abandoned-agent findings."
            }
        }
    }

    pub fn value(self, settings: &Settings) -> String {
        match self {
            // Client preferences live outside the service `Settings`; the
            // TUNE page reads them through `App::setting_value`.
            Self::ClientTheme | Self::ClientEffects | Self::ClientTimeout => String::new(),
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
            Self::ClientTheme | Self::ClientEffects | Self::ClientTimeout => {
                return Err("local client preference — edited through its own handler".into());
            }
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
        focus_alert: Option<Alert>,
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
                    Ok(WorkerCommand::RunChat { conversation_id, history, hours, focus_alert }) if analyzer.is_none() => {
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
                                    focus_alert,
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

/// Where the Oracle `y` copy writes its text; swappable so tests never
/// spawn `clip.exe`.
pub(crate) type ClipboardSink = Box<dyn Fn(&str) -> Result<(), String>>;

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
    /// Wall-clock start of the in-flight analyzer submission; see `analyzer_progress`.
    pub(crate) analyzer_started_at: Option<Instant>,
    /// Sticky record of the most recent analyzer failure. Unlike `status`, it
    /// is not clobbered by routine status updates; it clears on the next chat
    /// submission (or a new conversation).
    // ui: render analyzer_last_error as a persistent error banner on the Analyzer (Oracle)
    // page whenever it is Some, independent of the one-line footer status.
    pub analyzer_last_error: Option<String>,
    pub analyzer_window_hours: u32,
    pub conversation_id: String,
    pub chat_messages: VecDeque<ChatMessage>,
    pub latest_chat: Option<ChatResponse>,
    pub chat_scroll_from_bottom: u16,
    pub chat_sessions: Vec<ChatSession>,
    pub chat_history_focused: bool,
    pub chat_session_state: ListState,
    /// Inline Chat Vault rename: `Some(typed)` while the rename band owns the
    /// keyboard. Like [`Self::help_overlay`], deliberately not an
    /// [`InputMode`] variant — the effects layer diffs `InputMode` and this
    /// band is vault chrome, not a page input state.
    pub vault_rename: Option<String>,
    /// Two-step vault delete: the conversation id armed by the first `d`.
    /// Any other key disarms it.
    pub vault_delete_armed: Option<String>,
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
    /// The '?' keys overlay: `Some(scroll)` while open. Deliberately not an
    /// [`InputMode`] variant — the effects layer diffs `InputMode` through
    /// its own `ModeKind`, and the overlay is chrome, not an input state.
    pub help_overlay: Option<u16>,
    /// The client preferences in force for this run (CLI flags already
    /// folded in). `t` / `m` / TUNE edits update and persist them.
    pub client_prefs: UiPrefs,
    pub prefs_store: Option<PrefsStore>,
    /// Set when a theme change needs `terminal.clear()` on the next loop
    /// turn; drained by `take_terminal_clear`.
    needs_terminal_clear: bool,
    /// Set when the TUNE client section toggles motion effects; drained by
    /// the main loop, which owns the `MotionSystem`.
    effects_request: Option<bool>,
    /// Clipboard sink for the Oracle `y` copy. The real path pipes UTF-16LE
    /// into `clip.exe`; tests substitute a recorder.
    pub(crate) clipboard: ClipboardSink,
    pub process_state: TableState,
    pub tree_state: TableState,
    pub alert_state: TableState,
    /// Most recent left click on a finding row, for double-click detection.
    alert_last_click: Option<(usize, Instant)>,
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
            analyzer_started_at: None,
            analyzer_last_error: None,
            analyzer_window_hours: 1,
            conversation_id: new_conversation_id(),
            chat_messages: VecDeque::with_capacity(16),
            latest_chat: None,
            chat_scroll_from_bottom: 0,
            chat_sessions,
            chat_history_focused: false,
            chat_session_state: ListState::default().with_selected(Some(0)),
            vault_rename: None,
            vault_delete_armed: None,
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
            help_overlay: None,
            client_prefs: UiPrefs::default(),
            prefs_store: None,
            needs_terminal_clear: false,
            effects_request: None,
            clipboard: Box::new(write_clipboard_via_clip),
            process_state: TableState::default().with_selected(0),
            tree_state: TableState::default().with_selected(0),
            alert_state: TableState::default().with_selected(0),
            alert_last_click: None,
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
                    self.analyzer_started_at = None;
                    self.chat_messages.push_back(ChatMessage {
                        role: ChatRole::Assistant,
                        timestamp_ms: Utc::now().timestamp_millis(),
                        text: response.answer.clone(),
                        evidence_refs: response.evidence_refs.clone(),
                        is_error: false,
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
                WorkerEvent::Chat(Err(error)) => self.handle_chat_failure(error),
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
        // While the vault rename band is open it owns the keyboard, exactly
        // like the keys overlay below: every character is title text.
        if let Some(mut typed) = self.vault_rename.take() {
            match key.code {
                KeyCode::Esc => {}
                KeyCode::Enter => self.commit_vault_rename(&typed),
                KeyCode::Backspace => {
                    typed.pop();
                    self.vault_rename = Some(typed);
                }
                KeyCode::Char(character)
                    if !key.modifiers.contains(KeyModifiers::CONTROL)
                        && typed.chars().count() < 60 =>
                {
                    typed.push(character);
                    self.vault_rename = Some(typed);
                }
                _ => self.vault_rename = Some(typed),
            }
            return false;
        }
        // Two-step delete: the armed id survives only an immediate second
        // `d`/`Delete`; every other key path leaves it taken (disarmed).
        let delete_armed = self.vault_delete_armed.take();
        // While the keys overlay is up it owns the keyboard: the page below
        // must not react to navigation or action keys.
        if let Some(scroll) = self.help_overlay {
            match key.code {
                KeyCode::Char('q') => return true,
                KeyCode::Char('?') | KeyCode::Esc => self.help_overlay = None,
                KeyCode::Char('j') | KeyCode::Down => {
                    self.help_overlay = Some(scroll.saturating_add(1));
                }
                KeyCode::Char('k') | KeyCode::Up => {
                    self.help_overlay = Some(scroll.saturating_sub(1));
                }
                KeyCode::PageDown => self.help_overlay = Some(scroll.saturating_add(10)),
                KeyCode::PageUp => self.help_overlay = Some(scroll.saturating_sub(10)),
                _ => {}
            }
            return false;
        }
        match key.code {
            KeyCode::Char('q') => return true,
            KeyCode::Tab | KeyCode::Right if self.page != Page::Settings => self.change_page(1),
            KeyCode::BackTab | KeyCode::Left if self.page != Page::Settings => self.change_page(-1),
            KeyCode::Char('?') => self.help_overlay = Some(0),
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
                // Land on the first saved chat, not the "＋ NEW CHAT" row, so
                // r/d act on a real session immediately.
                if self.chat_history_focused
                    && !self.chat_sessions.is_empty()
                    && self.chat_session_state.selected().unwrap_or(0) == 0
                {
                    self.chat_session_state.select(Some(1));
                }
            }
            KeyCode::Char('n' | 'c') if self.page == Page::Analyzer && !self.analyzer_running => {
                self.begin_new_chat();
            }
            KeyCode::Char('r') | KeyCode::F(2)
                if self.page == Page::Analyzer
                    && self.chat_history_focused
                    && !self.analyzer_running =>
            {
                self.begin_vault_rename();
            }
            KeyCode::Char('d') | KeyCode::Delete
                if self.page == Page::Analyzer
                    && self.chat_history_focused
                    && !self.analyzer_running =>
            {
                self.vault_delete_step(delete_armed);
            }
            KeyCode::Char('e')
                if self.page == Page::Analyzer
                    && !self.chat_history_focused
                    && !self.analyzer_running =>
            {
                self.edit_last_question();
            }
            KeyCode::Char('y') if self.page == Page::Analyzer => self.copy_latest_answer(),
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
            KeyCode::Char('i') if self.page == Page::Alerts => self.investigate_selected_finding(),
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
                self.submit_chat_message(value.trim().to_string(), Vec::new(), None);
                self.mode = InputMode::Normal;
            }
            _ => {}
        }
        false
    }

    /// The single submission path for every analyzer question — typed or
    /// composed by an investigation. Records the user turn, arms the running
    /// state and timeout ticker, clears the sticky error, and hands the
    /// bounded history to the worker.
    fn submit_chat_message(
        &mut self,
        text: String,
        evidence_refs: Vec<String>,
        focus_alert: Option<Alert>,
    ) {
        let message = ChatMessage {
            role: ChatRole::User,
            timestamp_ms: Utc::now().timestamp_millis(),
            text,
            evidence_refs,
            is_error: false,
        };
        self.chat_messages.push_back(message);
        self.bound_chat_history();
        let history_result = self.persist_current_chat();
        self.analyzer_running = true;
        self.analyzer_started_at = Some(Instant::now());
        self.analyzer_last_error = None;
        self.chat_scroll_from_bottom = 0;
        self.status = format!(
            "Systems analyzer is reading {} hour(s) of live evidence…",
            self.analyzer_window_hours
        );
        self.status_is_error = false;
        let command = WorkerCommand::RunChat {
            conversation_id: self.conversation_id.clone(),
            history: self.outgoing_chat_history(),
            hours: self.analyzer_window_hours,
            focus_alert,
        };
        if self.worker.commands.try_send(command).is_err() {
            self.analyzer_running = false;
            self.analyzer_started_at = None;
            self.set_error("systems-analyzer command queue is busy".into());
        }
        if let Err(error) = history_result {
            self.set_error(error);
        }
    }

    /// `i` on the Findings page (or a double-click on a finding row): open a
    /// fresh Oracle conversation about the selected finding — active or
    /// archived — and submit the composed question through the ordinary
    /// chat path, citing the finding's evidence reference.
    pub(crate) fn investigate_selected_finding(&mut self) {
        if self.analyzer_running {
            self.set_error("analyzer busy — Esc to cancel first".into());
            return;
        }
        let Some(alert) = self.selected_alert().cloned() else {
            return;
        };
        let question = compose_investigation_question(&alert);
        self.select_page(Page::Analyzer);
        self.begin_new_chat();
        // Carry the full finding so the analyzer's evidence bundle contains
        // it even when it has aged out of the fresh-context window; the
        // citation contract only accepts references backed by the bundle.
        self.submit_chat_message(question, vec![format!("alert:{}", alert.id)], Some(alert));
    }

    /// A left click on a finding row: always select it; a second click on the
    /// same row within [`DOUBLE_CLICK_WINDOW`] opens the investigation.
    pub(crate) fn register_finding_click(&mut self, index: usize) {
        self.alert_state.select(Some(index));
        let now = Instant::now();
        let is_double = self.alert_last_click.take().is_some_and(|(last, at)| {
            last == index && now.duration_since(at) <= DOUBLE_CLICK_WINDOW
        });
        if is_double {
            self.investigate_selected_finding();
        } else {
            self.alert_last_click = Some((index, now));
        }
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
            KeyCode::Enter if field == SettingField::ClientTimeout => {
                match parse_range(
                    &typed,
                    prefs::MIN_ANALYZER_TIMEOUT_SECS,
                    prefs::MAX_ANALYZER_TIMEOUT_SECS,
                ) {
                    Ok(seconds) => {
                        self.client_prefs.analyzer_timeout_secs = seconds;
                        self.mode = InputMode::Normal;
                        self.status =
                            "Oracle time budget saved for your user · applies at next launch"
                                .into();
                        self.status_is_error = false;
                        self.persist_client_prefs();
                    }
                    Err(error) => {
                        self.set_error(error);
                        self.mode = InputMode::EditSetting { field, typed };
                    }
                }
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
        let Some(field) = self.visible_setting_fields().get(index).copied() else {
            return;
        };
        match field {
            // The theme row is a two-position switch: Enter flips it and
            // persists immediately — no typed input to get wrong.
            SettingField::ClientTheme => {
                let active = theme::cycle();
                self.client_prefs.theme = active.id;
                self.needs_terminal_clear = true;
                self.status = format!("Theme: {} · saved for your user", active.name);
                self.status_is_error = false;
                self.persist_client_prefs();
            }
            SettingField::ClientEffects => {
                self.client_prefs.effects = !self.client_prefs.effects;
                self.effects_request = Some(self.client_prefs.effects);
                self.status = format!(
                    "Motion effects {} · saved for your user",
                    if self.client_prefs.effects {
                        "enabled"
                    } else {
                        "disabled"
                    }
                );
                self.status_is_error = false;
                self.persist_client_prefs();
            }
            _ => {
                self.mode = InputMode::EditSetting {
                    field,
                    typed: self.setting_value(field),
                };
            }
        }
    }

    /// The display value for a TUNE row: client preferences come from this
    /// process's runtime state, everything else from the service settings.
    pub fn setting_value(&self, field: SettingField) -> String {
        match field {
            SettingField::ClientTheme => theme::active().name.into(),
            SettingField::ClientEffects => if self.client_prefs.effects {
                "on"
            } else {
                "off"
            }
            .into(),
            SettingField::ClientTimeout => self.client_prefs.analyzer_timeout_secs.to_string(),
            _ => field.value(&self.settings),
        }
    }

    /// Adopt the startup preferences (CLI flags already folded in) and the
    /// store that future choices persist through.
    pub fn adopt_client_prefs(&mut self, prefs: UiPrefs, store: Option<PrefsStore>) {
        self.client_prefs = prefs;
        self.prefs_store = store;
    }

    /// Write the current client preferences to disk; without a store (tests,
    /// no %LOCALAPPDATA%) this is a no-op.
    pub fn persist_client_prefs(&mut self) {
        if let Some(store) = &self.prefs_store
            && let Err(error) = store.save(&self.client_prefs)
        {
            self.set_error(format!("Failed to save client preferences: {error:#}"));
        }
    }

    /// True exactly once after a theme change from inside the App: the main
    /// loop must clear the backend diff so no stale-bg cell survives.
    pub fn take_terminal_clear(&mut self) -> bool {
        std::mem::take(&mut self.needs_terminal_clear)
    }

    /// The desired motion-effects state, once, after a TUNE toggle; the main
    /// loop reconciles its `MotionSystem` with it.
    pub fn take_effects_request(&mut self) -> Option<bool> {
        self.effects_request.take()
    }

    /// `y` on Oracle: copy the latest successful analyzer answer.
    fn copy_latest_answer(&mut self) {
        let Some(answer) = self
            .chat_messages
            .iter()
            .rev()
            .find(|message| message.role == ChatRole::Assistant && !message.is_error)
            .map(|message| message.text.clone())
        else {
            self.set_error("No analyzer answer to copy yet".into());
            return;
        };
        match (self.clipboard)(&answer) {
            Ok(()) => {
                self.status = "Answer copied to clipboard".into();
                self.status_is_error = false;
            }
            Err(error) => self.set_error(format!("Clipboard copy failed: {error}")),
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

    /// Elapsed seconds since the in-flight analyzer submission plus the total
    /// timeout budget in seconds; `None` when no analysis is running.
    // ui: while analyzer_running, render this on the Analyzer (Oracle) page as
    // "analyzing {elapsed_m}m{elapsed_s}s / {budget_m}m{budget_s}s · Esc cancels".
    pub fn analyzer_progress(&self) -> Option<(u64, u64)> {
        self.analyzer_started_at.map(|started| {
            (
                started.elapsed().as_secs(),
                crate::analyzer::analyzer_timeout_secs(),
            )
        })
    }

    /// Milliseconds since the in-flight analyzer submission; `None` when no
    /// analysis is running. Drives the transcript's phase animation, which
    /// derives every frame deterministically from this value.
    pub fn analyzer_elapsed_ms(&self) -> Option<u64> {
        self.analyzer_started_at
            .map(|started| u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX))
    }

    /// The conversation turns sent to Codex: failed-turn records stay local to
    /// the transcript and are excluded from the analyzer prompt.
    fn outgoing_chat_history(&self) -> Vec<ChatMessage> {
        self.chat_messages
            .iter()
            .filter(|message| !message.is_error)
            .cloned()
            .collect()
    }

    /// Record an analyzer failure so it can never disappear silently: the
    /// failure becomes an error-marked assistant turn persisted with the
    /// conversation, and a sticky error that outlives routine status updates.
    fn handle_chat_failure(&mut self, error: String) {
        self.analyzer_running = false;
        self.analyzer_started_at = None;
        self.chat_messages.push_back(ChatMessage {
            role: ChatRole::Assistant,
            timestamp_ms: Utc::now().timestamp_millis(),
            text: format!("Analysis failed: {error}"),
            evidence_refs: Vec::new(),
            is_error: true,
        });
        self.bound_chat_history();
        self.chat_scroll_from_bottom = 0;
        let persisted = self.persist_current_chat();
        self.analyzer_last_error = Some(error.clone());
        self.set_error(error);
        if let Err(persist_error) = persisted {
            self.set_error(persist_error);
        }
    }

    fn persist_current_chat(&mut self) -> Result<(), String> {
        if self.chat_messages.is_empty() {
            return Ok(());
        }
        let now_ms = Utc::now().timestamp_millis();
        let existing = self
            .chat_sessions
            .iter()
            .find(|session| session.conversation_id == self.conversation_id);
        let created_at_ms = existing.map(|session| session.created_at_ms);
        // An explicit (renamed) title always outlives the derived one, even
        // as new turns arrive after a restore.
        let pinned_title = existing
            .filter(|session| session.title_pinned)
            .map(|session| session.title.clone());
        let session = ChatSession::from_conversation(
            self.conversation_id.clone(),
            self.chat_messages.iter().cloned().collect(),
            self.latest_chat.clone(),
            created_at_ms,
            pinned_title,
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
        self.analyzer_last_error = None;
        self.chat_scroll_from_bottom = 0;
        self.chat_history_focused = false;
        self.vault_rename = None;
        self.vault_delete_armed = None;
        self.chat_session_state.select(Some(0));
        self.status = "New analyzer conversation ready".into();
        self.status_is_error = false;
    }

    /// The Chat Vault session behind the current selection, skipping the
    /// pinned "＋ NEW CHAT" row at index 0.
    fn selected_vault_session_index(&self) -> Option<usize> {
        let index = self.chat_session_state.selected()?.checked_sub(1)?;
        (index < self.chat_sessions.len()).then_some(index)
    }

    /// `r` / `F2` with the vault focused: open the inline rename band seeded
    /// with the current title.
    fn begin_vault_rename(&mut self) {
        match self.selected_vault_session_index() {
            Some(index) => self.vault_rename = Some(self.chat_sessions[index].title.clone()),
            None => self.set_error("Select a saved chat to rename".into()),
        }
    }

    /// Enter inside the rename band: pin the typed title to the selected
    /// session and persist the vault. An empty title re-arms the band.
    fn commit_vault_rename(&mut self, typed: &str) {
        let title = typed.trim();
        if title.is_empty() {
            self.set_error("Chat title cannot be empty".into());
            self.vault_rename = Some(String::new());
            return;
        }
        let Some(index) = self.selected_vault_session_index() else {
            return;
        };
        let session = &mut self.chat_sessions[index];
        session.title = crate::chat_history::truncate_title(title, 52);
        session.title_pinned = true;
        match self.persist_sessions() {
            Ok(()) => {
                self.status = "Chat renamed".into();
                self.status_is_error = false;
            }
            Err(error) => self.set_error(error),
        }
    }

    /// `d` / `Delete` with the vault focused. First press arms the selected
    /// session; a second press on the same session deletes and persists.
    /// Deleting the restored/active session starts a fresh chat.
    fn vault_delete_step(&mut self, armed: Option<String>) {
        let Some(index) = self.selected_vault_session_index() else {
            self.set_error("Select a saved chat to delete".into());
            return;
        };
        let id = self.chat_sessions[index].conversation_id.clone();
        if armed.as_deref() != Some(id.as_str()) {
            self.status = format!(
                "Press d again to delete '{}'",
                self.chat_sessions[index].title
            );
            self.status_is_error = false;
            self.vault_delete_armed = Some(id);
            return;
        }
        let removed = self.chat_sessions.remove(index);
        let persisted = self.persist_sessions();
        if removed.conversation_id == self.conversation_id {
            self.begin_new_chat();
            // The user is still working the vault; keep it focused.
            self.chat_history_focused = true;
        }
        self.clamp_selection();
        match persisted {
            Ok(()) => {
                self.status = "Chat deleted".into();
                self.status_is_error = false;
            }
            Err(error) => self.set_error(error),
        }
    }

    /// `e` on Oracle: recall the latest user question into the chat input
    /// for editing and resubmission.
    fn edit_last_question(&mut self) {
        let Some(question) = self
            .chat_messages
            .iter()
            .rev()
            .find(|message| message.role == ChatRole::User)
            .map(|message| message.text.clone())
        else {
            self.set_error("No question to edit yet".into());
            return;
        };
        self.mode = InputMode::Chat(question);
        self.status = "Editing your last question — Enter resubmits".into();
        self.status_is_error = false;
    }

    /// Write the whole vault through the store's atomic-replace path; without
    /// a store (tests, no %LOCALAPPDATA%) the in-memory vault is the truth.
    fn persist_sessions(&self) -> Result<(), String> {
        match &self.chat_store {
            Some(store) => store
                .save(&self.chat_sessions)
                .map_err(|error| format!("Failed to save chat history: {error:#}")),
            None => Ok(()),
        }
    }

    /// A click on a Chat Vault row shows that conversation immediately —
    /// the natural click contract for a chat list — and keeps the vault
    /// focused so r/rename and d/delete still target the clicked chat.
    pub(crate) fn register_vault_click(&mut self, index: usize) {
        if index == 0 {
            self.begin_new_chat();
            return;
        }
        if index > self.chat_sessions.len() {
            return;
        }
        self.activate_chat_history_index(index);
        self.chat_history_focused = true;
        self.status = "Chat restored · r rename · d delete · Esc leaves the vault".into();
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

    /// TUNE rows: the local CLIENT section stays pinned at the top in its
    /// declared order; the service settings below it obey the active sort.
    pub fn visible_setting_fields(&self) -> Vec<SettingField> {
        let mut fields = SettingField::SERVICE.to_vec();
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
        let mut rows = SettingField::CLIENT.to_vec();
        rows.extend(fields);
        rows
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

fn severity_word(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "info",
        Severity::Warning => "warning",
        Severity::Critical => "critical",
    }
}

/// The Oracle question an investigation submits: it cites the finding
/// precisely, keeps only the fields that carry a value, and always ends on
/// the same three asks so the analyzer's answer shape stays predictable.
pub(crate) fn compose_investigation_question(alert: &Alert) -> String {
    let mut question = format!("Investigate finding {}: {}.", alert.id, alert.title);
    let mut facts: Vec<String> = Vec::new();
    if !alert.kind.is_empty() {
        facts.push(format!("Kind {}", alert.kind));
    }
    facts.push(format!("severity {}", severity_word(alert.severity)));
    if let Some(name) = alert
        .process_name
        .as_deref()
        .filter(|name| !name.is_empty())
    {
        facts.push(match alert.process_id {
            Some(pid) => format!("owner {name} (pid {pid})"),
            None => format!("owner {name}"),
        });
    }
    facts.push(format!("seen {}x", alert.occurrence_count));
    if alert.resolved_at_ms.is_some() {
        facts.push("now resolved".into());
    }
    question.push(' ');
    question.push_str(&facts.join(", "));
    question.push('.');
    let evidence: Vec<String> = alert
        .evidence
        .iter()
        .map(|item| format!("{} {}", item.label, item.value))
        .collect();
    if !evidence.is_empty() {
        question.push_str(&format!(" Evidence: {}.", evidence.join("; ")));
    }
    question.push_str(
        " Explain the likely root cause, whether it is still occurring, and the safest next steps.",
    );
    question
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

/// Copy `text` to the Windows clipboard by piping UTF-16LE with a BOM into
/// `clip.exe`. clip.exe sniffs the `FF FE` BOM and stores the payload as
/// Unicode text, which preserves non-ASCII characters end to end (verified
/// empirically: accents, symbols, and CJK round-trip); without the BOM it
/// would reinterpret the bytes in the console codepage and mangle them.
fn write_clipboard_via_clip(text: &str) -> Result<(), String> {
    use std::io::Write as _;
    use std::process::{Command, Stdio};
    let mut child = Command::new("clip.exe")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("failed to start clip.exe: {error}"))?;
    let mut payload: Vec<u8> = Vec::with_capacity(2 + text.len() * 2);
    payload.extend_from_slice(&[0xFF, 0xFE]);
    for unit in text.encode_utf16() {
        payload.extend_from_slice(&unit.to_le_bytes());
    }
    // Write, then drop stdin so clip.exe sees EOF before we wait on it.
    let written = child
        .stdin
        .take()
        .ok_or_else(|| "clip.exe stdin unavailable".to_string())
        .and_then(|mut stdin| {
            stdin
                .write_all(&payload)
                .map_err(|error| format!("failed to write to clip.exe: {error}"))
        });
    let status = child
        .wait()
        .map_err(|error| format!("clip.exe did not finish: {error}"));
    written?;
    let status = status?;
    if !status.success() {
        return Err(format!("clip.exe exited with {status}"));
    }
    Ok(())
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
                is_error: false,
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
            is_error: false,
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

    #[test]
    fn chat_failure_is_recorded_as_failed_turn_and_sticky_error() {
        let mut app = App::new_inert();
        app.chat_messages.push_back(ChatMessage {
            role: ChatRole::User,
            timestamp_ms: 10,
            text: "Why is the disk thrashing?".into(),
            evidence_refs: Vec::new(),
            is_error: false,
        });
        app.analyzer_running = true;
        app.analyzer_started_at = Some(Instant::now());

        app.handle_chat_failure(
            "Codex systems chat timed out after 300s · details: analyzer-last-error.log".into(),
        );

        assert!(!app.analyzer_running);
        assert!(app.analyzer_progress().is_none());
        assert_eq!(app.chat_messages.len(), 2);
        let failed = app.chat_messages.back().unwrap();
        assert_eq!(failed.role, ChatRole::Assistant);
        assert!(failed.is_error);
        assert!(failed.text.contains("timed out"));
        assert!(
            app.analyzer_last_error
                .as_deref()
                .is_some_and(|error| error.ends_with("details: analyzer-last-error.log"))
        );
        assert!(app.status_is_error);

        // The failed turn is persisted with the conversation for the Chat Vault.
        assert_eq!(app.chat_sessions.len(), 1);
        assert!(
            app.chat_sessions[0]
                .messages
                .iter()
                .any(|message| message.is_error)
        );

        // Failed turns never travel back to Codex on the next submission.
        let outgoing = app.outgoing_chat_history();
        assert_eq!(outgoing.len(), 1);
        assert!(outgoing.iter().all(|message| !message.is_error));

        // Routine status updates must not clobber the sticky error.
        app.status = "Connected".into();
        app.status_is_error = false;
        assert!(app.analyzer_last_error.is_some());

        // The next submission-equivalent reset clears it.
        app.begin_new_chat();
        assert!(app.analyzer_last_error.is_none());
    }

    /// An `App` whose worker command queue is held open by the test, so
    /// submissions actually enqueue and the sent commands can be asserted.
    fn app_with_captive_worker() -> (App, Receiver<WorkerCommand>) {
        let (commands, command_rx) = bounded(8);
        let (event_source, events) = bounded(1);
        drop(event_source);
        let app = App::with_worker(
            Worker {
                commands,
                events,
                handle: None,
            },
            false,
        );
        (app, command_rx)
    }

    fn investigation_alert() -> Alert {
        Alert {
            id: "finding-77".into(),
            kind: "memoryGrowth".into(),
            severity: Severity::Warning,
            first_seen_ms: 1_800_000_000_000,
            last_seen_ms: 1_800_000_600_000,
            process_id: Some(5100),
            process_name: Some("chrome.exe".into()),
            title: "Chrome working set is growing".into(),
            explanation: "sustained growth over baseline".into(),
            evidence: vec![
                pcpulse_service::models::Evidence {
                    label: "working set".into(),
                    value: "+512 MB in 10m".into(),
                },
                pcpulse_service::models::Evidence {
                    label: "baseline".into(),
                    value: "4.2 sigma".into(),
                },
            ],
            recommendation: "observe".into(),
            acknowledged: false,
            occurrence_count: 3,
            resolved_at_ms: None,
        }
    }

    const INVESTIGATION_TAIL: &str =
        " Explain the likely root cause, whether it is still occurring, and the safest next steps.";

    #[test]
    fn investigate_composes_the_question_and_submits_through_the_chat_path() {
        let (mut app, commands) = app_with_captive_worker();
        app.page = Page::Alerts;
        app.alerts = vec![investigation_alert()];
        app.alert_state.select(Some(0));

        app.handle_key(KeyEvent::new(KeyCode::Char('i'), KeyModifiers::NONE));

        assert_eq!(app.page, Page::Analyzer);
        assert!(app.analyzer_running);
        assert!(app.analyzer_progress().is_some());
        assert!(app.analyzer_last_error.is_none());
        assert_eq!(app.chat_messages.len(), 1);
        let turn = app.chat_messages.front().unwrap();
        assert_eq!(turn.role, ChatRole::User);
        assert_eq!(
            turn.text,
            format!(
                "Investigate finding finding-77: Chrome working set is growing. \
                 Kind memoryGrowth, severity warning, owner chrome.exe (pid 5100), seen 3x. \
                 Evidence: working set +512 MB in 10m; baseline 4.2 sigma.{INVESTIGATION_TAIL}"
            )
        );
        assert_eq!(turn.evidence_refs, vec!["alert:finding-77".to_string()]);

        // select_page(Analyzer) refreshes the page, then the chat runs; the
        // enqueued conversation carries the composed question.
        let sent: Vec<WorkerCommand> = commands.try_iter().collect();
        let run = sent
            .iter()
            .find_map(|command| match command {
                WorkerCommand::RunChat {
                    conversation_id,
                    history,
                    focus_alert,
                    ..
                } => Some((conversation_id, history, focus_alert)),
                _ => None,
            })
            .expect("investigation must enqueue a RunChat command");
        assert_eq!(run.0, &app.conversation_id);
        assert_eq!(run.1.len(), 1);
        assert!(run.1[0].text.starts_with("Investigate finding finding-77:"));
        // The full finding rides along so the analyzer folds it into the
        // evidence bundle — otherwise citing alert:<id> fails validation
        // whenever the finding has aged out of the fresh-context window.
        assert_eq!(
            run.2.as_ref().map(|alert| alert.id.as_str()),
            Some("finding-77")
        );
    }

    #[test]
    fn investigation_question_drops_absent_fields_and_notes_resolution() {
        let mut alert = investigation_alert();
        alert.id = "f-2".into();
        alert.title = "Kernel pool climbing".into();
        alert.kind = "kernelPool".into();
        alert.severity = Severity::Critical;
        alert.process_id = None;
        alert.process_name = None;
        alert.evidence = Vec::new();
        alert.occurrence_count = 1;
        alert.resolved_at_ms = Some(1_800_000_700_000);
        assert_eq!(
            compose_investigation_question(&alert),
            format!(
                "Investigate finding f-2: Kernel pool climbing. \
                 Kind kernelPool, severity critical, seen 1x, now resolved.{INVESTIGATION_TAIL}"
            )
        );
    }

    #[test]
    fn investigate_refuses_while_the_analyzer_is_busy() {
        let (mut app, commands) = app_with_captive_worker();
        app.page = Page::Alerts;
        app.alerts = vec![investigation_alert()];
        app.alert_state.select(Some(0));
        app.analyzer_running = true;
        app.analyzer_started_at = Some(Instant::now());

        app.handle_key(KeyEvent::new(KeyCode::Char('i'), KeyModifiers::NONE));

        assert_eq!(app.page, Page::Alerts);
        assert!(app.chat_messages.is_empty());
        assert_eq!(app.status, "analyzer busy — Esc to cancel first");
        assert!(app.status_is_error);
        assert!(
            !commands
                .try_iter()
                .any(|command| matches!(command, WorkerCommand::RunChat { .. }))
        );
    }

    #[test]
    fn double_clicking_a_finding_row_investigates_and_a_single_click_selects() {
        let (mut app, commands) = app_with_captive_worker();
        app.page = Page::Alerts;
        app.alerts = vec![investigation_alert()];

        app.register_finding_click(0);
        assert_eq!(app.page, Page::Alerts, "first click only selects");
        assert_eq!(app.alert_state.selected(), Some(0));
        assert!(app.chat_messages.is_empty());

        app.register_finding_click(0);
        assert_eq!(app.page, Page::Analyzer);
        assert!(app.analyzer_running);
        assert!(
            app.chat_messages
                .front()
                .is_some_and(|turn| turn.text.starts_with("Investigate finding finding-77:"))
        );
        assert!(
            commands
                .try_iter()
                .any(|command| matches!(command, WorkerCommand::RunChat { .. }))
        );
    }

    #[test]
    fn a_vault_click_shows_the_chat_and_keeps_rename_reachable() {
        let mut app = app_with_vault_session("Morning hunt question");
        let saved = app.conversation_id.clone();
        app.begin_new_chat();
        assert_ne!(app.conversation_id, saved);

        // One click shows the conversation — the click contract of a chat
        // list — and the vault stays focused so r/d target the clicked chat.
        app.register_vault_click(1);
        assert_eq!(app.conversation_id, saved, "a click must show the chat");
        assert!(app.chat_history_focused);
        assert_eq!(app.chat_session_state.selected(), Some(1));
    }

    #[test]
    fn focusing_the_vault_lands_on_the_first_saved_chat() {
        let mut app = app_with_vault_session("Morning hunt question");
        app.begin_new_chat();
        assert_eq!(app.chat_session_state.selected(), Some(0));
        app.handle_key(key(KeyCode::Char('h')));
        assert!(app.chat_history_focused);
        assert_eq!(
            app.chat_session_state.selected(),
            Some(1),
            "focus should land on a renameable chat, not the new-chat row"
        );
    }

    fn scratch_prefs_store(tag: &str) -> (PrefsStore, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!(
            "pcpulse-app-prefs-{tag}-{}-{}.json",
            std::process::id(),
            Utc::now().timestamp_millis()
        ));
        (PrefsStore::at(path.clone()), path)
    }

    #[test]
    fn y_copies_the_latest_successful_answer_to_the_clipboard() {
        use std::{cell::RefCell, rc::Rc};
        let mut app = App::new_inert();
        app.page = Page::Analyzer;
        let captured: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
        let sink = Rc::clone(&captured);
        app.clipboard = Box::new(move |text| {
            sink.borrow_mut().push(text.to_string());
            Ok(())
        });
        for (role, text, is_error) in [
            (ChatRole::User, "Why is the disk slow?", false),
            (
                ChatRole::Assistant,
                "Disk latency is fine — 1.8 ms average.",
                false,
            ),
            (ChatRole::Assistant, "Analysis failed: timed out", true),
        ] {
            app.chat_messages.push_back(ChatMessage {
                role,
                timestamp_ms: 0,
                text: text.into(),
                evidence_refs: Vec::new(),
                is_error,
            });
        }

        app.handle_key(KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE));

        // The failed turn is skipped: the latest *successful* answer wins.
        assert_eq!(
            captured.borrow().as_slice(),
            ["Disk latency is fine — 1.8 ms average.".to_string()]
        );
        assert_eq!(app.status, "Answer copied to clipboard");
        assert!(!app.status_is_error);
    }

    #[test]
    fn y_with_no_answer_sets_an_error_and_never_touches_the_clipboard() {
        use std::{cell::Cell, rc::Rc};
        let mut app = App::new_inert();
        app.page = Page::Analyzer;
        let called = Rc::new(Cell::new(false));
        let flag = Rc::clone(&called);
        app.clipboard = Box::new(move |_| {
            flag.set(true);
            Ok(())
        });
        // Only a failed turn exists — nothing copyable.
        app.chat_messages.push_back(ChatMessage {
            role: ChatRole::Assistant,
            timestamp_ms: 0,
            text: "Analysis failed: timed out".into(),
            evidence_refs: Vec::new(),
            is_error: true,
        });

        app.handle_key(KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE));

        assert!(!called.get(), "clipboard must not run without an answer");
        assert!(app.status_is_error);
        assert!(app.status.contains("No analyzer answer"));
    }

    #[test]
    fn question_mark_toggles_the_keys_overlay_without_leaving_the_page() {
        let mut app = App::new_inert();
        assert_eq!(app.page, Page::Overview);

        app.handle_key(KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE));
        assert_eq!(app.help_overlay, Some(0));
        assert_eq!(app.page, Page::Overview, "the page below must not change");

        // The overlay owns the keyboard: navigation keys scroll or are inert.
        app.handle_key(KeyEvent::new(KeyCode::Char('2'), KeyModifiers::NONE));
        assert_eq!(app.page, Page::Overview);
        app.handle_key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE));
        assert_eq!(app.help_overlay, Some(1));
        app.handle_key(KeyEvent::new(KeyCode::Char('k'), KeyModifiers::NONE));
        assert_eq!(app.help_overlay, Some(0));

        app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert_eq!(app.help_overlay, None);
        assert_eq!(app.page, Page::Overview);

        // '?' also closes it, including on the Keys page itself.
        app.select_page(Page::Help);
        app.handle_key(KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE));
        assert_eq!(app.help_overlay, Some(0));
        app.handle_key(KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE));
        assert_eq!(app.help_overlay, None);
        assert_eq!(app.page, Page::Help);
    }

    #[test]
    fn question_mark_stays_literal_text_inside_input_modes() {
        let mut app = App::new_inert();
        app.page = Page::Processes;
        app.mode = InputMode::Search("cpu".into());
        app.handle_key(KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE));
        assert!(matches!(app.mode, InputMode::Search(ref value) if value == "cpu?"));
        assert_eq!(app.help_overlay, None);

        app.mode = InputMode::Chat("what".into());
        app.handle_key(KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE));
        assert!(matches!(app.mode, InputMode::Chat(ref value) if value == "what?"));
        assert_eq!(app.help_overlay, None);

        app.mode = InputMode::EditSetting {
            field: SettingField::AgentPatterns,
            typed: "codex".into(),
        };
        app.handle_key(KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE));
        assert!(matches!(app.mode, InputMode::EditSetting { ref typed, .. } if typed == "codex?"));
        assert_eq!(app.help_overlay, None);
    }

    #[test]
    fn client_rows_stay_pinned_above_the_sorted_service_settings() {
        let mut app = App::new_inert();
        for sort in [SettingSort::Name, SettingSort::Value, SettingSort::Unit] {
            app.setting_sort = sort;
            let fields = app.visible_setting_fields();
            assert_eq!(&fields[..3], &SettingField::CLIENT, "{sort:?}");
            assert_eq!(fields.len(), SettingField::ALL.len());
        }
        assert!(SettingField::ClientTheme.is_client());
        assert!(!SettingField::Sustained.is_client());
        // Every row has a real plain-language description.
        for field in SettingField::ALL {
            assert!(
                field.description().len() > 40,
                "{field:?} needs a description"
            );
        }
    }

    #[test]
    fn enter_on_the_client_theme_row_cycles_and_persists_locally() {
        let _guard = theme::test_support::activate(theme::ThemeId::Vitals);
        let (store, path) = scratch_prefs_store("theme");
        let mut app = App::new_inert();
        app.adopt_client_prefs(UiPrefs::default(), Some(store.clone()));
        app.page = Page::Settings;
        app.setting_state.select(Some(0));

        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));

        assert_eq!(theme::active().id, theme::ThemeId::Avionics);
        assert_eq!(app.client_prefs.theme, theme::ThemeId::Avionics);
        assert_eq!(app.setting_value(SettingField::ClientTheme), "avionics");
        assert!(matches!(app.mode, InputMode::Normal), "no typed edit opens");
        assert!(app.take_terminal_clear(), "theme swap needs a repaint");
        assert!(!app.take_terminal_clear(), "the flag drains");
        assert_eq!(store.load().theme, theme::ThemeId::Avionics);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn enter_on_the_client_effects_row_toggles_and_hands_the_state_to_the_loop() {
        let mut app = App::new_inert();
        app.page = Page::Settings;
        app.setting_state.select(Some(1));
        assert!(app.client_prefs.effects);

        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));

        assert!(!app.client_prefs.effects);
        assert_eq!(app.setting_value(SettingField::ClientEffects), "off");
        assert_eq!(app.take_effects_request(), Some(false));
        assert_eq!(app.take_effects_request(), None, "the request drains");
        assert!(matches!(app.mode, InputMode::Normal));
    }

    #[test]
    fn client_timeout_edits_validate_and_save_per_user() {
        let (store, path) = scratch_prefs_store("timeout");
        let mut app = App::new_inert();
        app.adopt_client_prefs(UiPrefs::default(), Some(store.clone()));
        app.page = Page::Settings;
        app.setting_state.select(Some(2));

        // Enter opens the ordinary typed edit, prefilled with the current value.
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(matches!(
            app.mode,
            InputMode::EditSetting { field: SettingField::ClientTimeout, ref typed } if typed == "300"
        ));

        app.mode = InputMode::EditSetting {
            field: SettingField::ClientTimeout,
            typed: "600".into(),
        };
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(app.client_prefs.analyzer_timeout_secs, 600);
        assert_eq!(store.load().analyzer_timeout_secs, 600);
        assert!(app.status.contains("next launch"));
        assert!(!app.status_is_error);

        // Out-of-range input re-arms the edit with an error.
        app.mode = InputMode::EditSetting {
            field: SettingField::ClientTimeout,
            typed: "10".into(),
        };
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(app.status_is_error);
        assert!(matches!(app.mode, InputMode::EditSetting { .. }));
        assert_eq!(app.client_prefs.analyzer_timeout_secs, 600);
        let _ = std::fs::remove_file(path);
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    /// An inert app with one persisted vault session and the vault focused.
    fn app_with_vault_session(question: &str) -> App {
        let mut app = App::new_inert();
        app.page = Page::Analyzer;
        app.chat_messages.push_back(ChatMessage {
            role: ChatRole::User,
            timestamp_ms: 10,
            text: question.into(),
            evidence_refs: Vec::new(),
            is_error: false,
        });
        app.persist_current_chat().unwrap();
        app.handle_key(key(KeyCode::Char('h')));
        assert!(app.chat_history_focused);
        app.chat_session_state.select(Some(1));
        app
    }

    #[test]
    fn vault_rename_commits_a_pinned_title_that_beats_derivation_and_restore() {
        let mut app = app_with_vault_session("Why did the machine slow down?");

        // `r` opens the band seeded with the current (derived) title, and
        // while it is open every printable key is title text — even q.
        app.handle_key(key(KeyCode::Char('r')));
        assert_eq!(
            app.vault_rename.as_deref(),
            Some("Why did the machine slow down?")
        );
        for _ in 0.."Why did the machine slow down?".len() {
            app.handle_key(key(KeyCode::Backspace));
        }
        for character in "Morning slowdown q".chars() {
            assert!(!app.handle_key(key(KeyCode::Char(character))));
        }
        app.handle_key(key(KeyCode::Enter));

        assert!(app.vault_rename.is_none());
        assert_eq!(app.chat_sessions[0].title, "Morning slowdown q");
        assert!(app.chat_sessions[0].title_pinned);
        assert_eq!(app.status, "Chat renamed");
        assert!(!app.status_is_error);

        // The derived title never wins again: a new turn re-persists the
        // conversation and the explicit title survives.
        app.chat_messages.push_back(ChatMessage {
            role: ChatRole::User,
            timestamp_ms: 20,
            text: "And what about the disk?".into(),
            evidence_refs: Vec::new(),
            is_error: false,
        });
        app.persist_current_chat().unwrap();
        assert_eq!(app.chat_sessions[0].title, "Morning slowdown q");
        assert!(app.chat_sessions[0].title_pinned);

        // Restoring the session keeps the explicit title too.
        let renamed_id = app.chat_sessions[0].conversation_id.clone();
        app.begin_new_chat();
        app.activate_chat_history_index(1);
        assert_eq!(app.conversation_id, renamed_id);
        app.persist_current_chat().unwrap();
        assert_eq!(app.chat_sessions[0].title, "Morning slowdown q");
    }

    #[test]
    fn vault_rename_esc_cancels_and_f2_also_opens() {
        let mut app = app_with_vault_session("Why is the fan loud?");
        app.handle_key(key(KeyCode::F(2)));
        assert!(app.vault_rename.is_some());
        app.handle_key(key(KeyCode::Char('!')));
        app.handle_key(key(KeyCode::Esc));
        assert!(app.vault_rename.is_none());
        assert_eq!(app.chat_sessions[0].title, "Why is the fan loud?");
        assert!(!app.chat_sessions[0].title_pinned);

        // An empty title re-arms the band with an error instead of renaming.
        app.handle_key(key(KeyCode::Char('r')));
        for _ in 0..40 {
            app.handle_key(key(KeyCode::Backspace));
        }
        app.handle_key(key(KeyCode::Enter));
        assert!(app.vault_rename.is_some());
        assert!(app.status_is_error);
        app.handle_key(key(KeyCode::Esc));

        // On the ＋ NEW CHAT row there is nothing to rename.
        app.chat_session_state.select(Some(0));
        app.handle_key(key(KeyCode::Char('r')));
        assert!(app.vault_rename.is_none());
        assert!(app.status_is_error);
    }

    #[test]
    fn vault_delete_takes_two_presses_and_any_other_key_disarms() {
        let mut app = app_with_vault_session("Old chat to purge");
        // Park a second, inactive session so the delete target is not the
        // active conversation.
        app.begin_new_chat();
        app.chat_messages.push_back(ChatMessage {
            role: ChatRole::User,
            timestamp_ms: 30,
            text: "Fresh question".into(),
            evidence_refs: Vec::new(),
            is_error: false,
        });
        app.persist_current_chat().unwrap();
        app.handle_key(key(KeyCode::Char('h')));
        assert_eq!(app.chat_sessions.len(), 2);
        // Select the older (inactive) session — the last vault row.
        app.chat_session_state.select(Some(2));

        // First press only arms.
        app.handle_key(key(KeyCode::Char('d')));
        assert!(app.vault_delete_armed.is_some());
        assert!(app.status.contains("Press d again to delete 'Old chat to purge'"));
        assert_eq!(app.chat_sessions.len(), 2);

        // Any other key disarms; the next d starts over.
        app.handle_key(key(KeyCode::Char('k')));
        assert!(app.vault_delete_armed.is_none());
        app.chat_session_state.select(Some(2));
        app.handle_key(key(KeyCode::Char('d')));
        assert_eq!(app.chat_sessions.len(), 2, "re-armed, not deleted");

        // The immediate second press deletes and persists.
        app.handle_key(key(KeyCode::Char('d')));
        assert_eq!(app.chat_sessions.len(), 1);
        assert_eq!(app.status, "Chat deleted");
        assert!(!app.status_is_error);
        assert!(app.vault_delete_armed.is_none());
        assert!(
            app.chat_sessions
                .iter()
                .all(|session| session.title != "Old chat to purge")
        );
    }

    #[test]
    fn deleting_the_active_session_starts_a_fresh_chat() {
        let mut app = app_with_vault_session("Active investigation");
        let active_id = app.conversation_id.clone();
        app.handle_key(key(KeyCode::Delete));
        app.handle_key(key(KeyCode::Delete));
        assert!(app.chat_sessions.is_empty());
        assert_ne!(app.conversation_id, active_id);
        assert!(app.chat_messages.is_empty());
        assert!(app.latest_chat.is_none());
        assert!(app.chat_history_focused, "the vault keeps focus");
        assert_eq!(app.status, "Chat deleted");
    }

    #[test]
    fn e_recalls_the_latest_user_question_into_the_chat_input() {
        let mut app = App::new_inert();
        app.page = Page::Analyzer;
        for (role, text) in [
            (ChatRole::User, "First question"),
            (ChatRole::Assistant, "First answer"),
            (ChatRole::User, "Second question about the disk"),
            (ChatRole::Assistant, "Second answer"),
        ] {
            app.chat_messages.push_back(ChatMessage {
                role,
                timestamp_ms: 0,
                text: text.into(),
                evidence_refs: Vec::new(),
                is_error: false,
            });
        }
        app.handle_key(key(KeyCode::Char('e')));
        assert!(matches!(
            app.mode,
            InputMode::Chat(ref value) if value == "Second question about the disk"
        ));
        assert_eq!(app.status, "Editing your last question — Enter resubmits");
        assert!(!app.status_is_error);

        // Without a user turn there is nothing to edit.
        let mut empty = App::new_inert();
        empty.page = Page::Analyzer;
        empty.handle_key(key(KeyCode::Char('e')));
        assert!(matches!(empty.mode, InputMode::Normal));
        assert!(empty.status_is_error);
        assert!(empty.status.contains("No question to edit"));

        // With the vault focused, e is not the edit key.
        let mut focused = app_with_vault_session("A question");
        focused.handle_key(key(KeyCode::Char('e')));
        assert!(matches!(focused.mode, InputMode::Normal));
    }

    #[test]
    fn analyzer_progress_reports_elapsed_and_budget() {
        let mut app = App::new_inert();
        assert!(app.analyzer_progress().is_none());
        app.analyzer_started_at = Some(Instant::now());
        let (elapsed, budget) = app.analyzer_progress().unwrap();
        assert!(elapsed <= 1);
        assert!((30..=1_800).contains(&budget));
    }
}
