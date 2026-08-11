use crate::{
    analyzer::{ChatMessage, ChatResponse, ChatRole},
    background::Background,
    chat_history::{ChatHistoryStore, ChatSession},
    client::PipeClient,
    clipconvert::{self, ConvertEvent},
    prefs::{self, PrefsStore, UiPrefs},
    theme,
    update::{self, UpdateInfo},
};
use chrono::Utc;
use crossbeam_channel::{Receiver, Sender, bounded, select};
use pcpulse_service::{
    config::Settings,
    models::{
        Alert, DiagnosticLogResponse, DiagnosticLogStatus, HardwareMetrics, HistoryResponse,
        LiveSample, OptimizationPlan, ProcessMetric, ProcessNode, Severity, Snapshot,
        SystemMetric,
    },
};
use ratatui::{
    crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    widgets::{ListState, TableState},
};
use std::{
    collections::VecDeque,
    path::PathBuf,
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const LIVE_HISTORY_CAPACITY: usize = 180;
/// The high-res pressure-field tail: ~180 seconds of 8 Hz live samples.
const LIVE_TAIL_CAPACITY: usize = 1_440;
/// MOVERS trend rings: how many pids the client tracks — the union of the
/// snapshot's top-CPU and top-memory processes, roughly 20 + 20.
const PROCESS_TREND_PIDS: usize = 40;
/// MOVERS trend rings: points per pid — ~2 minutes at the 2-second
/// snapshot cadence.
const PROCESS_TREND_POINTS: usize = 60;
/// The MOVERS comparison window: deltas read "now vs ~2 minutes ago".
pub const MOVERS_WINDOW_MS: i64 = 120_000;
/// Movement floors: CPU deltas under this many percentage points and
/// working-set deltas under this many bytes are noise, not movers.
pub const MOVER_CPU_FLOOR: f64 = 1.5;
pub const MOVER_MEMORY_FLOOR: f64 = 32.0 * 1024.0 * 1024.0;
/// The live channel's request ceiling: never faster than 8 Hz, matching the
/// service's 125 ms collection cadence.
const LIVE_MAX_HZ: u32 = 8;
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
    Hardware,
}

impl Page {
    /// Every page in tab order. The KEYS reference deliberately sits last —
    /// it is the appendix, reached by Tab wrap-around or its printed "?"
    /// entry, and it is the only page without a digit key.
    pub const ALL: [Self; 9] = [
        Self::Overview,
        Self::Processes,
        Self::Tree,
        Self::Alerts,
        Self::Timeline,
        Self::Analyzer,
        Self::Settings,
        Self::Hardware,
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
            Self::Hardware => "Gauges",
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

/// Which findings the INCIDENTS list shows. `v` cycles: the default list
/// (active + resolved, unarchived) → archived only → back.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AlertView {
    #[default]
    Current,
    Archived,
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

/// One temperature source's recent readings for the GAUGES sparklines —
/// a client-side ring buffer fed from snapshots, bounded exactly like
/// [`App::live_history`].
#[derive(Debug, Clone)]
pub struct HardwareTrace {
    pub label: String,
    pub points: VecDeque<f64>,
}

/// One point of a per-process MOVERS trend ring: the client-side record of
/// what a pid's CPU share and working set looked like at a snapshot.
#[derive(Debug, Clone, Copy)]
pub struct ProcessTrendPoint {
    pub timestamp_ms: i64,
    pub cpu_percent: f64,
    pub working_set_bytes: u64,
}

/// A bounded per-pid ring of [`ProcessTrendPoint`]s, fed on every fresh
/// snapshot; the ledger MOVERS board reads deltas out of these.
#[derive(Debug, Clone, Default)]
pub struct ProcessTrend {
    pub name: String,
    pub points: VecDeque<ProcessTrendPoint>,
}

/// One MOVERS board entry: a process whose CPU or working set moved past
/// the floors over the recent window.
#[derive(Debug, Clone)]
pub struct Mover {
    /// The pid whose [`ProcessTrend`] ring produced this entry; the board
    /// reads the ring again to draw the row's trace.
    pub pid: u32,
    pub name: String,
    /// CPU change over the window in percentage points (signed).
    pub cpu_delta: f64,
    /// Working-set change over the window in bytes (signed).
    pub memory_delta: f64,
    pub cpu_now: f64,
    pub working_set_now: u64,
    /// True when the CPU delta is the dominant signal; false = working set.
    pub cpu_dominant: bool,
    /// The dominant signal's floor-normalized magnitude; sorts the board.
    pub weight: f64,
}

impl Mover {
    /// True for the RISING column: the dominant signal grew.
    pub fn rising(&self) -> bool {
        if self.cpu_dominant {
            self.cpu_delta > 0.0
        } else {
            self.memory_delta > 0.0
        }
    }
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
    ClientRefresh,
    ClientTimeout,
    ClientUpdates,
    ClientBackgroundVideo,
    ClientBackgroundEnabled,
    ClientBackgroundDim,
    ClientBackgroundFps,
    SampleInterval,
    Retention,
    Sustained,
    BaselineSigma,
    Cpu,
    CollectorCpu,
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
    pub const CLIENT: [Self; 9] = [
        Self::ClientTheme,
        Self::ClientEffects,
        Self::ClientRefresh,
        Self::ClientTimeout,
        Self::ClientUpdates,
        Self::ClientBackgroundVideo,
        Self::ClientBackgroundEnabled,
        Self::ClientBackgroundDim,
        Self::ClientBackgroundFps,
    ];

    /// Service-validated detector settings, saved through the pipe with `s`.
    pub const SERVICE: [Self; 19] = [
        Self::SampleInterval,
        Self::Retention,
        Self::Sustained,
        Self::BaselineSigma,
        Self::Cpu,
        Self::CollectorCpu,
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

    pub const ALL: [Self; 28] = [
        Self::ClientTheme,
        Self::ClientEffects,
        Self::ClientRefresh,
        Self::ClientTimeout,
        Self::ClientUpdates,
        Self::ClientBackgroundVideo,
        Self::ClientBackgroundEnabled,
        Self::ClientBackgroundDim,
        Self::ClientBackgroundFps,
        Self::SampleInterval,
        Self::Retention,
        Self::Sustained,
        Self::BaselineSigma,
        Self::Cpu,
        Self::CollectorCpu,
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
            Self::ClientTheme
                | Self::ClientEffects
                | Self::ClientRefresh
                | Self::ClientTimeout
                | Self::ClientUpdates
                | Self::ClientBackgroundVideo
                | Self::ClientBackgroundEnabled
                | Self::ClientBackgroundDim
                | Self::ClientBackgroundFps
        )
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::ClientTheme => "Theme profile",
            Self::ClientEffects => "Motion effects",
            Self::ClientRefresh => "Refresh rate",
            Self::ClientTimeout => "Oracle time budget",
            Self::ClientUpdates => "Update checks",
            Self::ClientBackgroundVideo => "Background video",
            Self::ClientBackgroundEnabled => "Background",
            Self::ClientBackgroundDim => "Background dim",
            Self::ClientBackgroundFps => "Background fps",
            Self::SampleInterval => "Sample interval",
            Self::Retention => "History retention",
            Self::Sustained => "Sustained samples",
            Self::BaselineSigma => "Baseline deviation",
            Self::Cpu => "Process CPU",
            Self::CollectorCpu => "Collector CPU ceiling",
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
            Self::ClientTheme
            | Self::ClientEffects
            | Self::ClientRefresh
            | Self::ClientUpdates
            | Self::ClientBackgroundVideo
            | Self::ClientBackgroundEnabled => "local",
            Self::ClientTimeout => "seconds",
            Self::ClientBackgroundDim => "%",
            Self::ClientBackgroundFps => "fps",
            Self::SampleInterval | Self::SlowLaunch => "ms",
            Self::Retention => "days",
            Self::BaselineSigma => "sigma",
            Self::Cpu => "%",
            Self::CollectorCpu => "%",
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
                "Which look this terminal uses — vitals (green patient monitor), avionics \
                 (amber cockpit display), or ledger (night-edition broadsheet). Enter switches \
                 immediately and remembers your choice."
            }
            Self::ClientEffects => {
                "Whether brief motion effects play on page changes and new findings. Enter \
                 toggles; off is the reduced-motion mode."
            }
            Self::ClientRefresh => {
                "How often this terminal redraws. Off draws only when something changes \
                 (the default); 30 or 60 fps redraws continuously and smoothly animates \
                 meters between telemetry samples. Enter cycles and remembers your choice."
            }
            Self::ClientTimeout => {
                "How many seconds one Oracle analysis may run before it is cancelled. Saved \
                 for your user and applied the next time PC Pulse starts."
            }
            Self::ClientUpdates => {
                "Whether PC Pulse asks GitHub for a newer release once per launch (at most \
                 every 20 hours). Enter toggles; off means no update-related network \
                 request is ever made."
            }
            Self::ClientBackgroundVideo => {
                "Path to a video file to play, muted and dimmed, behind every page. First use \
                 converts it once with ffmpeg (winget install ffmpeg); afterwards it costs \
                 almost nothing. Enter edits; empty turns it off."
            }
            Self::ClientBackgroundEnabled => {
                "Whether the converted background video is drawn. Enter toggles; off keeps the \
                 clip and its conversion, it just stops painting it."
            }
            Self::ClientBackgroundDim => {
                "How far the background video is darkened toward the theme, as a percent from \
                 10 to 60. Higher keeps text easy to read; lower shows more of the clip. Enter \
                 edits."
            }
            Self::ClientBackgroundFps => {
                "How many times a second the background advances, from 1 to 60. Empty or auto \
                 follows the clip's own rate; lower it to spend less on the video. Enter edits."
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
            Self::CollectorCpu => {
                "How much CPU PC Pulse's own collector may use before it flags itself. \
                 Raise on slower machines if the collector-budget finding fires without a \
                 real problem."
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
            Self::ClientTheme
            | Self::ClientEffects
            | Self::ClientRefresh
            | Self::ClientTimeout
            | Self::ClientUpdates
            | Self::ClientBackgroundVideo
            | Self::ClientBackgroundEnabled
            | Self::ClientBackgroundDim
            | Self::ClientBackgroundFps => String::new(),
            Self::SampleInterval => settings.sample_interval_ms.to_string(),
            Self::Retention => settings.retention_days.to_string(),
            Self::Sustained => settings.sustained_samples.to_string(),
            Self::BaselineSigma => settings.baseline_sigma.to_string(),
            Self::Cpu => settings.cpu_percent.to_string(),
            Self::CollectorCpu => settings.collector_cpu_percent.to_string(),
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
            Self::ClientTheme
            | Self::ClientEffects
            | Self::ClientRefresh
            | Self::ClientTimeout
            | Self::ClientUpdates
            | Self::ClientBackgroundVideo
            | Self::ClientBackgroundEnabled
            | Self::ClientBackgroundDim
            | Self::ClientBackgroundFps => {
                return Err("local client preference — edited through its own handler".into());
            }
            Self::SampleInterval => {
                settings.sample_interval_ms = parse_range(input, 1_000, 60_000)?
            }
            Self::Retention => settings.retention_days = parse_range(input, 1, 365)?,
            Self::Sustained => settings.sustained_samples = parse_range(input, 2, 120)?,
            Self::BaselineSigma => settings.baseline_sigma = parse_float(input, 1.0, 10.0)?,
            Self::Cpu => settings.cpu_percent = parse_float(input, 1.0, 100.0)?,
            Self::CollectorCpu => {
                settings.collector_cpu_percent = parse_float(input, 0.05, 10.0)?
            }
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
    /// Set (`true`) or clear (`false`) the archive flag on a finding.
    Archive {
        id: String,
        archived: bool,
    },
    Terminate(u32),
    /// One launch-time release check against GitHub; sent only when the
    /// `updateChecks` preference is on and the 20-hour cadence is due.
    CheckUpdate,
    /// Download the release's MSI and checksum manifest into the user's
    /// Downloads folder and verify the SHA-256 (the first `u` press).
    DownloadUpdate(UpdateInfo),
    /// Reconcile live polling with the effective refresh rate: `fps == 0`
    /// stops the `live` requests entirely (event-driven mode stays
    /// byte-identical to pre-live behavior); otherwise the worker polls at
    /// `min(8 Hz, fps)` between the unchanged 2-second snapshot fetches.
    ConfigureLive {
        fps: u32,
    },
    Stop,
}

#[derive(Debug)]
pub enum WorkerEvent {
    Snapshot(Result<Snapshot, String>),
    /// A high-rate system sample from the `live` pipe command. `Err` means
    /// the service does not understand the command (pre-v1.11); the worker
    /// sends it at most once per session and stops asking.
    Live(Result<LiveSample, String>),
    Alerts(Result<Vec<Alert>, String>),
    History(Result<HistoryResponse, String>),
    Tree(Result<Vec<ProcessNode>, String>),
    Diagnostics(Result<DiagnosticLogResponse, String>),
    Plans(Result<Vec<OptimizationPlan>, String>),
    CodexAuth(Result<String, String>),
    Chat(Result<ChatResponse, String>),
    Settings(Result<Settings, String>),
    Action(Result<String, String>),
    /// The launch-time release check: `Ok(Some)` = a newer release with a
    /// downloadable MSI, `Ok(None)` = up to date, `Err` = offline, rate
    /// limited, or curl missing — all failures stay silent in the UI.
    UpdateCheck(Result<Option<UpdateInfo>, String>),
    /// The verified installer path from a `DownloadUpdate` run.
    UpdateDownload(Result<PathBuf, String>),
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

/// How often the worker polls `live` for a refresh tier: `None` at 0 fps
/// (event-driven mode sends no live requests at all), else `min(8 Hz, fps)`
/// expressed as a request spacing — 125 ms for both 30 and 60 fps.
pub(crate) fn live_poll_interval(fps: u32) -> Option<Duration> {
    if fps == 0 {
        None
    } else {
        Some(Duration::from_millis(
            1_000 / u64::from(fps.min(LIVE_MAX_HZ)),
        ))
    }
}

/// Whether a `live` failure means the service predates the command (the
/// pre-v1.11 collector answers unknown commands with `invalidRequest`), as
/// opposed to a transient pipe error worth retrying.
pub(crate) fn live_unsupported_error(error: &anyhow::Error) -> bool {
    format!("{error:#}").contains("(invalidRequest)")
}

fn worker_loop(commands: Receiver<WorkerCommand>, events: Sender<WorkerEvent>) {
    let client = PipeClient;
    let mut next_snapshot = Instant::now();
    let mut analyzer: Option<(JoinHandle<()>, Arc<AtomicBool>)> = None;
    // Live polling rides the same thread between snapshot fetches; inert
    // until a ConfigureLive command arms it, sticky-off for the session once
    // the service proves it predates the command.
    let mut live_every: Option<Duration> = None;
    let mut next_live = Instant::now();
    let mut live_unsupported = false;
    loop {
        if analyzer
            .as_ref()
            .is_some_and(|(handle, _)| handle.is_finished())
            && let Some((handle, _)) = analyzer.take()
        {
            let _ = handle.join();
        }
        let mut deadline = next_snapshot;
        if live_every.is_some() && !live_unsupported {
            deadline = deadline.min(next_live);
        }
        let wait = deadline.saturating_duration_since(Instant::now());
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
                    Ok(WorkerCommand::Archive { id, archived }) => {
                        let done = if archived {
                            "Finding archived — v shows archive"
                        } else {
                            "Finding recovered"
                        };
                        let result = client.archive(id, archived).map(|_| done.into()).map_err(error_text);
                        let _ = events.send(WorkerEvent::Action(result));
                    }
                    Ok(WorkerCommand::Terminate(pid)) => {
                        let result = client.terminate(pid, true).map(|_| format!("Termination request completed for PID {pid}")).map_err(error_text);
                        let _ = events.send(WorkerEvent::Action(result));
                        next_snapshot = Instant::now();
                    }
                    Ok(WorkerCommand::CheckUpdate) => {
                        // Fire-and-forget on its own thread so a slow or
                        // stalled HTTPS exchange never delays snapshots.
                        let update_events = events.clone();
                        let _ = thread::Builder::new()
                            .name("pcpulse-update-check".into())
                            .spawn(move || {
                                let result = update::check_for_update(
                                    &update::SystemTransport,
                                    env!("CARGO_PKG_VERSION"),
                                )
                                .map_err(error_text);
                                let _ = update_events.send(WorkerEvent::UpdateCheck(result));
                            });
                    }
                    Ok(WorkerCommand::DownloadUpdate(info)) => {
                        let update_events = events.clone();
                        let _ = thread::Builder::new()
                            .name("pcpulse-update-download".into())
                            .spawn(move || {
                                let result = update::downloads_directory()
                                    .and_then(|directory| {
                                        update::download_and_verify(
                                            &update::SystemTransport,
                                            &info,
                                            &directory,
                                        )
                                    })
                                    .map_err(error_text);
                                let _ = update_events.send(WorkerEvent::UpdateDownload(result));
                            });
                    }
                    Ok(WorkerCommand::ConfigureLive { fps }) => {
                        live_every = live_poll_interval(fps);
                        next_live = Instant::now();
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
                // The unchanged 2-second full-snapshot cadence.
                if Instant::now() >= next_snapshot {
                    let _ = events.send(WorkerEvent::Snapshot(client.snapshot().map_err(error_text)));
                    next_snapshot = Instant::now() + Duration::from_secs(2);
                }
                // The lightweight live request between snapshot polls.
                if let Some(every) = live_every
                    && !live_unsupported
                    && Instant::now() >= next_live
                {
                    match client.live() {
                        Ok(sample) => {
                            let _ = events.send(WorkerEvent::Live(Ok(sample)));
                        }
                        Err(error) if live_unsupported_error(&error) => {
                            // Pre-v1.11 collector: note once, stop asking
                            // for the rest of the session.
                            live_unsupported = true;
                            let _ = events.send(WorkerEvent::Live(Err(error_text(error))));
                        }
                        // Transient pipe trouble: the snapshot path owns
                        // connection status; just try again next tick.
                        Err(_) => {}
                    }
                    next_live = Instant::now() + every;
                }
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

/// How a verified installer is launched on the second `u` press; swappable
/// so tests never spawn `msiexec.exe`.
pub(crate) type InstallerLauncher = Box<dyn Fn(&std::path::Path) -> Result<(), String>>;

/// The `u`-key update flow: strictly forward, one press per transition.
/// `Idle → Available` on discovery, `Available → Downloading` on the first
/// press, `Downloading → Verified` when the checksum matches (a failure
/// resets to `Available`), `Verified → Launched` on the second press.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateState {
    Idle,
    Available(UpdateInfo),
    Downloading(UpdateInfo),
    Verified { info: UpdateInfo, installer: PathBuf },
    Launched(UpdateInfo),
}

pub struct App {
    pub page: Page,
    pub snapshot: Option<Snapshot>,
    pub connected: bool,
    pub last_error: Option<String>,
    pub status: String,
    pub status_is_error: bool,
    pub live_history: VecDeque<SystemMetric>,
    /// The high-res pressure-field tail: system samples from the 8 Hz live
    /// channel, kept apart from the 2-second [`Self::live_history`] so
    /// mixed cadences never disturb the snapshot chart invariants. Bounded
    /// to [`LIVE_TAIL_CAPACITY`] (~180 s at 8 Hz); consulted by the chart
    /// only while smooth mode is on.
    pub live_tail: VecDeque<SystemMetric>,
    /// Sticky for the session: the service answered `live` with an
    /// unknown-command error (pre-v1.11), so smooth mode runs on 2-second
    /// snapshots exactly as v1.10.0 and no further live requests are sent.
    pub live_unsupported: bool,
    /// The last fps value handed to the worker's live poller, so refresh
    /// changes send exactly one ConfigureLive each. `None` = never sent
    /// (the worker default is off, so 0 fps needs no message).
    live_fps_sent: Option<u32>,
    /// GAUGES sparklines: one bounded trace per temperature source, fed
    /// only when a snapshot carries a fresh hardware sample.
    pub hardware_history: Vec<HardwareTrace>,
    /// The `sampled_at_ms` of the last hardware sample recorded into
    /// [`Self::hardware_history`]; the service caches hardware between
    /// 5-second probes, so most snapshots repeat the previous sample.
    hardware_history_ms: i64,
    /// MOVERS trend rings: pid → bounded (timestamp, cpu, working-set)
    /// history for the union of the snapshot's top CPU/memory processes.
    /// Purely client-side; fed by [`Self::record_process_trends`].
    pub(crate) process_trends: std::collections::HashMap<u32, ProcessTrend>,
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
    /// The INCIDENTS list filter `v` cycles; archived findings are hidden
    /// from the default view and shown alone in the archived view.
    pub alert_view: AlertView,
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
    /// The video clip painted behind the UI, once one has been loaded.
    /// `None` — the default, and what every headless test uses — means the
    /// renderer's background passes are skipped entirely.
    pub background: Option<crate::background::Background>,
    /// The renderer's memo of the video frame resampled onto the current
    /// terminal geometry. It lives here rather than inside `Background`
    /// because it is keyed on the *terminal*, not the clip: the player knows
    /// nothing of `Rect`s, and a cache the player owned would have to be
    /// invalidated by every resize from the outside anyway. Keyed on the
    /// player's generation, so replacing `background` above retires it with
    /// no bookkeeping here.
    pub background_resample: crate::ui::VideoResample,
    /// The live one-time ffmpeg conversion, while one is running. `drain_events`
    /// polls it and drops it the moment the worker reports `Done` or `Failed`,
    /// so `is_some()` is exactly "a conversion is in flight".
    pub convert_rx: Option<Receiver<ConvertEvent>>,
    /// The source path [`Self::convert_rx`] is converting. Kept beside the
    /// receiver so a repeated commit of the same path can recognize its own
    /// conversion instead of starting a rival one over the same cache file.
    converting: Option<String>,
    pub prefs_store: Option<PrefsStore>,
    /// Smooth-refresh tween state: previous displayed sample, frame clock,
    /// and the session frame governor. Inert while `refresh_fps` is 0.
    pub(crate) smooth: crate::tween::SmoothState,
    /// Set when a theme change needs `terminal.clear()` on the next loop
    /// turn; drained by `take_terminal_clear`.
    needs_terminal_clear: bool,
    /// Set when the TUNE client section toggles motion effects; drained by
    /// the main loop, which owns the `MotionSystem`.
    effects_request: Option<bool>,
    /// Clipboard sink for the Oracle `y` copy. The real path pipes UTF-16LE
    /// into `clip.exe`; tests substitute a recorder.
    pub(crate) clipboard: ClipboardSink,
    /// Where the release update flow stands; the chrome badge and the `u`
    /// key both read this.
    pub update: UpdateState,
    /// Installer launcher for the second `u` press. The real path spawns
    /// `msiexec.exe /i` detached; tests substitute a recorder.
    pub(crate) installer: InstallerLauncher,
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
            live_tail: VecDeque::new(),
            live_unsupported: false,
            live_fps_sent: None,
            hardware_history: Vec::new(),
            hardware_history_ms: 0,
            process_trends: std::collections::HashMap::new(),
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
            alert_view: AlertView::default(),
            setting_sort: SettingSort::Name,
            suspect_sort: SuspectSort::Heat,
            process_filter: String::new(),
            agents_only: false,
            timeline_hours: 3,
            mode: InputMode::Normal,
            help_overlay: None,
            client_prefs: UiPrefs::default(),
            background: None,
            background_resample: crate::ui::VideoResample::default(),
            convert_rx: None,
            converting: None,
            prefs_store: None,
            smooth: crate::tween::SmoothState::default(),
            needs_terminal_clear: false,
            effects_request: None,
            clipboard: Box::new(write_clipboard_via_clip),
            update: UpdateState::Idle,
            installer: Box::new(|msi| {
                update::launch_installer(msi).map_err(|error| format!("{error:#}"))
            }),
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
                WorkerEvent::Snapshot(Ok(mut snapshot)) => {
                    // The one shared exclusion point for archived findings on
                    // live surfaces: annunciator lamps, incident tapes, ledger
                    // notices, open-finding counts, motion cues, and the
                    // pressure map all read `snapshot.active_alerts`. The
                    // INCIDENTS page reads the separately fetched
                    // `self.alerts` archive, which keeps them reachable.
                    snapshot.active_alerts.retain(|alert| !alert.archived);
                    let reconnected = !self.connected;
                    self.connected = true;
                    self.last_error = None;
                    if reconnected {
                        self.status.clear();
                        self.status_is_error = false;
                    }
                    // Smooth refresh: capture the outgoing sample's displayed
                    // values so the new one eases in from where the screen
                    // is. Skipped entirely in event-driven mode, and when the
                    // fetched snapshot repeats the same telemetry sample.
                    if self.effective_refresh_fps() > 0
                        && let Some(outgoing) = &self.snapshot
                        && outgoing.system.timestamp_ms != snapshot.system.timestamp_ms
                    {
                        self.smooth.observe_snapshot(outgoing, Instant::now());
                    }
                    if self.live_history.back().map(|item| item.timestamp_ms)
                        != Some(snapshot.system.timestamp_ms)
                    {
                        self.live_history.push_back(snapshot.system.clone());
                        while self.live_history.len() > LIVE_HISTORY_CAPACITY {
                            self.live_history.pop_front();
                        }
                        // Same freshness guard feeds the MOVERS trend rings:
                        // a repeated telemetry sample must not double-record.
                        self.record_process_trends(
                            snapshot.system.timestamp_ms,
                            &snapshot.processes,
                        );
                    }
                    if snapshot.hardware.sampled_at_ms != self.hardware_history_ms {
                        self.hardware_history_ms = snapshot.hardware.sampled_at_ms;
                        self.record_hardware(&snapshot.hardware);
                    }
                    self.snapshot = Some(snapshot);
                    self.clamp_selection();
                }
                WorkerEvent::Snapshot(Err(error)) => {
                    self.connected = false;
                    self.last_error = Some(error);
                    // A dead collector ends the live stream too: fall back
                    // to the snapshot tween rather than holding stale live
                    // values on screen.
                    self.smooth.clear_live();
                }
                WorkerEvent::Live(Ok(sample)) => self.apply_live(sample),
                WorkerEvent::Live(Err(_)) => self.note_live_unsupported(),
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
                WorkerEvent::UpdateCheck(result) => self.finish_update_check(result),
                WorkerEvent::UpdateDownload(result) => self.finish_update_download(result),
            }
        }
        changed |= self.drain_conversion();
        changed
    }

    /// Pump the background-video conversion worker. Collected before it is
    /// handled because every outcome touches `self`, and a finished
    /// conversion (either way) drops the receiver.
    fn drain_conversion(&mut self) -> bool {
        let events: Vec<ConvertEvent> = match &self.convert_rx {
            Some(receiver) => receiver.try_iter().collect(),
            None => return false,
        };
        let mut changed = false;
        for event in events {
            changed = true;
            match event {
                ConvertEvent::Progress(percent) => {
                    self.status = format!("Converting background… {percent}%");
                    self.status_is_error = false;
                }
                ConvertEvent::Failed(message) => {
                    self.forget_conversion();
                    self.set_error(format!("Background video conversion failed: {message}"));
                }
                ConvertEvent::Done(cache) => {
                    self.forget_conversion();
                    if self.load_background(&cache) {
                        self.status = "Background ready".into();
                        self.status_is_error = false;
                    }
                }
            }
        }
        changed
    }

    /// Start (or restart) the one-time conversion of the configured video.
    /// The worker short-circuits to `Done` when the clip is already cached,
    /// so this is also the cheap "load what we have" path.
    pub fn start_background_conversion(&mut self) {
        let source = self.client_prefs.background_video.trim().to_string();
        if source.is_empty() {
            self.forget_conversion();
            return;
        }
        // A conversion already running for this exact source is left alone.
        // A second worker would find the first one's half-written cache
        // file, report `Done` against it immediately, and hand back a clip
        // that cannot be opened — while the real worker's later `Done`
        // landed on a receiver this call had already replaced.
        if self.converting.as_deref() == Some(source.as_str()) {
            return;
        }
        self.converting = Some(source.clone());
        self.convert_rx = Some(clipconvert::spawn_convert(PathBuf::from(source)));
        self.status = "Converting background…".into();
        self.status_is_error = false;
    }

    /// Let go of the conversion worker: the receiver and the source it was
    /// converting always travel together.
    fn forget_conversion(&mut self) {
        self.convert_rx = None;
        self.converting = None;
    }

    /// Open a converted clip and hand it the stored playback rate. Returns
    /// whether it loaded; a failure clears the player and speaks once
    /// through the status line rather than taking the TUI down.
    fn load_background(&mut self, cache: &std::path::Path) -> bool {
        match Background::load(cache) {
            Ok(mut background) => {
                if self.client_prefs.background_fps != 0 {
                    background.set_playback_fps(self.client_prefs.background_fps);
                }
                self.background = Some(background);
                true
            }
            Err(error) => {
                self.background = None;
                self.set_error(format!("Background video could not be played: {error:#}"));
                false
            }
        }
    }

    /// Put the configured video on screen: a clip that is already cached
    /// loads straight away, anything else is converted first. Called at
    /// startup and whenever the path changes.
    fn restore_background(&mut self) {
        let source = self.client_prefs.background_video.trim().to_string();
        if source.is_empty() {
            self.background = None;
            self.forget_conversion();
            return;
        }
        // The running conversion owns the cache file until it reports
        // `Done`: reading it now would open a half-written clip, so leave
        // the worker to finish and load from its own event.
        if self.converting.as_deref() == Some(source.as_str()) {
            return;
        }
        let cache = match clipconvert::cache_path(&PathBuf::from(source)) {
            Ok(cache) => cache,
            Err(error) => {
                self.set_error(format!("Background video unavailable: {error:#}"));
                return;
            }
        };
        // A cache that exists but no longer opens is not a dead end: the
        // converter checks it too, throws it away, and reconverts. Reporting
        // the load failure and stopping here would strand the user with a
        // background that can never come back.
        if cache.exists() && self.load_background(&cache) {
            return;
        }
        self.start_background_conversion();
    }

    /// A completed launch-time release check. The completion time is
    /// stamped and persisted whatever the outcome, so a failing endpoint
    /// is asked at most once per cadence window too. Only a genuine newer
    /// release speaks: `Ok(None)` and every failure stay silent.
    fn finish_update_check(&mut self, result: Result<Option<UpdateInfo>, String>) {
        self.client_prefs.last_update_check_ms = Utc::now().timestamp_millis();
        self.persist_client_prefs();
        if let Ok(Some(info)) = result {
            self.status = format!(
                "PC Pulse v{} is available — press u to download",
                info.version
            );
            self.status_is_error = false;
            self.update = UpdateState::Available(info);
        }
    }

    /// A completed download-and-verify run. Success arms the second `u`
    /// press; failure reports once and resets to `Available` so the flow
    /// can be retried.
    fn finish_update_download(&mut self, result: Result<PathBuf, String>) {
        let UpdateState::Downloading(info) = self.update.clone() else {
            return;
        };
        match result {
            Ok(installer) => {
                self.status = format!(
                    "v{} downloaded and checksum verified — press u again to open the installer",
                    info.version
                );
                self.status_is_error = false;
                self.update = UpdateState::Verified { info, installer };
            }
            Err(error) => {
                self.set_error(format!("Update download failed: {error}"));
                self.update = UpdateState::Available(info);
            }
        }
    }

    /// The `u` key: advance the update flow one deliberate step. Inert
    /// while no update is known; a repeat press during a download or after
    /// launch only restates where things stand (the double-press guard).
    pub(crate) fn press_update_key(&mut self) {
        match self.update.clone() {
            UpdateState::Idle => {}
            UpdateState::Available(info) => {
                let command = WorkerCommand::DownloadUpdate(info.clone());
                if self.worker.commands.try_send(command).is_ok() {
                    self.status = format!(
                        "Downloading v{} and its checksum manifest to Downloads…",
                        info.version
                    );
                    self.status_is_error = false;
                    self.update = UpdateState::Downloading(info);
                } else {
                    self.set_error("update download queue is busy".into());
                }
            }
            UpdateState::Downloading(info) => {
                self.status = format!("v{} is still downloading…", info.version);
                self.status_is_error = false;
            }
            UpdateState::Verified { info, installer } => match (self.installer)(&installer) {
                Ok(()) => {
                    self.status =
                        "Installer launched — the collector service restarts during install"
                            .into();
                    self.status_is_error = false;
                    self.update = UpdateState::Launched(info);
                }
                Err(error) => self.set_error(format!("Failed to launch the installer: {error}")),
            },
            UpdateState::Launched(_) => {
                self.status = "Installer already launched — finish the install there".into();
                self.status_is_error = false;
            }
        }
    }

    /// Ask the worker for one release check, unless the preference is off
    /// or the last check was within the 20-hour cadence window. With the
    /// preference off no update-related network request is ever made.
    pub(crate) fn request_update_check(&mut self, now_ms: i64) {
        if !self.client_prefs.update_checks {
            return;
        }
        if now_ms.saturating_sub(self.client_prefs.last_update_check_ms)
            < update::UPDATE_CHECK_INTERVAL_MS
        {
            return;
        }
        let _ = self.worker.commands.try_send(WorkerCommand::CheckUpdate);
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
            // Digits address the first eight pages only; the KEYS page has
            // no digit — Tab wraps to it, and '?' opens the quick overlay.
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
            KeyCode::Char('z') if self.page == Page::Alerts => self.archive_selected(),
            KeyCode::Char('v') if self.page == Page::Alerts => self.cycle_alert_view(),
            KeyCode::Char('i') if self.page == Page::Alerts => self.investigate_selected_finding(),
            KeyCode::Enter | KeyCode::Char('/')
                if self.page == Page::Analyzer
                    && !self.analyzer_running
                    && !self.chat_history_focused =>
            {
                self.mode = InputMode::Chat(String::new());
            }
            KeyCode::Char('r') => self.refresh_page(),
            // Global on every page, but inert until a newer release is
            // known: first press downloads + verifies, second press opens
            // the installer.
            KeyCode::Char('u') => self.press_update_key(),
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
        let title = investigation_title(&alert);
        self.select_page(Page::Analyzer);
        self.begin_new_chat();
        // Carry the full finding so the analyzer's evidence bundle contains
        // it even when it has aged out of the fresh-context window; the
        // citation contract only accepts references backed by the bundle.
        self.submit_chat_message(question, vec![format!("alert:{}", alert.id)], Some(alert));
        // The derived vault title would be the raw question ("Investigate
        // finding crashDump:ee75aad2…") — pin a human one instead.
        if let Some(session) = self
            .chat_sessions
            .iter_mut()
            .find(|session| session.conversation_id == self.conversation_id)
        {
            session.title = crate::chat_history::truncate_title(&title, 52);
            session.title_pinned = true;
            if let Err(error) = self.persist_sessions() {
                self.set_error(error);
            }
        }
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
            KeyCode::Enter if field == SettingField::ClientBackgroundVideo => {
                // Terminals hand back drag-and-dropped paths quoted; a
                // pasted path should not have to be de-quoted by hand.
                let path = typed.trim().trim_matches('"').trim().to_string();
                if path.is_empty() {
                    self.client_prefs.background_video.clear();
                    self.background = None;
                    self.forget_conversion();
                    self.mode = InputMode::Normal;
                    self.status = "Background video off · saved for your user".into();
                    self.status_is_error = false;
                    self.persist_client_prefs();
                } else if !std::path::Path::new(&path).is_file() {
                    self.set_error(format!("No video file at {path}"));
                    self.mode = InputMode::EditSetting { field, typed };
                } else {
                    self.client_prefs.background_video = path;
                    self.mode = InputMode::Normal;
                    self.persist_client_prefs();
                    self.start_background_conversion();
                }
            }
            KeyCode::Enter if field == SettingField::ClientBackgroundDim => {
                // Out-of-range dim is clamped rather than rejected: every
                // value in between is legible, so the nearest legal one is
                // what the person meant.
                match typed.trim().parse::<u32>() {
                    Ok(percent) => {
                        let dim = percent.clamp(
                            u32::from(prefs::MIN_BACKGROUND_DIM),
                            u32::from(prefs::MAX_BACKGROUND_DIM),
                        ) as u8;
                        self.client_prefs.background_dim = dim;
                        self.mode = InputMode::Normal;
                        self.status = format!("Background dim: {dim}% · saved for your user");
                        self.status_is_error = false;
                        self.persist_client_prefs();
                    }
                    Err(_) => {
                        self.set_error(format!(
                            "enter a number from {} to {}",
                            prefs::MIN_BACKGROUND_DIM,
                            prefs::MAX_BACKGROUND_DIM
                        ));
                        self.mode = InputMode::EditSetting { field, typed };
                    }
                }
            }
            KeyCode::Enter if field == SettingField::ClientBackgroundFps => {
                let input = typed.trim();
                // `0` is the stored "match the clip" sentinel, so it is the
                // one number that escapes the 1–60 clamp — typing it means
                // the same as leaving the box empty or writing `auto`.
                let requested = if input.is_empty() || input.eq_ignore_ascii_case("auto") {
                    Some(0)
                } else {
                    input.parse::<u32>().ok().map(|fps| match fps {
                        0 => 0,
                        fps => fps.clamp(prefs::MIN_BACKGROUND_FPS, prefs::MAX_BACKGROUND_FPS),
                    })
                };
                match requested {
                    Some(fps) => {
                        self.client_prefs.background_fps = fps;
                        self.mode = InputMode::Normal;
                        self.status = match fps {
                            0 => "Background fps: auto · saved for your user".to_string(),
                            fps => format!("Background fps: {fps} · saved for your user"),
                        };
                        self.status_is_error = false;
                        self.persist_client_prefs();
                        match fps {
                            // Auto has no number to hand the player: reopen
                            // the cached clip, which starts at its own
                            // capture rate with no downshift applied.
                            0 => self.restore_background(),
                            fps => {
                                if let Some(background) = &mut self.background {
                                    background.set_playback_fps(fps);
                                }
                            }
                        }
                    }
                    None => {
                        self.set_error(format!(
                            "enter a number from {} to {}, or auto",
                            prefs::MIN_BACKGROUND_FPS,
                            prefs::MAX_BACKGROUND_FPS
                        ));
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

    /// `z` on the Findings page: archive the selected finding — or, in the
    /// archived view, recover it. The flip direction comes from the finding
    /// itself, so the same key serves both views.
    pub(crate) fn archive_selected(&mut self) {
        if let Some(index) = self.alert_state.selected()
            && let Some(alert) = self.visible_alerts().get(index).copied()
        {
            let _ = self.worker.commands.try_send(WorkerCommand::Archive {
                id: alert.id.clone(),
                archived: !alert.archived,
            });
        }
    }

    /// `v` on the Findings page: cycle the list filter — default (active +
    /// resolved, unarchived) → archived only → back.
    pub(crate) fn cycle_alert_view(&mut self) {
        self.alert_view = match self.alert_view {
            AlertView::Current => AlertView::Archived,
            AlertView::Archived => AlertView::Current,
        };
        self.alert_state.select(Some(0));
        self.status = match self.alert_view {
            AlertView::Current => "Showing current findings — v shows archive".into(),
            AlertView::Archived => "Showing archived findings — z recovers".into(),
        };
        self.status_is_error = false;
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
            // The refresh row is a three-position switch: Enter cycles
            // off → 30 → 60 and persists immediately. An explicit choice
            // also lifts any session downgrade the frame governor imposed.
            SettingField::ClientRefresh => {
                let next = match prefs::normalize_refresh_fps(self.client_prefs.refresh_fps) {
                    0 => 30,
                    30 => 60,
                    _ => 0,
                };
                self.client_prefs.refresh_fps = next;
                self.smooth.reset_session();
                self.sync_live_polling();
                self.status = format!(
                    "Refresh rate: {} · saved for your user",
                    refresh_label(next)
                );
                self.status_is_error = false;
                self.persist_client_prefs();
            }
            // The update-checks row is a two-position switch like effects:
            // Enter flips it and persists immediately.
            SettingField::ClientUpdates => {
                self.client_prefs.update_checks = !self.client_prefs.update_checks;
                self.status = format!(
                    "Update checks {} · saved for your user",
                    if self.client_prefs.update_checks {
                        "enabled"
                    } else {
                        "disabled"
                    }
                );
                self.status_is_error = false;
                self.persist_client_prefs();
            }
            // The background switch is a two-position switch like effects;
            // the clip and its conversion survive being switched off.
            SettingField::ClientBackgroundEnabled => {
                self.client_prefs.background_enabled = !self.client_prefs.background_enabled;
                self.status = format!(
                    "Background video {} · saved for your user",
                    if self.client_prefs.background_enabled {
                        "shown"
                    } else {
                        "hidden"
                    }
                );
                self.status_is_error = false;
                self.persist_client_prefs();
            }
            // Both of these prefill with what the person would type, not
            // with the display value: an empty box rather than "off", and a
            // bare number rather than "auto (matches clip)".
            SettingField::ClientBackgroundVideo => {
                self.mode = InputMode::EditSetting {
                    field,
                    typed: self.client_prefs.background_video.clone(),
                };
            }
            SettingField::ClientBackgroundFps => {
                self.mode = InputMode::EditSetting {
                    field,
                    typed: match self.client_prefs.background_fps {
                        0 => String::new(),
                        fps => fps.to_string(),
                    },
                };
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
            SettingField::ClientRefresh => {
                refresh_label(prefs::normalize_refresh_fps(self.client_prefs.refresh_fps)).into()
            }
            SettingField::ClientTimeout => self.client_prefs.analyzer_timeout_secs.to_string(),
            SettingField::ClientUpdates => if self.client_prefs.update_checks {
                "on"
            } else {
                "off"
            }
            .into(),
            SettingField::ClientBackgroundVideo => {
                match self.client_prefs.background_video.trim() {
                    "" => "off".into(),
                    path => path.to_string(),
                }
            }
            SettingField::ClientBackgroundEnabled => if self.client_prefs.background_enabled {
                "on"
            } else {
                "off"
            }
            .into(),
            SettingField::ClientBackgroundDim => self.client_prefs.background_dim.to_string(),
            // An auto-downshifted player is reported as `asked → playing
            // (auto)`, so a rate the person did not choose never looks like
            // one they did.
            SettingField::ClientBackgroundFps => {
                let downshifted = self
                    .background
                    .as_ref()
                    .filter(|background| background.is_downshifted())
                    .map(Background::effective_fps);
                match (self.client_prefs.background_fps, downshifted) {
                    (0, None) => "auto (matches clip)".into(),
                    // Already an automatic rate: the arrow says it moved,
                    // a second "(auto)" would only repeat the "auto".
                    (0, Some(playing)) => format!("auto → {playing}"),
                    (asked, None) => asked.to_string(),
                    (asked, Some(playing)) => format!("{asked} → {playing} (auto)"),
                }
            }
            _ => field.value(&self.settings),
        }
    }

    /// Adopt the startup preferences (CLI flags already folded in) and the
    /// store that future choices persist through.
    pub fn adopt_client_prefs(&mut self, prefs: UiPrefs, store: Option<PrefsStore>) {
        self.client_prefs = prefs;
        self.prefs_store = store;
        // A stored 30/60 fps preference arms the worker's live poller from
        // the first frame; at 0 fps nothing is sent.
        self.sync_live_polling();
        // A configured background comes back from the cache if it is already
        // converted, and converts itself in the worker if it is not.
        self.restore_background();
        // The once-per-launch release check, gated by the preference and
        // the 20-hour cadence.
        self.request_update_check(Utc::now().timestamp_millis());
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

    // ---- Smooth refresh --------------------------------------------------

    /// The refresh rate in force right now: the stored preference clamped to
    /// a supported tier, further capped by any session downgrade the frame
    /// governor imposed. `0` = event-driven.
    pub fn effective_refresh_fps(&self) -> u32 {
        let preferred = prefs::normalize_refresh_fps(self.client_prefs.refresh_fps);
        match self.smooth.session_cap() {
            Some(cap) => preferred.min(cap),
            None => preferred,
        }
    }

    /// Stamp the frame clock. The main loop calls this immediately before
    /// every draw; render paths never consult `Instant::now` themselves.
    pub fn set_render_now(&mut self, now: Instant) {
        self.smooth.set_render_now(now);
    }

    /// Record one smooth frame's cost against its budget. On the third
    /// consecutive overrun something has to give, and the cheapest thing to
    /// give up goes first: a *shown* video background halves its playback
    /// rate, and only once it is at its 2 fps floor — or absent, or hidden,
    /// in which case it costs nothing to draw and slowing it would relieve
    /// nothing — does the session drop a refresh tier (60 → 30 → off).
    /// Either way the footer says so and `true` comes back so the loop can
    /// repaint the message.
    pub fn note_smooth_frame(&mut self, cost: Duration, budget: Duration) -> bool {
        let current = self.effective_refresh_fps();
        if current == 0 {
            return false;
        }
        if !self.smooth.note_frame(cost, budget) {
            return false;
        }
        if self.client_prefs.background_enabled
            && let Some(background) = self.background.as_mut()
            && background.downshift()
        {
            let fps = background.effective_fps();
            self.status = format!("background rate lowered to {fps} fps (frame budget)");
            self.status_is_error = false;
            return true;
        }
        let next = self.smooth.drop_tier(current);
        self.sync_live_polling();
        self.status = format!(
            "Refresh reduced to {} — frame budget exceeded",
            refresh_label(next)
        );
        self.status_is_error = false;
        true
    }

    /// Eased tween progress for the current frame; exactly `1.0` whenever
    /// smooth refresh is off, which keeps every display accessor a
    /// pass-through on the default path.
    fn tween_t(&self) -> f64 {
        if self.effective_refresh_fps() == 0 {
            1.0
        } else {
            self.smooth.t()
        }
    }

    /// The system sample the meters display this frame: the tweened channels
    /// ease from the previous sample, everything else is `target` verbatim.
    /// While the live channel is streaming (smooth mode on a v1.11+
    /// service), the tweened channels come from the live layer instead —
    /// the same surfaces, fresher targets; pass-through fields still come
    /// from the snapshot `target`.
    pub fn display_system(&self, target: &SystemMetric) -> SystemMetric {
        if self.effective_refresh_fps() > 0
            && let Some(live) = self.smooth.display_live_system()
        {
            return crate::tween::lerp_system_channels(&live, target, 0.0);
        }
        crate::tween::display_system(&self.smooth, target, self.tween_t())
    }

    /// Ingest one live sample: re-target the system tween from what the
    /// screen currently shows toward the fresh values, and extend the
    /// high-res pressure-field tail. Per-process surfaces are untouched —
    /// they stay on the 2-second snapshot cadence, data-honest.
    pub(crate) fn apply_live(&mut self, sample: LiveSample) {
        if self.effective_refresh_fps() == 0 || !sample.available || self.live_unsupported {
            return;
        }
        let Some(snapshot) = &self.snapshot else {
            return;
        };
        // Duplicate delivery of the same collection (polling can outpace
        // the service's 125 ms loop) must not restart the ease window.
        if self.live_tail.back().map(|item| item.timestamp_ms) == Some(sample.timestamp_ms) {
            return;
        }
        let raw = live_to_system(&sample, &snapshot.system);
        // Ease toward the EMA, not the raw 125 ms window; the chart tail
        // carries the same smoothed series so meters and chart agree.
        let target = smooth_live_target(self.live_tail.back(), &raw);
        let displayed = self.display_system(&snapshot.system);
        self.smooth
            .retarget_live(displayed, target.clone(), Instant::now());
        self.live_tail.push_back(target);
        while self.live_tail.len() > LIVE_TAIL_CAPACITY {
            self.live_tail.pop_front();
        }
    }

    /// The service predates the `live` command: note it once, then run
    /// smooth mode on 2-second snapshots exactly as v1.10.0 did.
    fn note_live_unsupported(&mut self) {
        if self.live_unsupported {
            return;
        }
        self.live_unsupported = true;
        self.smooth.clear_live();
        self.live_tail.clear();
        self.status = "This collector predates live telemetry — smooth mode continues on \
                       2-second snapshots"
            .into();
        self.status_is_error = false;
        self.sync_live_polling();
    }

    /// Reconcile the worker's live poller with the effective refresh rate.
    /// Sends ConfigureLive only when the target rate actually changed; at
    /// 0 fps the live layer and tail are dropped so event-driven rendering
    /// is byte-identical to a build without the live channel.
    pub(crate) fn sync_live_polling(&mut self) {
        let fps = if self.live_unsupported {
            0
        } else {
            self.effective_refresh_fps()
        };
        if self.live_fps_sent.unwrap_or(0) != fps {
            self.live_fps_sent = Some(fps);
            let _ = self
                .worker
                .commands
                .try_send(WorkerCommand::ConfigureLive { fps });
        }
        if fps == 0 {
            self.smooth.clear_live();
            self.live_tail.clear();
        }
    }

    /// The CPU share a process row displays this frame.
    pub fn display_process_cpu(&self, process: &ProcessMetric) -> f64 {
        crate::tween::display_process_channel(
            &self.smooth,
            process.pid,
            process.cpu_percent,
            |previous| previous.cpu_percent,
            self.tween_t(),
        )
    }

    /// The working-set bytes a heat computation uses this frame. Layout
    /// weights must keep using the raw snapshot value — only heat eases.
    pub fn display_process_working_set(&self, process: &ProcessMetric) -> f64 {
        crate::tween::display_process_channel(
            &self.smooth,
            process.pid,
            process.working_set_bytes as f64,
            |previous| previous.working_set_bytes,
            self.tween_t(),
        )
    }

    /// The combined read+write rate a process row displays this frame.
    pub fn display_process_io(&self, process: &ProcessMetric) -> f64 {
        crate::tween::display_process_channel(
            &self.smooth,
            process.pid,
            process.read_bytes_per_sec + process.write_bytes_per_sec,
            |previous| previous.io_bytes_per_sec,
            self.tween_t(),
        )
    }

    /// The value a hardware gauge (temperature, clock, utilization) displays
    /// this frame, keyed by the `crate::tween` gauge-key helpers.
    pub fn display_gauge(&self, key: &str, target: f64) -> f64 {
        let t = self.tween_t();
        match self.smooth.previous_gauge(key) {
            Some(previous) if t < 1.0 => crate::tween::lerp(previous, target, t),
            _ => target,
        }
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
        let alert_count = self.visible_alerts().len();
        match self.page {
            Page::Processes => move_table(&mut self.process_state, process_count, delta),
            Page::Tree => move_table(&mut self.tree_state, self.tree.len(), delta),
            Page::Alerts => move_table(&mut self.alert_state, alert_count, delta),
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
        let alert_count = self.visible_alerts().len();
        clamp_table(&mut self.process_state, process_count);
        clamp_table(&mut self.tree_state, self.tree.len());
        clamp_table(&mut self.alert_state, alert_count);
        clamp_list(&mut self.chat_session_state, self.chat_sessions.len() + 1);
        let action_count = self.plans.first().map_or(0, |plan| plan.actions.len());
        clamp_list(&mut self.plan_action_state, action_count);
    }

    fn set_error(&mut self, error: String) {
        self.status = error;
        self.status_is_error = true;
    }

    /// Feed the GAUGES sparklines: one point per temperature source per
    /// fresh hardware sample. Sources that vanish (a zone denied after a
    /// service restart, a GPU gone) drop their trace; every kept trace is
    /// bounded to [`LIVE_HISTORY_CAPACITY`] points like `live_history`.
    fn record_hardware(&mut self, hardware: &HardwareMetrics) {
        let sources: Vec<(&str, f64)> = hardware
            .thermal_zones
            .iter()
            .map(|zone| (zone.name.as_str(), zone.temperature_c))
            .chain(hardware.gpus.iter().filter_map(|gpu| {
                gpu.temperature_c
                    .map(|temperature| (gpu.name.as_str(), temperature))
            }))
            .collect();
        self.hardware_history
            .retain(|trace| sources.iter().any(|(label, _)| *label == trace.label));
        for (label, temperature) in sources {
            let trace = match self
                .hardware_history
                .iter_mut()
                .position(|trace| trace.label == label)
            {
                Some(index) => &mut self.hardware_history[index],
                None => {
                    self.hardware_history.push(HardwareTrace {
                        label: label.to_string(),
                        points: VecDeque::with_capacity(LIVE_HISTORY_CAPACITY),
                    });
                    let last = self.hardware_history.len() - 1;
                    &mut self.hardware_history[last]
                }
            };
            trace.points.push_back(temperature);
            while trace.points.len() > LIVE_HISTORY_CAPACITY {
                trace.points.pop_front();
            }
        }
    }

    /// Feed the MOVERS trend rings from one fresh snapshot: record a point
    /// for every pid in the union of the top-CPU and top-memory processes,
    /// evict pids that left the process table, and hold the tracked set to
    /// [`PROCESS_TREND_PIDS`] by dropping the stalest untracked rings.
    pub(crate) fn record_process_trends(
        &mut self,
        timestamp_ms: i64,
        processes: &[ProcessMetric],
    ) {
        let half = PROCESS_TREND_PIDS / 2;
        let mut by_cpu = processes
            .iter()
            .filter(|process| process.pid > 4)
            .collect::<Vec<_>>();
        let mut by_memory = by_cpu.clone();
        by_cpu.sort_by(|left, right| right.cpu_percent.total_cmp(&left.cpu_percent));
        by_memory.sort_by_key(|process| std::cmp::Reverse(process.working_set_bytes));
        let tracked = by_cpu
            .iter()
            .take(half)
            .chain(by_memory.iter().take(half))
            .map(|process| process.pid)
            .collect::<std::collections::HashSet<u32>>();
        // A pid gone from the table is stale — its ring would otherwise
        // report a ghost mover forever.
        self.process_trends
            .retain(|pid, _| processes.iter().any(|process| process.pid == *pid));
        for process in processes {
            if !tracked.contains(&process.pid) {
                continue;
            }
            let trend = self.process_trends.entry(process.pid).or_default();
            trend.name = process.name.clone();
            if trend.points.back().map(|point| point.timestamp_ms) == Some(timestamp_ms) {
                continue;
            }
            trend.points.push_back(ProcessTrendPoint {
                timestamp_ms,
                cpu_percent: process.cpu_percent,
                working_set_bytes: process.working_set_bytes,
            });
            while trend.points.len() > PROCESS_TREND_POINTS {
                trend.points.pop_front();
            }
        }
        // Rings that survive the retain but fell out of the union keep
        // their history (a process easing off IS the story) — until the map
        // outgrows the cap, when the stalest of them are shed first.
        if self.process_trends.len() > PROCESS_TREND_PIDS {
            let mut untracked = self
                .process_trends
                .iter()
                .filter(|(pid, _)| !tracked.contains(pid))
                .map(|(pid, trend)| {
                    (
                        *pid,
                        trend.points.back().map(|point| point.timestamp_ms).unwrap_or(0),
                    )
                })
                .collect::<Vec<_>>();
            untracked.sort_by_key(|(_, last)| *last);
            for (pid, _) in untracked
                .iter()
                .take(self.process_trends.len() - PROCESS_TREND_PIDS)
            {
                self.process_trends.remove(pid);
            }
        }
    }

    /// The MOVERS board: processes whose CPU or working set moved past the
    /// floors over [`MOVERS_WINDOW_MS`], split into (rising, easing) and
    /// sorted by floor-normalized magnitude. Quiet rings yield no entry.
    pub fn process_movers(&self) -> (Vec<Mover>, Vec<Mover>) {
        let mut rising = Vec::new();
        let mut easing = Vec::new();
        for (pid, trend) in &self.process_trends {
            let Some(latest) = trend.points.back() else {
                continue;
            };
            // The reference point: the oldest sample still inside the
            // window, so a short ring compares over what it actually has.
            let Some(reference) = trend
                .points
                .iter()
                .find(|point| point.timestamp_ms >= latest.timestamp_ms - MOVERS_WINDOW_MS)
            else {
                continue;
            };
            if reference.timestamp_ms == latest.timestamp_ms {
                continue;
            }
            let cpu_delta = latest.cpu_percent - reference.cpu_percent;
            let memory_delta =
                latest.working_set_bytes as f64 - reference.working_set_bytes as f64;
            let cpu_weight = cpu_delta.abs() / MOVER_CPU_FLOOR;
            let memory_weight = memory_delta.abs() / MOVER_MEMORY_FLOOR;
            let weight = cpu_weight.max(memory_weight);
            if weight < 1.0 {
                continue;
            }
            let mover = Mover {
                pid: *pid,
                name: trend.name.clone(),
                cpu_delta,
                memory_delta,
                cpu_now: latest.cpu_percent,
                working_set_now: latest.working_set_bytes,
                cpu_dominant: cpu_weight >= memory_weight,
                weight,
            };
            if mover.rising() {
                rising.push(mover);
            } else {
                easing.push(mover);
            }
        }
        rising.sort_by(|left, right| right.weight.total_cmp(&left.weight));
        easing.sort_by(|left, right| right.weight.total_cmp(&left.weight));
        (rising, easing)
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
        let mut alerts: Vec<&Alert> = self
            .alerts
            .iter()
            .filter(|alert| match self.alert_view {
                AlertView::Current => !alert.archived,
                AlertView::Archived => alert.archived,
            })
            .collect();
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

/// Map a live sample onto the system-metric shape the tween and chart
/// understand: the live channels land in their fields, everything else
/// (pool bytes, counts, collector self-metrics) carries over from the
/// latest snapshot sample. A zero live memory total (memory probe denied)
/// keeps the snapshot's total so percentage math never divides by zero.
/// A 125 ms PDH window is honest but spiky: instantaneous CPU whipsaws
/// between near-zero and bursts, and easing toward every twitch makes the
/// meters thrash ("cpu numbers look very crazy"). Display targets are
/// therefore an exponential moving average over the live stream — a ~500 ms
/// time constant for the twitchy channels and ~300 ms for throughput —
/// which keeps sub-second responsiveness without the seismograph needle.
const LIVE_EMA_SLOW: f64 = 0.22;
const LIVE_EMA_FAST: f64 = 0.35;

fn ema(previous: f64, sample: f64, alpha: f64) -> f64 {
    previous + (sample - previous) * alpha
}

fn smooth_live_target(previous: Option<&SystemMetric>, raw: &SystemMetric) -> SystemMetric {
    let Some(prev) = previous else {
        return raw.clone();
    };
    SystemMetric {
        cpu_percent: ema(prev.cpu_percent, raw.cpu_percent, LIVE_EMA_SLOW),
        disk_latency_ms: ema(prev.disk_latency_ms, raw.disk_latency_ms, LIVE_EMA_SLOW),
        dpc_rate: ema(prev.dpc_rate, raw.dpc_rate, LIVE_EMA_SLOW),
        interrupt_rate: ema(prev.interrupt_rate, raw.interrupt_rate, LIVE_EMA_SLOW),
        disk_read_bytes_per_sec: ema(
            prev.disk_read_bytes_per_sec,
            raw.disk_read_bytes_per_sec,
            LIVE_EMA_FAST,
        ),
        disk_write_bytes_per_sec: ema(
            prev.disk_write_bytes_per_sec,
            raw.disk_write_bytes_per_sec,
            LIVE_EMA_FAST,
        ),
        network_bytes_per_sec: ema(
            prev.network_bytes_per_sec,
            raw.network_bytes_per_sec,
            LIVE_EMA_FAST,
        ),
        ..raw.clone()
    }
}

/// A human Chat Vault title for an investigation: owner first, then a short
/// condition label, then the sharpest detail we hold (faulting module for
/// crashes) — never the raw finding id.
pub(crate) fn investigation_title(alert: &Alert) -> String {
    let owner = alert.process_name.as_deref().unwrap_or("system");
    let label = match alert.kind.as_str() {
        "crashDump" => "crash",
        "sustainedCpu" => "sustained CPU",
        "memoryGrowth" => "memory growth",
        "handleGrowth" => "handle leak",
        "threadGrowth" => "thread growth",
        "sustainedIo" => "heavy I/O",
        "diskLatency" => "disk latency",
        "unresponsive" => "hang",
        "slowLaunch" => "slow launch",
        "abandonedAgent" => "abandoned agent",
        "kernelPoolGrowth" => "kernel pool growth",
        "dpcInterrupt" => "interrupts",
        "collectorBudget" | "collectorGrowth" => "collector budget",
        _ => alert.title.as_str(),
    };
    let detail = alert
        .evidence
        .iter()
        .find(|row| row.label == "Faulting module" || row.label == "Top driver")
        .map(|row| {
            let value = row.value.split(" — ").next().unwrap_or(&row.value);
            format!(" ({value})")
        })
        .unwrap_or_default();
    format!("{owner} — {label}{detail}")
}

fn live_to_system(sample: &LiveSample, base: &SystemMetric) -> SystemMetric {
    SystemMetric {
        timestamp_ms: sample.timestamp_ms,
        cpu_percent: sample.cpu_percent,
        memory_used_bytes: sample.memory_used_bytes,
        memory_total_bytes: if sample.memory_total_bytes == 0 {
            base.memory_total_bytes
        } else {
            sample.memory_total_bytes
        },
        disk_latency_ms: sample.disk_latency_ms,
        disk_read_bytes_per_sec: sample.disk_read_bytes_per_sec,
        disk_write_bytes_per_sec: sample.disk_write_bytes_per_sec,
        network_bytes_per_sec: sample.network_bytes_per_sec,
        dpc_rate: sample.dpc_rate,
        interrupt_rate: sample.interrupt_rate,
        ..base.clone()
    }
}

/// The human label for a refresh tier, shared by the TUNE row and statuses.
pub(crate) fn refresh_label(fps: u32) -> &'static str {
    match fps {
        0 => "off",
        30 => "30 fps",
        _ => "60 fps",
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
    #[ignore = "dev harness: prices the App::drain_events snapshot-ingest path; run with --ignored --nocapture"]
    fn dev_bench_snapshot_ingest() {
        use pcpulse_service::models::Snapshot;
        const ROUNDS: usize = 500;
        let (command_tx, _command_rx) = bounded(4);
        let (event_tx, event_rx) = bounded(4);
        let mut app = App::with_worker(
            Worker {
                commands: command_tx,
                events: event_rx,
                handle: None,
            },
            false,
        );
        // A gallery-sized snapshot: 15 processes on a populated system sample.
        let mut template = Snapshot::default();
        template.system.cpu_percent = 46.0;
        template.system.memory_total_bytes = 64 * 1024 * 1024 * 1024;
        template.system.memory_used_bytes = 32 * 1024 * 1024 * 1024;
        for index in 0..15u32 {
            template.processes.push(ProcessMetric {
                timestamp_ms: 1_800_000_000_000,
                pid: 5_000 + index * 4,
                parent_pid: 1_000,
                name: format!("worker-{index}.exe"),
                executable_path: format!(r"C:\apps\worker-{index}.exe"),
                cpu_percent: 3.0 + f64::from(index),
                working_set_bytes: u64::from(index + 1) * 128 * 1024 * 1024,
                private_bytes: u64::from(index + 1) * 96 * 1024 * 1024,
                handle_count: 200 + index,
                thread_count: 20 + index,
                read_bytes_per_sec: 1024.0,
                write_bytes_per_sec: 1024.0,
                total_read_bytes: 0,
                total_write_bytes: 0,
                started_at_ms: 1_799_999_000_000,
                session_id: 1,
                responsive: true,
                has_visible_window: false,
                launch_duration_ms: None,
                is_agent_candidate: false,
            });
        }
        let mut samples = Vec::with_capacity(ROUNDS);
        for round in 0..ROUNDS {
            let mut snapshot = template.clone();
            snapshot.system.timestamp_ms = 1_800_000_000_000 + round as i64 * 2_000;
            event_tx
                .send(WorkerEvent::Snapshot(Ok(snapshot)))
                .expect("send snapshot");
            let started = Instant::now();
            assert!(app.drain_events());
            samples.push(started.elapsed().as_micros());
        }
        samples.sort_unstable();
        let mean = samples.iter().sum::<u128>() as f64 / samples.len() as f64;
        println!(
            "snapshot ingest (drain_events, 15 processes): mean {:.1} us  p95 {} us  max {} us",
            mean,
            samples[samples.len() * 95 / 100 - 1],
            samples[samples.len() - 1]
        );
    }

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
    fn key_8_routes_to_gauges_and_keys_sits_last_without_a_digit() {
        let mut app = App::new_inert();
        app.handle_key(KeyEvent::new(KeyCode::Char('8'), KeyModifiers::NONE));
        assert_eq!(app.page, Page::Hardware);
        // '9' addresses nothing: the KEYS page has no digit.
        app.handle_key(KeyEvent::new(KeyCode::Char('9'), KeyModifiers::NONE));
        assert_eq!(app.page, Page::Hardware);
        // Tab from GAUGES reaches the KEYS appendix, then wraps to Overview.
        app.handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
        assert_eq!(app.page, Page::Help);
        app.handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
        assert_eq!(app.page, Page::Overview);
        // Shift-Tab reaches KEYS from Overview.
        app.handle_key(KeyEvent::new(KeyCode::BackTab, KeyModifiers::NONE));
        assert_eq!(app.page, Page::Help);
        assert_eq!(Page::ALL.len(), 9);
        assert_eq!(Page::ALL[7], Page::Hardware);
        assert_eq!(Page::ALL[8], Page::Help);
        assert_eq!(Page::Help.title(), "Keys");
        // '?' still opens the quick overlay rather than routing pages.
        app.handle_key(KeyEvent::new(KeyCode::Char('1'), KeyModifiers::NONE));
        app.handle_key(KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE));
        assert_eq!(app.help_overlay, Some(0));
        assert_eq!(app.page, Page::Overview);
    }

    /// A ProcessMetric for the trend-ring tests: only the fields the rings
    /// read matter.
    fn trend_process(pid: u32, name: &str, cpu: f64, working_set_mb: u64) -> ProcessMetric {
        ProcessMetric {
            timestamp_ms: 0,
            pid,
            parent_pid: 1,
            name: name.into(),
            executable_path: format!(r"C:\apps\{name}"),
            cpu_percent: cpu,
            working_set_bytes: working_set_mb * 1024 * 1024,
            private_bytes: 0,
            handle_count: 10,
            thread_count: 2,
            read_bytes_per_sec: 0.0,
            write_bytes_per_sec: 0.0,
            total_read_bytes: 0,
            total_write_bytes: 0,
            started_at_ms: 0,
            session_id: 1,
            responsive: true,
            has_visible_window: false,
            launch_duration_ms: None,
            is_agent_candidate: false,
        }
    }

    #[test]
    fn process_trend_rings_stay_bounded_and_evict_departed_pids() {
        let mut app = App::new_inert();
        // 60 pids on offer, but only the top-CPU/top-memory union is
        // tracked: the cap holds at PROCESS_TREND_PIDS.
        let crowd = (0..60)
            .map(|index| {
                trend_process(
                    100 + index,
                    &format!("proc-{index}.exe"),
                    f64::from(index),
                    64 + u64::from(index),
                )
            })
            .collect::<Vec<_>>();
        for step in 0..(PROCESS_TREND_POINTS as i64 + 20) {
            app.record_process_trends(step * 2_000, &crowd);
        }
        assert!(app.process_trends.len() <= PROCESS_TREND_PIDS);
        for trend in app.process_trends.values() {
            assert!(trend.points.len() <= PROCESS_TREND_POINTS);
        }
        // A repeated timestamp must not double-record.
        let tracked_pid = *app.process_trends.keys().next().expect("tracked pid");
        let before = app.process_trends[&tracked_pid].points.len();
        app.record_process_trends((PROCESS_TREND_POINTS as i64 + 19) * 2_000, &crowd);
        assert_eq!(app.process_trends[&tracked_pid].points.len(), before);
        // A pid that leaves the process table loses its ring.
        let survivors = crowd
            .iter()
            .filter(|process| process.pid != tracked_pid)
            .cloned()
            .collect::<Vec<_>>();
        app.record_process_trends(1_000_000, &survivors);
        assert!(!app.process_trends.contains_key(&tracked_pid));
        // System pids never enter the rings.
        app.record_process_trends(1_002_000, &[trend_process(4, "System", 90.0, 900)]);
        assert!(!app.process_trends.contains_key(&4));
    }

    #[test]
    fn process_movers_split_by_direction_with_floors_and_delta_math() {
        let mut app = App::new_inert();
        let steps = 60_i64;
        for step in 0..=steps {
            let t = step as f64 / steps as f64;
            let processes = vec![
                // CPU climbs 2% → 16%: a riser, CPU-dominant.
                trend_process(10, "climber.exe", 2.0 + 14.0 * t, 100),
                // CPU falls 20% → 5%: an easer.
                trend_process(20, "cooler.exe", 20.0 - 15.0 * t, 100),
                // Working set grows 100 MB → 480 MB: a memory riser.
                trend_process(30, "bloater.exe", 1.0, 100 + (380.0 * t) as u64),
                // Flat under both floors: never a mover.
                trend_process(40, "steady.exe", 3.0 + 0.4 * t, 100),
            ];
            app.record_process_trends(step * 2_000, &processes);
        }
        let (rising, easing) = app.process_movers();
        let names = |movers: &[Mover]| {
            movers
                .iter()
                .map(|mover| mover.name.clone())
                .collect::<Vec<_>>()
        };
        assert!(names(&rising).contains(&"climber.exe".to_string()));
        assert!(names(&rising).contains(&"bloater.exe".to_string()));
        assert_eq!(names(&easing), vec!["cooler.exe".to_string()]);
        assert!(!names(&rising).contains(&"steady.exe".to_string()));
        let climber = rising
            .iter()
            .find(|mover| mover.name == "climber.exe")
            .expect("climber");
        // The window covers the last 2 minutes of the ring, i.e. cpu at
        // t=window-start vs now; the delta is positive and CPU-dominant.
        assert!(climber.cpu_dominant);
        assert!(climber.cpu_delta > MOVER_CPU_FLOOR);
        assert!((climber.cpu_now - 16.0).abs() < 1e-9);
        let bloater = rising
            .iter()
            .find(|mover| mover.name == "bloater.exe")
            .expect("bloater");
        assert!(!bloater.cpu_dominant);
        assert!(bloater.memory_delta > MOVER_MEMORY_FLOOR);
        // Rising sorts by normalized magnitude, strongest first.
        assert!(
            rising
                .windows(2)
                .all(|pair| pair[0].weight >= pair[1].weight)
        );
        // A single-point ring yields nothing (no reference to compare).
        let mut fresh = App::new_inert();
        fresh.record_process_trends(0, &[trend_process(10, "solo.exe", 50.0, 500)]);
        let (rising, easing) = fresh.process_movers();
        assert!(rising.is_empty() && easing.is_empty());
    }

    #[test]
    fn hardware_history_records_fresh_samples_bounded_per_source() {
        use pcpulse_service::models::{GpuMetrics, HardwareMetrics, ThermalZone};
        let mut app = App::new_inert();
        for step in 0..200_i64 {
            let hardware = HardwareMetrics {
                sampled_at_ms: step * 5_000,
                cpu_frequency_mhz: Some(4_000.0),
                thermal_zones: vec![ThermalZone {
                    name: "TZ00".into(),
                    temperature_c: 40.0 + step as f64 * 0.1,
                }],
                gpus: vec![GpuMetrics {
                    name: "NVIDIA GeForce RTX 4080".into(),
                    temperature_c: Some(60.0),
                    core_clock_mhz: Some(2_550.0),
                    memory_clock_mhz: Some(10_500.0),
                    utilization_percent: Some(34.0),
                }],
                available: true,
                detail: String::new(),
            };
            // Mirror the drain_events guard: a cached sample whose
            // sampled_at_ms did not advance is skipped.
            if hardware.sampled_at_ms != app.hardware_history_ms {
                app.hardware_history_ms = hardware.sampled_at_ms;
                app.record_hardware(&hardware);
            }
        }
        assert_eq!(app.hardware_history.len(), 2);
        for trace in &app.hardware_history {
            assert!(trace.points.len() <= LIVE_HISTORY_CAPACITY);
        }
        // A source that disappears drops its trace; the survivor remains.
        let survivor_only = HardwareMetrics {
            sampled_at_ms: 999 * 5_000,
            thermal_zones: vec![ThermalZone {
                name: "TZ00".into(),
                temperature_c: 55.0,
            }],
            ..HardwareMetrics::default()
        };
        app.record_hardware(&survivor_only);
        assert_eq!(app.hardware_history.len(), 1);
        assert_eq!(app.hardware_history[0].label, "TZ00");
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
            archived: false,
        }
    }

    const INVESTIGATION_TAIL: &str =
        " Explain the likely root cause, whether it is still occurring, and the safest next steps.";

    fn stub_update_info(version: &str) -> UpdateInfo {
        UpdateInfo {
            version: version.into(),
            html_url: "https://example.invalid/release".into(),
            msi_name: format!("PcPulse-{version}-x64.msi"),
            msi_url: "https://example.invalid/installer.msi".into(),
            msi_size_bytes: 2_000_000,
            sums_name: "SHA256SUMS.txt".into(),
            sums_url: "https://example.invalid/SHA256SUMS.txt".into(),
        }
    }

    #[test]
    fn update_check_is_gated_by_the_preference_and_the_20_hour_window() {
        let now = 1_800_000_000_000_i64;
        // Preference off: never touch the network, no matter how stale.
        let (mut app, commands) = app_with_captive_worker();
        app.client_prefs.update_checks = false;
        app.client_prefs.last_update_check_ms = 0;
        app.request_update_check(now);
        assert!(
            !commands
                .try_iter()
                .any(|command| matches!(command, WorkerCommand::CheckUpdate)),
            "the off switch means no CheckUpdate command"
        );
        // Checked recently: within the 20-hour window the launch is silent.
        let (mut app, commands) = app_with_captive_worker();
        app.client_prefs.last_update_check_ms =
            now - crate::update::UPDATE_CHECK_INTERVAL_MS + 60_000;
        app.request_update_check(now);
        assert!(
            !commands
                .try_iter()
                .any(|command| matches!(command, WorkerCommand::CheckUpdate)),
            "a fresh check timestamp skips the network"
        );
        // Stale (or never checked): exactly one command goes out.
        let (mut app, commands) = app_with_captive_worker();
        app.client_prefs.last_update_check_ms = now - crate::update::UPDATE_CHECK_INTERVAL_MS;
        app.request_update_check(now);
        assert_eq!(
            commands
                .try_iter()
                .filter(|command| matches!(command, WorkerCommand::CheckUpdate))
                .count(),
            1
        );
    }

    #[test]
    fn adopting_prefs_with_checks_off_sends_no_update_command() {
        let (mut app, commands) = app_with_captive_worker();
        app.adopt_client_prefs(
            UiPrefs {
                update_checks: false,
                ..UiPrefs::default()
            },
            None,
        );
        assert!(
            !commands
                .try_iter()
                .any(|command| matches!(command, WorkerCommand::CheckUpdate)),
        );
        // The default preferences (on, never checked) do ask once.
        let (mut app, commands) = app_with_captive_worker();
        app.adopt_client_prefs(UiPrefs::default(), None);
        assert!(
            commands
                .try_iter()
                .any(|command| matches!(command, WorkerCommand::CheckUpdate)),
        );
    }

    #[test]
    fn update_discovery_stamps_the_check_time_and_announces_once() {
        let (store, path) = scratch_prefs_store("update-stamp");
        let (mut app, _commands) = app_with_captive_worker();
        app.client_prefs = UiPrefs::default();
        app.prefs_store = Some(store.clone());
        app.finish_update_check(Ok(Some(stub_update_info("1.16.0"))));
        assert_eq!(
            app.update,
            UpdateState::Available(stub_update_info("1.16.0"))
        );
        assert_eq!(
            app.status,
            "PC Pulse v1.16.0 is available — press u to download"
        );
        assert!(!app.status_is_error);
        assert!(
            store.load().last_update_check_ms > 0,
            "the completed check is stamped and persisted"
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn up_to_date_and_failed_checks_stay_silent_but_still_stamp() {
        for result in [Ok(None), Err("curl.exe was not found".to_string())] {
            let (store, path) = scratch_prefs_store("update-silent");
            let (mut app, _commands) = app_with_captive_worker();
            app.prefs_store = Some(store.clone());
            app.status.clear();
            app.finish_update_check(result);
            assert_eq!(app.update, UpdateState::Idle);
            assert!(app.status.is_empty(), "no status noise: {}", app.status);
            assert!(!app.status_is_error, "never a status error");
            assert!(store.load().last_update_check_ms > 0);
            let _ = std::fs::remove_file(path);
        }
    }

    #[test]
    fn the_update_key_walks_the_state_machine_and_guards_double_presses() {
        let (mut app, commands) = app_with_captive_worker();
        let launched = std::rc::Rc::new(std::cell::RefCell::new(Vec::<PathBuf>::new()));
        let recorder = std::rc::Rc::clone(&launched);
        app.installer = Box::new(move |msi| {
            recorder.borrow_mut().push(msi.to_path_buf());
            Ok(())
        });

        // Idle: `u` is inert — no state change, no command, no status.
        app.handle_key(key(KeyCode::Char('u')));
        assert_eq!(app.update, UpdateState::Idle);
        assert_eq!(commands.try_iter().count(), 0);

        // Available → first press downloads.
        let info = stub_update_info("1.16.0");
        app.update = UpdateState::Available(info.clone());
        app.handle_key(key(KeyCode::Char('u')));
        assert_eq!(app.update, UpdateState::Downloading(info.clone()));
        assert!(app.status.contains("Downloading v1.16.0"));
        let sent: Vec<WorkerCommand> = commands.try_iter().collect();
        assert_eq!(
            sent.iter()
                .filter(|command| matches!(command, WorkerCommand::DownloadUpdate(sent_info) if *sent_info == info))
                .count(),
            1
        );

        // Downloading: a second press must not enqueue another download.
        app.handle_key(key(KeyCode::Char('u')));
        assert_eq!(app.update, UpdateState::Downloading(info.clone()));
        assert!(app.status.contains("still downloading"));
        assert_eq!(commands.try_iter().count(), 0, "double-press guard");

        // Verified → second press launches the installer exactly once.
        let installer = PathBuf::from(r"C:\Users\x\Downloads\PcPulse-1.16.0-x64.msi");
        app.finish_update_download(Ok(installer.clone()));
        assert_eq!(
            app.update,
            UpdateState::Verified {
                info: info.clone(),
                installer: installer.clone()
            }
        );
        assert!(app.status.contains("checksum verified"));
        assert!(app.status.contains("press u again"));
        app.handle_key(key(KeyCode::Char('u')));
        assert_eq!(app.update, UpdateState::Launched(info.clone()));
        assert!(app.status.contains("Installer launched"));
        assert!(app.status.contains("collector service restarts"));
        assert_eq!(launched.borrow().as_slice(), [installer]);

        // Launched: further presses only restate, never relaunch.
        app.handle_key(key(KeyCode::Char('u')));
        assert_eq!(app.update, UpdateState::Launched(info));
        assert_eq!(launched.borrow().len(), 1);
    }

    #[test]
    fn a_failed_download_resets_to_available_for_retry() {
        let (mut app, commands) = app_with_captive_worker();
        let info = stub_update_info("1.16.0");
        app.update = UpdateState::Downloading(info.clone());
        app.finish_update_download(Err("checksum mismatch for the installer".into()));
        assert_eq!(app.update, UpdateState::Available(info.clone()));
        assert!(app.status_is_error);
        assert!(app.status.contains("checksum mismatch"));
        // The flow is immediately retryable.
        app.handle_key(key(KeyCode::Char('u')));
        assert_eq!(app.update, UpdateState::Downloading(info));
        assert!(
            commands
                .try_iter()
                .any(|command| matches!(command, WorkerCommand::DownloadUpdate(_))),
        );
    }

    #[test]
    fn a_stray_download_event_without_a_download_in_flight_is_ignored() {
        let (mut app, _commands) = app_with_captive_worker();
        app.finish_update_download(Ok(PathBuf::from(r"C:\stray.msi")));
        assert_eq!(app.update, UpdateState::Idle);
        app.update = UpdateState::Available(stub_update_info("1.16.0"));
        app.finish_update_download(Err("late failure".into()));
        assert_eq!(
            app.update,
            UpdateState::Available(stub_update_info("1.16.0")),
            "only a Downloading state consumes download results"
        );
    }

    #[test]
    fn enter_on_the_update_checks_row_toggles_and_persists() {
        let (store, path) = scratch_prefs_store("update-toggle");
        let mut app = App::new_inert();
        app.adopt_client_prefs(UiPrefs::default(), Some(store.clone()));
        app.page = Page::Settings;
        app.setting_state.select(Some(4));
        assert_eq!(app.setting_value(SettingField::ClientUpdates), "on");

        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));

        assert!(!app.client_prefs.update_checks);
        assert_eq!(app.setting_value(SettingField::ClientUpdates), "off");
        assert!(app.status.contains("Update checks disabled"));
        assert!(matches!(app.mode, InputMode::Normal), "no typed edit opens");
        assert!(!store.load().update_checks);

        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(store.load().update_checks);
        assert!(app.status.contains("Update checks enabled"));
        let _ = std::fs::remove_file(path);
    }

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
    fn investigations_pin_a_human_vault_title() {
        let mut alert = investigation_alert();
        alert.kind = "crashDump".into();
        alert.process_name = Some("XboxPcApp.exe".into());
        alert.evidence.push(pcpulse_service::models::Evidence {
            label: "Faulting module".into(),
            value: "hermes.dll".into(),
        });
        assert_eq!(
            investigation_title(&alert),
            "XboxPcApp.exe — crash (hermes.dll)"
        );
        alert.kind = "dpcInterrupt".into();
        alert.process_name = None;
        alert.evidence.push(pcpulse_service::models::Evidence {
            label: "Top driver".into(),
            value: "nvlddmkm.sys — NVIDIA Windows Kernel Mode Driver".into(),
        });
        assert!(investigation_title(&alert).starts_with("system — interrupts (hermes.dll)"));

        // End to end: the vault session carries the pinned human title, not
        // the raw question.
        let (mut app, _commands) = app_with_captive_worker();
        app.page = Page::Alerts;
        app.alerts = vec![investigation_alert()];
        app.register_finding_click(0);
        app.register_finding_click(0);
        let session = app
            .chat_sessions
            .iter()
            .find(|session| session.conversation_id == app.conversation_id)
            .expect("investigation session persisted");
        assert!(session.title_pinned);
        assert_eq!(session.title, "chrome.exe — memory growth");
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
    fn z_archives_the_selected_finding_and_the_default_list_hides_it() {
        let (mut app, commands) = app_with_captive_worker();
        app.page = Page::Alerts;
        app.alerts = vec![investigation_alert()];
        app.alert_state.select(Some(0));

        app.handle_key(KeyEvent::new(KeyCode::Char('z'), KeyModifiers::NONE));

        let sent: Vec<WorkerCommand> = commands.try_iter().collect();
        assert!(
            sent.iter().any(|command| matches!(
                command,
                WorkerCommand::Archive { id, archived: true } if id == "finding-77"
            )),
            "z must send an archive command for the selected finding"
        );

        // The refreshed fetch returns the finding flagged; the default view
        // must hide it while the archive view keeps it reachable.
        app.alerts[0].archived = true;
        assert!(app.visible_alerts().is_empty());
        assert_eq!(app.alert_view, AlertView::Current);
        app.cycle_alert_view();
        assert_eq!(app.visible_alerts().len(), 1);
    }

    #[test]
    fn v_cycles_the_view_and_z_recovers_archived_findings() {
        let (mut app, commands) = app_with_captive_worker();
        app.page = Page::Alerts;
        let mut archived = investigation_alert();
        archived.id = "finding-old".into();
        archived.archived = true;
        app.alerts = vec![investigation_alert(), archived];
        app.alert_state.select(Some(0));

        // Default view: only the unarchived finding.
        assert_eq!(
            app.visible_alerts()
                .iter()
                .map(|alert| alert.id.as_str())
                .collect::<Vec<_>>(),
            vec!["finding-77"]
        );

        app.handle_key(KeyEvent::new(KeyCode::Char('v'), KeyModifiers::NONE));
        assert_eq!(app.alert_view, AlertView::Archived);
        assert!(app.status.contains("archived"));
        assert_eq!(
            app.visible_alerts()
                .iter()
                .map(|alert| alert.id.as_str())
                .collect::<Vec<_>>(),
            vec!["finding-old"]
        );

        // z in the archived view recovers (archived: false).
        app.handle_key(KeyEvent::new(KeyCode::Char('z'), KeyModifiers::NONE));
        let sent: Vec<WorkerCommand> = commands.try_iter().collect();
        assert!(
            sent.iter().any(|command| matches!(
                command,
                WorkerCommand::Archive { id, archived: false } if id == "finding-old"
            )),
            "z in the archive must send a recover command"
        );

        // The cycle closes: v returns to the default view.
        app.handle_key(KeyEvent::new(KeyCode::Char('v'), KeyModifiers::NONE));
        assert_eq!(app.alert_view, AlertView::Current);
    }

    #[test]
    fn archived_findings_never_reach_live_surfaces() {
        use pcpulse_service::models::Snapshot;
        let (commands, _command_rx) = bounded(8);
        let (event_tx, events) = bounded(8);
        let mut app = App::with_worker(
            Worker {
                commands,
                events,
                handle: None,
            },
            false,
        );
        let mut filed = investigation_alert();
        filed.id = "finding-filed".into();
        filed.archived = true;
        let snapshot = Snapshot {
            active_alerts: vec![investigation_alert(), filed],
            ..Snapshot::default()
        };
        event_tx.send(WorkerEvent::Snapshot(Ok(snapshot))).unwrap();
        assert!(app.drain_events());
        // The single ingestion filter feeds every live surface: lamps,
        // tapes, notices, counts, and motion cues all read active_alerts.
        let active = &app.snapshot.as_ref().unwrap().active_alerts;
        assert_eq!(
            active.iter().map(|alert| alert.id.as_str()).collect::<Vec<_>>(),
            vec!["finding-77"]
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
            assert_eq!(
                &fields[..SettingField::CLIENT.len()],
                &SettingField::CLIENT,
                "{sort:?}"
            );
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

        // The row is a three-position switch: avionics -> ledger -> vitals.
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(theme::active().id, theme::ThemeId::Ledger);
        assert_eq!(app.setting_value(SettingField::ClientTheme), "ledger");
        assert_eq!(store.load().theme, theme::ThemeId::Ledger);
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(theme::active().id, theme::ThemeId::Vitals);
        assert_eq!(store.load().theme, theme::ThemeId::Vitals);
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
        app.setting_state.select(Some(3));

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

    #[test]
    fn enter_on_the_refresh_row_cycles_off_30_60_and_persists() {
        let (store, path) = scratch_prefs_store("refresh-cycle");
        let mut app = App::new_inert();
        app.adopt_client_prefs(UiPrefs::default(), Some(store.clone()));
        app.page = Page::Settings;
        app.setting_state.select(Some(2));
        assert_eq!(app.setting_value(SettingField::ClientRefresh), "off");

        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(app.client_prefs.refresh_fps, 30);
        assert_eq!(app.setting_value(SettingField::ClientRefresh), "30 fps");
        assert_eq!(app.effective_refresh_fps(), 30);
        assert_eq!(store.load().refresh_fps, 30);
        assert!(app.status.contains("Refresh rate: 30 fps"));
        assert!(matches!(app.mode, InputMode::Normal), "no typed edit opens");

        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(app.client_prefs.refresh_fps, 60);
        assert_eq!(app.setting_value(SettingField::ClientRefresh), "60 fps");
        assert_eq!(store.load().refresh_fps, 60);

        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(app.client_prefs.refresh_fps, 0);
        assert_eq!(app.setting_value(SettingField::ClientRefresh), "off");
        assert_eq!(app.effective_refresh_fps(), 0);
        assert_eq!(store.load().refresh_fps, 0);
        let _ = std::fs::remove_file(path);
    }

    /// A scratch source video, plus any `.pulseclip` planted for it, that
    /// deletes itself when the test ends. Under `cfg(test)` the cache root
    /// is a `%TEMP%` directory rather than `%LOCALAPPDATA%\PcPulse\
    /// backgrounds` (see `clipconvert::backgrounds_dir`), so a test run
    /// never touches the real profile — and with this guard it leaves
    /// nothing behind in `%TEMP%` either.
    struct Scratch {
        source: std::path::PathBuf,
        cache: Option<std::path::PathBuf>,
    }

    impl std::ops::Deref for Scratch {
        type Target = std::path::Path;

        fn deref(&self) -> &std::path::Path {
            &self.source
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.source);
            if let Some(cache) = &self.cache {
                let _ = std::fs::remove_file(cache);
                // Best effort, and only ever succeeds for the last test out:
                // an empty scratch cache root is worth removing too.
                if let Some(parent) = cache.parent() {
                    let _ = std::fs::remove_dir(parent);
                }
            }
        }
    }

    /// A scratch file standing in for a source video. Nothing is cached for
    /// it, so a conversion started against it stays in flight.
    fn scratch_source(tag: &str) -> Scratch {
        let source = std::env::temp_dir().join(format!(
            "pcpulse-app-bg-{tag}-{}-{}.mp4",
            std::process::id(),
            Utc::now().timestamp_millis()
        ));
        std::fs::write(&source, b"stands in for a video file").unwrap();
        Scratch {
            source,
            cache: None,
        }
    }

    /// A real `.pulseclip` planted at the cache path of a scratch source
    /// file. This is what lets the background rows be tested end to end
    /// without ffmpeg: `spawn_convert` short-circuits straight to `Done`
    /// when the cache for a source already exists and opens.
    fn scratch_background(tag: &str, capture_fps: f32) -> Scratch {
        let mut scratch = scratch_source(tag);
        let cache = crate::clipconvert::cache_path(&scratch).unwrap();
        let mut writer = crate::pulseclip::ClipWriter::create(&cache, 4, 2, capture_fps).unwrap();
        for frame in 0..4u32 {
            writer.push_frame(&[(frame * 50) as u8; 4 * 2 * 3]).unwrap();
        }
        writer.finish().unwrap();
        scratch.cache = Some(cache);
        scratch
    }

    /// Pump `drain_events` until the conversion worker's message lands.
    fn wait_for_background(app: &mut App) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while app.convert_rx.is_some() && Instant::now() < deadline {
            app.drain_events();
            thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn background_rows_are_client_rows_and_stay_pinned() {
        let app = App::new_inert();
        let fields = app.visible_setting_fields();
        for field in [
            SettingField::ClientBackgroundVideo,
            SettingField::ClientBackgroundEnabled,
            SettingField::ClientBackgroundDim,
            SettingField::ClientBackgroundFps,
        ] {
            assert!(field.is_client(), "{field:?}");
            assert!(SettingField::CLIENT.contains(&field), "{field:?}");
            assert!(SettingField::ALL.contains(&field), "{field:?}");
            assert!(!field.label().is_empty() && !field.description().is_empty());
            let position = fields.iter().position(|row| *row == field).unwrap();
            assert!(position < SettingField::CLIENT.len(), "{field:?} unpinned");
        }
        assert_eq!(SettingField::CLIENT.len(), 9);
        assert_eq!(SettingField::ALL.len(), 28);
    }

    #[test]
    fn enter_on_the_background_row_toggles_and_persists() {
        let (store, path) = scratch_prefs_store("background-enabled");
        let mut app = App::new_inert();
        app.adopt_client_prefs(UiPrefs::default(), Some(store.clone()));
        app.page = Page::Settings;
        app.setting_state.select(Some(6));
        assert!(app.client_prefs.background_enabled);
        assert_eq!(
            app.setting_value(SettingField::ClientBackgroundEnabled),
            "on"
        );

        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));

        assert!(!app.client_prefs.background_enabled);
        assert_eq!(
            app.setting_value(SettingField::ClientBackgroundEnabled),
            "off"
        );
        assert!(!store.load().background_enabled);
        assert!(matches!(app.mode, InputMode::Normal), "no typed edit opens");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn committing_a_dim_edit_clamps_and_persists() {
        let (store, path) = scratch_prefs_store("background-dim");
        let mut app = App::new_inert();
        app.adopt_client_prefs(UiPrefs::default(), Some(store.clone()));

        app.mode = InputMode::EditSetting {
            field: SettingField::ClientBackgroundDim,
            typed: "85".into(),
        };
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(app.client_prefs.background_dim, 60);
        assert_eq!(store.load().background_dim, 60);
        assert!(matches!(app.mode, InputMode::Normal));

        app.mode = InputMode::EditSetting {
            field: SettingField::ClientBackgroundDim,
            typed: "5".into(),
        };
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(app.client_prefs.background_dim, 10);
        assert_eq!(store.load().background_dim, 10);
        assert_eq!(app.setting_value(SettingField::ClientBackgroundDim), "10");

        // Nonsense re-arms the edit with an error instead of committing.
        app.mode = InputMode::EditSetting {
            field: SettingField::ClientBackgroundDim,
            typed: "dark".into(),
        };
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(app.status_is_error);
        assert!(matches!(app.mode, InputMode::EditSetting { .. }));
        assert_eq!(app.client_prefs.background_dim, 10);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_cached_background_loads_at_startup_with_the_stored_fps() {
        let source = scratch_background("startup", 20.0);
        let mut app = App::new_inert();
        app.adopt_client_prefs(
            UiPrefs {
                background_video: source.to_string_lossy().into_owned(),
                background_fps: 12,
                ..UiPrefs::default()
            },
            None,
        );

        let background = app.background.as_ref().expect("cached clip loads directly");
        assert_eq!(background.effective_fps(), 12);
        assert!(
            app.convert_rx.is_none(),
            "a cached clip converts nothing: {}",
            app.status
        );
    }

    #[test]
    fn fps_row_reports_the_auto_downshift_and_commits_a_fixed_rate() {
        let source = scratch_background("fps", 20.0);
        let mut app = App::new_inert();
        app.adopt_client_prefs(
            UiPrefs {
                background_video: source.to_string_lossy().into_owned(),
                ..UiPrefs::default()
            },
            None,
        );
        assert_eq!(
            app.setting_value(SettingField::ClientBackgroundFps),
            "auto (matches clip)"
        );

        // An automatic rate lowered automatically needs no second "(auto)".
        app.background.as_mut().unwrap().downshift();
        assert_eq!(
            app.setting_value(SettingField::ClientBackgroundFps),
            "auto → 10"
        );

        // An explicit rate clamps, reaches the player, and clears the auto state.
        app.mode = InputMode::EditSetting {
            field: SettingField::ClientBackgroundFps,
            typed: "90".into(),
        };
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(app.client_prefs.background_fps, 60);
        assert_eq!(app.background.as_ref().unwrap().effective_fps(), 60);
        assert!(!app.background.as_ref().unwrap().is_downshifted());
        assert_eq!(app.setting_value(SettingField::ClientBackgroundFps), "60");

        // A chosen rate the guardrail then lowers reads as `asked → playing (auto)`.
        app.background.as_mut().unwrap().downshift();
        assert_eq!(
            app.setting_value(SettingField::ClientBackgroundFps),
            "60 → 30 (auto)"
        );

        // Back to auto: the player returns to the clip's own capture rate.
        // A typed `0` is the sentinel, not a rate to clamp up to 1.
        app.mode = InputMode::EditSetting {
            field: SettingField::ClientBackgroundFps,
            typed: "0".into(),
        };
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(app.client_prefs.background_fps, 0);
        assert_eq!(app.background.as_ref().unwrap().effective_fps(), 20);
        assert!(!app.background.as_ref().unwrap().is_downshifted());
        assert_eq!(
            app.setting_value(SettingField::ClientBackgroundFps),
            "auto (matches clip)"
        );

        // `auto` in words reaches the same sentinel.
        app.client_prefs.background_fps = 30;
        app.mode = InputMode::EditSetting {
            field: SettingField::ClientBackgroundFps,
            typed: "auto".into(),
        };
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(app.client_prefs.background_fps, 0);
    }

    #[test]
    fn committing_a_background_path_converts_it_then_an_empty_one_turns_it_off() {
        let (store, prefs_path) = scratch_prefs_store("background-video");
        let source = scratch_background("commit", 20.0);
        let mut app = App::new_inert();
        app.adopt_client_prefs(UiPrefs::default(), Some(store.clone()));
        app.page = Page::Settings;
        app.setting_state.select(Some(5));

        // Enter opens a typed edit prefilled with the stored path (none yet).
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(matches!(
            app.mode,
            InputMode::EditSetting { field: SettingField::ClientBackgroundVideo, ref typed }
                if typed.is_empty()
        ));

        // A pasted, quoted Windows path commits and starts the conversion.
        app.mode = InputMode::EditSetting {
            field: SettingField::ClientBackgroundVideo,
            typed: format!("\"{}\"", source.display()),
        };
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(app.client_prefs.background_video, source.to_string_lossy());
        assert_eq!(store.load().background_video, source.to_string_lossy());
        assert!(app.convert_rx.is_some(), "conversion started");
        assert!(matches!(app.mode, InputMode::Normal));

        wait_for_background(&mut app);
        assert!(app.background.is_some(), "status was {}", app.status);
        assert!(app.status.contains("Background ready"), "{}", app.status);
        assert!(!app.status_is_error);
        assert_eq!(
            app.setting_value(SettingField::ClientBackgroundVideo),
            source.to_string_lossy()
        );

        // A path that names nothing re-arms the edit rather than committing.
        app.mode = InputMode::EditSetting {
            field: SettingField::ClientBackgroundVideo,
            typed: r"C:\nope\missing.mp4".into(),
        };
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(app.status_is_error);
        assert!(matches!(app.mode, InputMode::EditSetting { .. }));
        assert_eq!(app.client_prefs.background_video, source.to_string_lossy());

        // An empty commit turns the background off and drops the player.
        app.mode = InputMode::EditSetting {
            field: SettingField::ClientBackgroundVideo,
            typed: String::new(),
        };
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(app.client_prefs.background_video.is_empty());
        assert!(store.load().background_video.is_empty());
        assert!(app.background.is_none());
        assert_eq!(
            app.setting_value(SettingField::ClientBackgroundVideo),
            "off"
        );
        let _ = std::fs::remove_file(prefs_path);
    }

    #[test]
    fn a_re_commit_of_the_same_path_leaves_the_running_conversion_alone() {
        let source = scratch_source("in-flight");
        let path = source.to_string_lossy().into_owned();
        let mut app = App::new_inert();
        app.client_prefs.background_video = path.clone();
        app.start_background_conversion();
        let first = app.convert_rx.clone().expect("a conversion is in flight");

        // Committing the same path again must not spawn a rival worker: it
        // would find the first one's half-written cache file, call it done,
        // and leave the real worker reporting into a discarded receiver.
        app.mode = InputMode::EditSetting {
            field: SettingField::ClientBackgroundVideo,
            typed: path.clone(),
        };
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(
            app.convert_rx
                .as_ref()
                .expect("the conversion is still running")
                .same_channel(&first),
            "the receiver was replaced"
        );
        assert!(app.background.is_none());

        // A genuinely different path does start its own conversion.
        let other = scratch_source("in-flight-other");
        app.mode = InputMode::EditSetting {
            field: SettingField::ClientBackgroundVideo,
            typed: other.to_string_lossy().into_owned(),
        };
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(!app.convert_rx.as_ref().unwrap().same_channel(&first));
    }

    #[test]
    fn auto_fps_mid_conversion_never_opens_the_half_written_cache() {
        let source = scratch_source("in-flight-cache");
        let cache = crate::clipconvert::cache_path(&source).unwrap();
        // Exactly the state the worker leaves while it streams frames: the
        // cache file exists but is not a readable clip yet. Held here with
        // a channel of our own so no real worker can race the assertion.
        std::fs::write(&cache, b"").unwrap();
        let (_convert_tx, convert_rx) = bounded::<ConvertEvent>(1);
        let mut app = App::new_inert();
        app.client_prefs.background_video = source.to_string_lossy().into_owned();
        app.converting = Some(source.to_string_lossy().into_owned());
        app.convert_rx = Some(convert_rx);

        app.mode = InputMode::EditSetting {
            field: SettingField::ClientBackgroundFps,
            typed: "auto".into(),
        };
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));

        assert!(app.background.is_none(), "status was {}", app.status);
        assert!(!app.status_is_error, "status was {}", app.status);
        assert!(
            app.convert_rx.is_some(),
            "the conversion still owns the file"
        );
        let _ = std::fs::remove_file(cache);
    }

    #[test]
    fn a_corrupt_cache_file_reconverts_instead_of_stranding_the_background() {
        let source = scratch_source("corrupt-cache");
        let cache = crate::clipconvert::cache_path(&source).unwrap();
        // What an interrupted conversion used to leave behind: a file at the
        // final cache path that no reader can open. Restoring used to report
        // a load error and stop, and every later commit of the same path
        // short-circuited to the same broken file — unrecoverable from the
        // UI. It has to fall through to a fresh conversion instead.
        std::fs::write(&cache, b"not a clip").unwrap();
        let mut app = App::new_inert();
        app.client_prefs.background_video = source.to_string_lossy().into_owned();

        app.restore_background();

        assert!(app.background.is_none());
        assert!(
            app.convert_rx.is_some(),
            "no reconversion started: {}",
            app.status
        );
        assert!(!app.status_is_error, "status was {}", app.status);

        // Let the worker run out (there is no real video behind the path, so
        // it fails) and confirm it threw the unreadable file away.
        wait_for_background(&mut app);
        assert!(!cache.exists(), "the corrupt cache file survived");
    }

    #[test]
    fn a_failed_conversion_reports_an_error_instead_of_crashing() {
        let mut app = App::new_inert();
        app.client_prefs.background_video = r"C:\nope\missing.mp4".into();
        app.start_background_conversion();
        wait_for_background(&mut app);
        assert!(app.status_is_error, "status was {}", app.status);
        assert!(app.background.is_none());
        assert!(app.convert_rx.is_none(), "the receiver is dropped");
    }

    /// An app whose cached clip is loaded and whose refresh preference is
    /// the top tier, so the frame governor has somewhere to fall.
    fn app_with_background_and_smooth(tag: &str) -> (App, Scratch) {
        let source = scratch_background(tag, 60.0);
        let mut app = App::new_inert();
        app.adopt_client_prefs(
            UiPrefs {
                background_video: source.to_string_lossy().into_owned(),
                refresh_fps: 60,
                ..UiPrefs::default()
            },
            None,
        );
        assert!(app.background.is_some(), "status was {}", app.status);
        (app, source)
    }

    #[test]
    fn budget_overruns_downshift_the_background_before_the_ui_tier() {
        let (mut app, _source) = app_with_background_and_smooth("guardrail");
        assert_eq!(app.effective_refresh_fps(), 60);
        assert_eq!(app.background.as_ref().unwrap().effective_fps(), 60);

        let over = Duration::from_millis(50);
        let budget = Duration::from_millis(16);
        // Three consecutive overruns is exactly one governor trip; the
        // counter rearms itself on firing.
        for _ in 0..3 {
            app.note_smooth_frame(over, budget);
        }
        assert_eq!(
            app.effective_refresh_fps(),
            60,
            "UI tier must survive the first trip"
        );
        assert_eq!(app.background.as_ref().unwrap().effective_fps(), 30);
        assert_eq!(
            app.status,
            "background rate lowered to 30 fps (frame budget)"
        );
        assert!(!app.status_is_error);

        // Drive the background to its floor; the UI tier is untouched the
        // whole way down.
        while app.background.as_ref().unwrap().effective_fps() > 2 {
            for _ in 0..3 {
                app.note_smooth_frame(over, budget);
            }
            assert_eq!(app.effective_refresh_fps(), 60);
        }

        // At the floor the background has nothing left to give, so the next
        // trip drops the UI tier with the existing message.
        for _ in 0..3 {
            app.note_smooth_frame(over, budget);
        }
        assert_eq!(app.effective_refresh_fps(), 30);
        assert_eq!(app.background.as_ref().unwrap().effective_fps(), 2);
        assert_eq!(
            app.status,
            "Refresh reduced to 30 fps — frame budget exceeded"
        );
    }

    #[test]
    fn a_hidden_background_does_not_absorb_the_budget_trip() {
        let (mut app, _source) = app_with_background_and_smooth("guardrail-hidden");
        app.client_prefs.background_enabled = false;
        let over = Duration::from_millis(50);
        let budget = Duration::from_millis(16);
        for _ in 0..3 {
            app.note_smooth_frame(over, budget);
        }
        // Nothing is drawing the clip, so slowing it would relieve nothing:
        // the trip has to reach the UI tier.
        assert_eq!(app.background.as_ref().unwrap().effective_fps(), 60);
        assert_eq!(app.effective_refresh_fps(), 30);
    }

    #[test]
    fn frame_overruns_walk_the_session_ladder_without_touching_the_pref() {
        let budget = Duration::from_millis(16);
        let over = Duration::from_millis(30);
        let mut app = App::new_inert();
        app.client_prefs.refresh_fps = 60;
        assert_eq!(app.effective_refresh_fps(), 60);

        // Two overruns then a good frame: no downgrade.
        assert!(!app.note_smooth_frame(over, budget));
        assert!(!app.note_smooth_frame(over, budget));
        assert!(!app.note_smooth_frame(Duration::from_millis(2), budget));
        assert_eq!(app.effective_refresh_fps(), 60);

        // Three consecutive overruns: 60 -> 30 with the footer message.
        assert!(!app.note_smooth_frame(over, budget));
        assert!(!app.note_smooth_frame(over, budget));
        assert!(app.note_smooth_frame(over, budget));
        assert_eq!(app.effective_refresh_fps(), 30);
        assert_eq!(
            app.status,
            "Refresh reduced to 30 fps — frame budget exceeded"
        );
        assert!(!app.status_is_error);

        // Again: 30 -> off. The stored preference never changes.
        assert!(!app.note_smooth_frame(over, budget));
        assert!(!app.note_smooth_frame(over, budget));
        assert!(app.note_smooth_frame(over, budget));
        assert_eq!(app.effective_refresh_fps(), 0);
        assert!(app.status.contains("Refresh reduced to off"));
        assert_eq!(app.client_prefs.refresh_fps, 60, "session-only downgrade");

        // Fully event-driven now: the governor is inert.
        assert!(!app.note_smooth_frame(over, budget));

        // An explicit TUNE choice lifts the cap for a fresh try.
        app.page = Page::Settings;
        app.setting_state.select(Some(2));
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(app.client_prefs.refresh_fps, 0, "60 cycles to off");
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(app.client_prefs.refresh_fps, 30);
        assert_eq!(
            app.effective_refresh_fps(),
            30,
            "the explicit choice lifted the session cap"
        );
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
        assert!(
            app.status
                .contains("Press d again to delete 'Old chat to purge'")
        );
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

    /// An `App` with both worker channels held open by the test: commands
    /// can be asserted and events can be injected.
    fn app_with_live_channels() -> (App, Receiver<WorkerCommand>, Sender<WorkerEvent>) {
        let (commands, command_rx) = bounded(32);
        let (event_tx, events) = bounded(64);
        let app = App::with_worker(
            Worker {
                commands,
                events,
                handle: None,
            },
            false,
        );
        (app, command_rx, event_tx)
    }

    fn live_sample(timestamp_ms: i64, cpu: f64) -> LiveSample {
        LiveSample {
            available: true,
            timestamp_ms,
            cpu_percent: cpu,
            memory_used_bytes: 8_000_000_000,
            memory_total_bytes: 16_000_000_000,
            disk_read_bytes_per_sec: 1_000.0,
            disk_write_bytes_per_sec: 2_000.0,
            disk_latency_ms: 1.5,
            network_bytes_per_sec: 3_000.0,
            dpc_rate: 100.0,
            interrupt_rate: 200.0,
        }
    }

    #[test]
    fn live_targets_are_ema_smoothed_against_window_jitter() {
        // First sample seeds raw.
        let seed = live_to_system(&live_sample(1_000, 40.0), &SystemMetric::default());
        assert_eq!(smooth_live_target(None, &seed).cpu_percent, 40.0);
        // A 125 ms window whipsawing 40 -> 95 must move the display target
        // only a fraction of the way — no seismograph needle.
        let spike = live_to_system(&live_sample(1_125, 95.0), &SystemMetric::default());
        let smoothed = smooth_live_target(Some(&seed), &spike);
        assert!(
            (smoothed.cpu_percent - (40.0 + 55.0 * LIVE_EMA_SLOW)).abs() < 1e-9,
            "expected one EMA step, got {}",
            smoothed.cpu_percent
        );
        assert!(smoothed.cpu_percent < 60.0);
        // Sustained load converges: repeated 95% samples approach 95.
        let mut rolling = seed;
        for step in 0..40 {
            let raw = live_to_system(&live_sample(1_250 + step, 95.0), &SystemMetric::default());
            rolling = smooth_live_target(Some(&rolling), &raw);
        }
        assert!((rolling.cpu_percent - 95.0).abs() < 1.0);
        // Non-jitter channels pass through raw.
        assert_eq!(rolling.memory_used_bytes, 8_000_000_000);
    }

    #[test]
    fn live_poll_interval_is_min_of_eight_hz_and_the_refresh_rate() {
        assert_eq!(live_poll_interval(0), None, "0 fps never sends live");
        assert_eq!(live_poll_interval(30), Some(Duration::from_millis(125)));
        assert_eq!(live_poll_interval(60), Some(Duration::from_millis(125)));
        // A hypothetical tier below 8 Hz would poll at its own rate.
        assert_eq!(live_poll_interval(4), Some(Duration::from_millis(250)));
    }

    #[test]
    fn unsupported_live_errors_are_distinguished_from_transient_ones() {
        assert!(live_unsupported_error(&anyhow::anyhow!(
            "invalid JSON request: unknown variant `live` (invalidRequest)"
        )));
        assert!(!live_unsupported_error(&anyhow::anyhow!(
            "PC Pulse collector did not create its named pipe within 5.0s"
        )));
    }

    #[test]
    fn live_events_retarget_the_tween_toward_fresh_system_values() {
        let (mut app, _commands, events) = app_with_live_channels();
        app.client_prefs.refresh_fps = 30;
        let mut snapshot = Snapshot::default();
        snapshot.system.timestamp_ms = 1_800_000_000_000;
        snapshot.system.cpu_percent = 20.0;
        snapshot.system.memory_total_bytes = 16_000_000_000;
        snapshot.system.paged_pool_bytes = 777;
        events.send(WorkerEvent::Snapshot(Ok(snapshot))).unwrap();
        assert!(app.drain_events());

        let before_apply = Instant::now();
        events
            .send(WorkerEvent::Live(Ok(live_sample(
                1_800_000_001_000,
                80.0,
            ))))
            .unwrap();
        assert!(app.drain_events());

        let target = app.snapshot.as_ref().unwrap().system.clone();
        // The raw snapshot is untouched — live data never rewrites it.
        assert_eq!(target.cpu_percent, 20.0);
        assert_eq!(target.timestamp_ms, 1_800_000_000_000);
        // Before the live arrival instant the display still shows the
        // captured previous value; after a full ease window it sits exactly
        // on the live target — with snapshot-only fields passed through.
        app.set_render_now(before_apply);
        assert_eq!(app.display_system(&target).cpu_percent, 20.0);
        app.set_render_now(Instant::now() + crate::tween::TWEEN);
        let settled = app.display_system(&target);
        assert_eq!(settled.cpu_percent, 80.0);
        assert_eq!(settled.disk_latency_ms, 1.5);
        assert_eq!(settled.paged_pool_bytes, 777, "pass-through field");
        // The high-res tail recorded the sample.
        assert_eq!(app.live_tail.len(), 1);
        assert_eq!(app.live_tail[0].timestamp_ms, 1_800_000_001_000);

        // A duplicate delivery of the same collection is ignored.
        events
            .send(WorkerEvent::Live(Ok(live_sample(
                1_800_000_001_000,
                80.0,
            ))))
            .unwrap();
        app.drain_events();
        assert_eq!(app.live_tail.len(), 1);

        // An unavailable (warm-up) sample is ignored too.
        let mut cold = live_sample(1_800_000_002_000, 50.0);
        cold.available = false;
        events.send(WorkerEvent::Live(Ok(cold))).unwrap();
        app.drain_events();
        assert_eq!(app.live_tail.len(), 1);
    }

    #[test]
    fn at_zero_fps_live_is_never_requested_and_display_is_unchanged() {
        let (mut app, commands, events) = app_with_live_channels();
        // Startup with the event-driven default: adopting prefs sends no
        // ConfigureLive at all — the worker's poller defaults to off.
        app.adopt_client_prefs(UiPrefs::default(), None);
        assert!(
            !commands
                .try_iter()
                .any(|command| matches!(command, WorkerCommand::ConfigureLive { .. })),
            "0 fps startup must not arm the live poller"
        );
        // Even if a stray live event arrives, event-driven display ignores it.
        let mut snapshot = Snapshot::default();
        snapshot.system.cpu_percent = 20.0;
        events.send(WorkerEvent::Snapshot(Ok(snapshot))).unwrap();
        events
            .send(WorkerEvent::Live(Ok(live_sample(5, 99.0))))
            .unwrap();
        app.drain_events();
        assert!(app.live_tail.is_empty());
        let target = app.snapshot.as_ref().unwrap().system.clone();
        assert_eq!(app.display_system(&target).cpu_percent, 20.0);
    }

    #[test]
    fn refresh_changes_and_downgrades_reconfigure_the_live_poller_once() {
        let (mut app, commands, _events) = app_with_live_channels();
        app.adopt_client_prefs(
            UiPrefs {
                refresh_fps: 30,
                ..UiPrefs::default()
            },
            None,
        );
        let sent: Vec<u32> = commands
            .try_iter()
            .filter_map(|command| match command {
                WorkerCommand::ConfigureLive { fps } => Some(fps),
                _ => None,
            })
            .collect();
        assert_eq!(sent, vec![30], "smooth startup arms the poller once");

        // Cycling 30 -> 60 reconfigures; the redundant same-value sync is
        // suppressed.
        app.page = Page::Settings;
        app.setting_state.select(Some(2));
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(app.client_prefs.refresh_fps, 60);
        let sent: Vec<u32> = commands
            .try_iter()
            .filter_map(|command| match command {
                WorkerCommand::ConfigureLive { fps } => Some(fps),
                _ => None,
            })
            .collect();
        assert_eq!(sent, vec![60]);

        // Governor downgrades walk 60 -> 30 -> 0 and stop the poller at 0.
        let budget = Duration::from_millis(16);
        let over = Duration::from_millis(40);
        for _ in 0..3 {
            app.note_smooth_frame(over, budget);
        }
        for _ in 0..3 {
            app.note_smooth_frame(over, budget);
        }
        assert_eq!(app.effective_refresh_fps(), 0);
        let sent: Vec<u32> = commands
            .try_iter()
            .filter_map(|command| match command {
                WorkerCommand::ConfigureLive { fps } => Some(fps),
                _ => None,
            })
            .collect();
        assert_eq!(sent, vec![30, 0]);
    }

    #[test]
    fn an_old_service_degrades_smooth_mode_to_snapshots_with_one_note() {
        let (mut app, commands, events) = app_with_live_channels();
        app.adopt_client_prefs(
            UiPrefs {
                refresh_fps: 30,
                ..UiPrefs::default()
            },
            None,
        );
        let mut snapshot = Snapshot::default();
        snapshot.system.cpu_percent = 20.0;
        events.send(WorkerEvent::Snapshot(Ok(snapshot))).unwrap();
        events
            .send(WorkerEvent::Live(Ok(live_sample(5, 99.0))))
            .unwrap();
        app.drain_events();
        assert_eq!(app.live_tail.len(), 1, "live worked until the error");

        // The stub client error an old service produces.
        events
            .send(WorkerEvent::Live(Err(
                "invalid JSON request: unknown variant `live`, expected one of `ping`, \
                 `getSnapshot` (invalidRequest)"
                    .into(),
            )))
            .unwrap();
        app.drain_events();
        assert!(app.live_unsupported);
        assert!(app.status.contains("2-second snapshots"));
        assert!(!app.status_is_error, "a note, not an error");
        assert!(app.live_tail.is_empty(), "stale live data is dropped");
        // The display falls back to the plain snapshot tween path.
        let target = app.snapshot.as_ref().unwrap().system.clone();
        app.set_render_now(Instant::now() + crate::tween::TWEEN);
        assert_eq!(app.display_system(&target).cpu_percent, 20.0);
        // The poller was told to stop.
        assert!(commands.try_iter().any(|command| matches!(
            command,
            WorkerCommand::ConfigureLive { fps: 0 }
        )));

        // Note exactly once: a second error changes nothing user-visible.
        app.status = "Connected".into();
        events.send(WorkerEvent::Live(Err("again (invalidRequest)".into()))).unwrap();
        app.drain_events();
        assert_eq!(app.status, "Connected");
        // And later live samples are refused for the session.
        events
            .send(WorkerEvent::Live(Ok(live_sample(9, 42.0))))
            .unwrap();
        app.drain_events();
        assert!(app.live_tail.is_empty());
    }

    #[test]
    fn the_live_tail_is_bounded_and_chronological() {
        let (mut app, _commands, events) = app_with_live_channels();
        app.client_prefs.refresh_fps = 60;
        events
            .send(WorkerEvent::Snapshot(Ok(Snapshot::default())))
            .unwrap();
        app.drain_events();
        for step in 0..(LIVE_TAIL_CAPACITY as i64 + 200) {
            app.apply_live(live_sample(step * 125, 10.0));
        }
        assert_eq!(app.live_tail.len(), LIVE_TAIL_CAPACITY);
        assert!(
            app.live_tail
                .iter()
                .zip(app.live_tail.iter().skip(1))
                .all(|(left, right)| left.timestamp_ms < right.timestamp_ms),
            "the tail must stay in arrival order"
        );
        // ~180 seconds of 8 Hz data.
        let span_ms = app.live_tail.back().unwrap().timestamp_ms
            - app.live_tail.front().unwrap().timestamp_ms;
        assert_eq!(span_ms, (LIVE_TAIL_CAPACITY as i64 - 1) * 125);
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
