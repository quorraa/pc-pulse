//! ISR/DPC driver attribution for active `dpcInterrupt` findings.
//!
//! The DPC/interrupt detector can say *that* kernel interrupt work is
//! sustained, but not *whose* code is running. While the finding is active,
//! this module captures a short Windows kernel trace (a dedicated system
//! logger session with the ISR and DPC flags), buckets every interrupt
//! service routine and DPC routine address, and maps the buckets to loaded
//! kernel drivers so the finding's evidence can read
//! `storport.sys 41% · ndis.sys 27% · nvlddmkm.sys 12%`.
//!
//! Session discipline: the classic NT Kernel Logger is a singleton and the
//! collector's process-lifecycle session in `crate::etw` must never be
//! disturbed, so the capture uses a **separate** short-lived system logger
//! (`EVENT_TRACE_SYSTEM_LOGGER_MODE`, supported since Windows 10 1703, up to
//! eight concurrent). If the session cannot start — older OS, policy, logger
//! exhaustion, missing privilege — the evidence degrades to an honest note,
//! exactly like leak forensics.
//!
//! Budget discipline: the engine performs **zero syscalls** while no
//! `dpcInterrupt` finding is active. While one is active it captures once
//! when the finding fires and then at most every [`CAPTURE_COOLDOWN_MS`].
//! Each capture is bounded: [`CAPTURE_WINDOW_MS`] of wall time, an
//! [`EVENT_CAP`]-event storm guard, a below-normal-priority consumer thread,
//! and a deterministic `ControlTrace(STOP)` + `CloseTrace` on every path.
//!
//! Privacy boundary: only driver base file names (`nvlddmkm.sys`) and the
//! version-resource description/company strings of the top driver are ever
//! recorded — never routine addresses, process data, or memory content.

use crate::models::{Alert, Evidence};
use anyhow::{Result, bail};
use std::collections::{HashMap, HashSet};
use std::ffi::c_void;
use std::mem::size_of;
use std::ptr;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};
use windows::{
    Win32::{
        Foundation::{ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_SUCCESS, WIN32_ERROR},
        Storage::FileSystem::{GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW},
        System::{
            Diagnostics::Etw::{
                CONTROLTRACE_HANDLE, CloseTrace, ControlTraceW, EVENT_HEADER_FLAG_32_BIT_HEADER,
                EVENT_RECORD, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_FLAG, EVENT_TRACE_FLAG_DPC,
                EVENT_TRACE_FLAG_INTERRUPT, EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES,
                EVENT_TRACE_REAL_TIME_MODE, EVENT_TRACE_SYSTEM_LOGGER_MODE, OpenTraceW,
                PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME,
                PROCESSTRACE_HANDLE, ProcessTrace, StartTraceW, WNODE_FLAG_TRACED_GUID,
            },
            ProcessStatus::{
                EnumDeviceDrivers, K32GetDeviceDriverBaseNameW, K32GetDeviceDriverFileNameW,
            },
            Threading::{GetCurrentThread, SetThreadPriority, THREAD_PRIORITY_BELOW_NORMAL},
        },
    },
    core::{GUID, PCWSTR, PWSTR},
};

/// Re-captures run at most this often while a `dpcInterrupt` finding stays
/// active. Interrupt captures are heavier than handle tables, so the cooldown
/// is ten minutes rather than the forensics minute.
pub const CAPTURE_COOLDOWN_MS: i64 = 10 * 60_000;
/// Wall-clock length of one capture.
pub const CAPTURE_WINDOW_MS: u32 = 8_000;
/// Storm guard: once this many consumer callbacks have run, the capture
/// stops early and the evidence notes the cap.
pub const EVENT_CAP: u64 = 400_000;

const DPC_INTERRUPT_KIND: &str = "dpcInterrupt";
const ATTRIBUTION_LABEL: &str = "ISR/DPC attribution";
const TOP_DRIVER_LABEL: &str = "Top driver";
const WINDOW_LABEL: &str = "Trace window";
const INTERRUPT_LABELS: [&str; 3] = [ATTRIBUTION_LABEL, TOP_DRIVER_LABEL, WINDOW_LABEL];
const UNATTRIBUTED: &str = "unattributed";
/// Routine addresses are rounded down to 64 KiB so the bucket map stays tiny
/// even during a storm concentrated on a handful of routines.
const BUCKET_MASK: u64 = !0xFFFF;
/// Evidence values render generically in the TUI; keep them terminal-friendly.
const MAX_VALUE_CHARS: usize = 60;

/// The result of one bounded ISR/DPC trace.
#[derive(Debug, Clone, Default)]
pub struct InterruptCapture {
    /// Actual wall time covered (shorter than requested when the storm guard
    /// stopped the capture early).
    pub window_ms: u32,
    /// ISR events decoded.
    pub isr_events: u64,
    /// DPC events decoded (ordinary, timer, and threaded DPCs).
    pub dpc_events: u64,
    /// 64 KiB-aligned routine address -> event count.
    pub buckets: HashMap<u64, u64>,
    /// True when the storm guard ended the capture before the full window.
    pub capped: bool,
}

impl InterruptCapture {
    pub fn total_events(&self) -> u64 {
        self.isr_events + self.dpc_events
    }
}

/// The syscall layer behind the engine, stubbed in unit tests.
pub trait InterruptSource {
    /// Runs one bounded real-time ISR/DPC trace.
    fn capture(&mut self, window_ms: u32, event_cap: u64) -> Result<InterruptCapture>;
    /// `(base address, base file name)` for every loaded kernel driver,
    /// sorted ascending by base. Empty when enumeration is denied.
    fn driver_bases(&mut self) -> Vec<(u64, String)>;
    /// The version-resource `FileDescription` (or `CompanyName`) of a driver
    /// by base file name, e.g. `Microsoft Storage Port Driver`.
    fn driver_description(&mut self, base_name: &str) -> Option<String>;
}

/// Holds the latest attribution evidence per `dpcInterrupt` alert ID and the
/// capture cooldown. Mirrors [`crate::metrics::forensics::ForensicsEngine`].
pub struct InterruptEngine<S> {
    source: S,
    /// Latest rows per alert ID; replaced wholesale by each capture so
    /// evidence stays bounded.
    latest: HashMap<String, Vec<Evidence>>,
    /// Rows for findings that just resolved survive exactly one extra pass so
    /// the resolution write-back keeps its final attribution state.
    stale: HashSet<String>,
    last_capture_ms: Option<i64>,
}

impl<S: InterruptSource> InterruptEngine<S> {
    pub fn new(source: S) -> Self {
        Self {
            source,
            latest: HashMap::new(),
            stale: HashSet::new(),
            last_capture_ms: None,
        }
    }

    pub fn source(&self) -> &S {
        &self.source
    }

    pub fn source_mut(&mut self) -> &mut S {
        &mut self.source
    }

    /// Drives captures from the sampling cadence.
    ///
    /// With no active `dpcInterrupt` finding this returns before any source
    /// call — the engine is a strict no-op. While one is active, a capture
    /// runs when the finding first fires and then at most once per
    /// [`CAPTURE_COOLDOWN_MS`]. The capture itself blocks for up to
    /// [`CAPTURE_WINDOW_MS`]; the sampling loop resumes afterwards.
    pub fn observe(&mut self, active: &[Alert], now_ms: i64) {
        let ids: HashSet<String> = active
            .iter()
            .filter(|alert| alert.kind == DPC_INTERRUPT_KIND)
            .map(|alert| alert.id.clone())
            .collect();
        // Grace pass: rows for findings that resolved on the *previous* pass
        // are dropped now; findings resolving on this pass keep their final
        // rows for the resolution write-back.
        let stale = &self.stale;
        self.latest
            .retain(|id, _| ids.contains(id) || !stale.contains(id));
        self.stale = self
            .latest
            .keys()
            .filter(|id| !ids.contains(*id))
            .cloned()
            .collect();

        if ids.is_empty() {
            self.last_capture_ms = None;
            return;
        }
        let due = self
            .last_capture_ms
            .is_none_or(|last| now_ms.saturating_sub(last) >= CAPTURE_COOLDOWN_MS);
        let has_new = ids.iter().any(|id| !self.latest.contains_key(id));
        if !due && !has_new {
            return;
        }
        // The cooldown counts from every capture attempt, including degraded
        // ones — a failing session must not be retried on every sample.
        self.last_capture_ms = Some(now_ms);
        let rows = match self.source.capture(CAPTURE_WINDOW_MS, EVENT_CAP) {
            Ok(capture) => self.build_rows(&capture),
            Err(error) => vec![evidence(
                ATTRIBUTION_LABEL,
                format!("capture degraded: {error:#}"),
            )],
        };
        for id in ids {
            self.latest.insert(id, rows.clone());
        }
    }

    /// Attaches the latest attribution rows to matching alerts, replacing any
    /// attribution rows already present so evidence never accumulates.
    pub fn decorate(&self, alerts: &mut [Alert]) {
        for alert in alerts.iter_mut() {
            if let Some(rows) = self.latest.get(&alert.id) {
                alert
                    .evidence
                    .retain(|item| !INTERRUPT_LABELS.contains(&item.label.as_str()));
                alert.evidence.extend(rows.iter().cloned());
            }
        }
    }

    fn build_rows(&mut self, capture: &InterruptCapture) -> Vec<Evidence> {
        let window = format_trace_window(capture);
        if capture.total_events() == 0 {
            return vec![
                evidence(ATTRIBUTION_LABEL, "no ISR/DPC events in the trace window".into()),
                evidence(WINDOW_LABEL, window),
            ];
        }
        let mut drivers = self.source.driver_bases();
        drivers.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
        let ranked = attribute_buckets(&capture.buckets, &drivers);
        let mut rows = vec![evidence(ATTRIBUTION_LABEL, format_shares(&ranked))];
        if let Some((name, _)) = ranked.iter().find(|(name, _)| name != UNATTRIBUTED) {
            let description = self.source.driver_description(name);
            rows.push(evidence(
                TOP_DRIVER_LABEL,
                format_top_driver(name, description.as_deref()),
            ));
        }
        rows.push(evidence(WINDOW_LABEL, window));
        rows
    }

    #[cfg(test)]
    fn debug_counts(&self) -> (usize, usize) {
        (self.latest.len(), self.stale.len())
    }
}

fn evidence(label: &str, value: String) -> Evidence {
    Evidence {
        label: label.into(),
        value,
    }
}

/// Maps each bucket to the loaded driver with the greatest base at or below
/// the bucket address (drivers are contiguous from their base; without image
/// sizes the next driver's base is the boundary). Addresses below every base
/// are `unattributed`. Returns per-driver totals ranked largest first.
fn attribute_buckets(buckets: &HashMap<u64, u64>, drivers: &[(u64, String)]) -> Vec<(String, u64)> {
    let mut counts: HashMap<&str, u64> = HashMap::new();
    for (&address, &count) in buckets {
        let index = drivers.partition_point(|(base, _)| *base <= address);
        let name = if index == 0 {
            UNATTRIBUTED
        } else {
            drivers[index - 1].1.as_str()
        };
        *counts.entry(name).or_insert(0) += count;
    }
    let mut ranked: Vec<(String, u64)> = counts
        .into_iter()
        .map(|(name, count)| (name.to_string(), count))
        .collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    ranked
}

/// Top three shares, largest first, e.g.
/// `storport.sys 41% · ndis.sys 27% · nvlddmkm.sys 12%`.
fn format_shares(ranked: &[(String, u64)]) -> String {
    let total: u64 = ranked.iter().map(|(_, count)| count).sum();
    if total == 0 {
        // Events arrived but no routine address could be decoded — the MOF
        // layout did not match; degrade honestly rather than guess.
        return "routine addresses could not be decoded".into();
    }
    ranked
        .iter()
        .take(3)
        .map(|(name, count)| {
            let percent = (count * 100 + total / 2) / total;
            let name = truncate_value(name, 24);
            if percent == 0 {
                format!("{name} <1%")
            } else {
                format!("{name} {percent}%")
            }
        })
        .collect::<Vec<_>>()
        .join(" · ")
}

/// `storport.sys — Microsoft Storage Port Driver`, bounded for the TUI.
fn format_top_driver(name: &str, description: Option<&str>) -> String {
    match description {
        Some(description) => truncate_value(&format!("{name} — {description}"), MAX_VALUE_CHARS),
        None => name.to_string(),
    }
}

/// `8 s · 214k events`, with `(capped)` when the storm guard stopped early.
fn format_trace_window(capture: &InterruptCapture) -> String {
    let seconds = if capture.window_ms.is_multiple_of(1_000) {
        format!("{} s", capture.window_ms / 1_000)
    } else {
        format!("{:.1} s", f64::from(capture.window_ms) / 1_000.0)
    };
    let suffix = if capture.capped { " (capped)" } else { "" };
    format!(
        "{seconds} · {} events{suffix}",
        format_event_count(capture.total_events())
    )
}

fn format_event_count(count: u64) -> String {
    if count < 1_000 {
        count.to_string()
    } else if count < 1_000_000 {
        format!("{}k", count / 1_000)
    } else {
        format!("{:.1}M", count as f64 / 1_000_000.0)
    }
}

fn truncate_value(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        value.to_string()
    } else {
        let mut kept: String = value.chars().take(max_chars.saturating_sub(1)).collect();
        kept.push('…');
        kept
    }
}

// ---------------------------------------------------------------------------
// Windows implementation
// ---------------------------------------------------------------------------

/// Unique session name; deliberately not the NT Kernel Logger, so the
/// collector's process-lifecycle session is never disturbed.
const SESSION_NAME: &str = "PcPulseIsrDpc";
/// Classic kernel `PerfInfo` MOF class GUID; ISR and DPC events arrive under
/// it in a system logger session.
const PERFINFO_GUID: GUID = GUID::from_u128(0xce1dbfb4_137e_4da6_87b0_3f59aa102cbc);
/// `PERFINFO_LOG_TYPE_*` opcodes for the PerfInfo class.
const OPCODE_THREADED_DPC: u8 = 66;
const OPCODE_ISR: u8 = 67;
const OPCODE_DPC: u8 = 68;
const OPCODE_TIMER_DPC: u8 = 69;

struct CaptureState {
    cap: u64,
    processed: AtomicU64,
    isr: AtomicU64,
    dpc: AtomicU64,
    capped: AtomicBool,
    buckets: Mutex<HashMap<u64, u64>>,
}

/// Consumer callback: minimal work per event. For PerfInfo ISR/DPC events the
/// MOF payload starts with `InitialTime` (8 bytes) followed by the
/// pointer-sized `Routine` address — the layout the probe harness verifies
/// empirically against this machine's loaded-driver ranges.
unsafe extern "system" fn capture_callback(record: *mut EVENT_RECORD) {
    if record.is_null() {
        return;
    }
    unsafe {
        let event = &*record;
        let Some(state) = (event.UserContext as *const CaptureState).as_ref() else {
            return;
        };
        let processed = state.processed.fetch_add(1, Ordering::Relaxed) + 1;
        if processed > state.cap {
            state.capped.store(true, Ordering::Release);
            return;
        }
        if event.EventHeader.ProviderId != PERFINFO_GUID {
            return;
        }
        let opcode = event.EventHeader.EventDescriptor.Opcode;
        let is_isr = opcode == OPCODE_ISR;
        let is_dpc = matches!(opcode, OPCODE_DPC | OPCODE_TIMER_DPC | OPCODE_THREADED_DPC);
        if !is_isr && !is_dpc {
            return;
        }
        if is_isr {
            state.isr.fetch_add(1, Ordering::Relaxed);
        } else {
            state.dpc.fetch_add(1, Ordering::Relaxed);
        }
        let pointer_bytes: usize =
            if u32::from(event.EventHeader.Flags) & EVENT_HEADER_FLAG_32_BIT_HEADER != 0 {
                4
            } else {
                8
            };
        if event.UserData.is_null() || usize::from(event.UserDataLength) < 8 + pointer_bytes {
            return;
        }
        let routine = if pointer_bytes == 4 {
            u64::from(ptr::read_unaligned(
                event.UserData.cast::<u8>().add(8).cast::<u32>(),
            ))
        } else {
            ptr::read_unaligned(event.UserData.cast::<u8>().add(8).cast::<u64>())
        };
        if routine == 0 {
            return;
        }
        // Single consumer thread: the mutex is uncontended during the trace.
        if let Ok(mut buckets) = state.buckets.lock() {
            *buckets.entry(routine & BUCKET_MASK).or_insert(0) += 1;
        }
    }
}

fn session_properties(name: &[u16]) -> Vec<u64> {
    let property_bytes = size_of::<EVENT_TRACE_PROPERTIES>();
    let name_bytes = std::mem::size_of_val(name);
    let total_bytes = property_bytes + name_bytes;
    let mut buffer = vec![0u64; total_bytes.div_ceil(size_of::<u64>())];
    let properties = unsafe { &mut *buffer.as_mut_ptr().cast::<EVENT_TRACE_PROPERTIES>() };
    properties.Wnode.BufferSize = total_bytes as u32;
    properties.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    properties.Wnode.ClientContext = 1;
    properties.BufferSize = 64; // KiB per ETW buffer; sized for interrupt storms.
    properties.MinimumBuffers = 4;
    properties.MaximumBuffers = 12;
    properties.LogFileMode = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE;
    properties.EnableFlags =
        EVENT_TRACE_FLAG(EVENT_TRACE_FLAG_INTERRUPT.0 | EVENT_TRACE_FLAG_DPC.0);
    properties.FlushTimer = 1;
    properties.LoggerNameOffset = property_bytes as u32;
    unsafe {
        ptr::copy_nonoverlapping(
            name.as_ptr().cast::<u8>(),
            buffer.as_mut_ptr().cast::<u8>().add(property_bytes),
            name_bytes,
        );
    }
    buffer
}

/// Owns the short-lived system logger session; `stop` is idempotent and runs
/// on drop, so every error path tears the session down deterministically.
struct SystemLoggerSession {
    control: CONTROLTRACE_HANDLE,
    name: Vec<u16>,
    stopped: bool,
}

impl SystemLoggerSession {
    fn start() -> Result<Self> {
        let name: Vec<u16> = SESSION_NAME.encode_utf16().chain(Some(0)).collect();
        for attempt in 0..2 {
            let mut properties = session_properties(&name);
            let mut control = CONTROLTRACE_HANDLE::default();
            let status = unsafe {
                StartTraceW(
                    &mut control,
                    PCWSTR(name.as_ptr()),
                    properties.as_mut_ptr().cast::<EVENT_TRACE_PROPERTIES>(),
                )
            };
            if status == ERROR_SUCCESS {
                return Ok(Self {
                    control,
                    name,
                    stopped: false,
                });
            }
            if status == ERROR_ALREADY_EXISTS && attempt == 0 {
                // A crashed capture left a stale session behind: stop it by
                // name (handle 0 + name is valid for STOP) and retry once.
                let mut stop_properties = session_properties(&name);
                unsafe {
                    let _ = ControlTraceW(
                        CONTROLTRACE_HANDLE::default(),
                        PCWSTR(name.as_ptr()),
                        stop_properties.as_mut_ptr().cast::<EVENT_TRACE_PROPERTIES>(),
                        EVENT_TRACE_CONTROL_STOP,
                    );
                }
                continue;
            }
            if status == ERROR_ACCESS_DENIED {
                bail!("system logger denied; ISR/DPC capture needs the elevated collector");
            }
            bail!("system logger start failed (0x{:08x})", status.0);
        }
        bail!("system logger name stayed busy after stale-session cleanup");
    }

    fn stop(&mut self) -> WIN32_ERROR {
        if self.stopped {
            return ERROR_SUCCESS;
        }
        self.stopped = true;
        let mut properties = session_properties(&self.name);
        unsafe {
            ControlTraceW(
                self.control,
                PCWSTR(self.name.as_ptr()),
                properties.as_mut_ptr().cast::<EVENT_TRACE_PROPERTIES>(),
                EVENT_TRACE_CONTROL_STOP,
            )
        }
    }
}

impl Drop for SystemLoggerSession {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

/// The real syscall layer. Tracks session/trace balance counters so the probe
/// harness can assert that every capture stops its session and closes its
/// processing handle in the same pass.
#[derive(Default)]
pub struct WindowsInterruptSource {
    /// Base file name (lowercased) -> raw kernel path from the last
    /// enumeration, for version-resource lookups.
    file_paths: HashMap<String, String>,
    descriptions: HashMap<String, Option<String>>,
    sessions_started: u64,
    sessions_stopped: u64,
    traces_opened: u64,
    traces_closed: u64,
}

impl WindowsInterruptSource {
    /// `(sessions started, sessions stopped, traces opened, traces closed)`;
    /// pairs are equal when the per-capture discipline holds.
    pub fn session_balance(&self) -> (u64, u64, u64, u64) {
        (
            self.sessions_started,
            self.sessions_stopped,
            self.traces_opened,
            self.traces_closed,
        )
    }
}

impl InterruptSource for WindowsInterruptSource {
    fn capture(&mut self, window_ms: u32, event_cap: u64) -> Result<InterruptCapture> {
        let mut session = SystemLoggerSession::start()?;
        self.sessions_started += 1;
        let state = Arc::new(CaptureState {
            cap: event_cap,
            processed: AtomicU64::new(0),
            isr: AtomicU64::new(0),
            dpc: AtomicU64::new(0),
            capped: AtomicBool::new(false),
            buckets: Mutex::new(HashMap::new()),
        });
        let mut logfile = EVENT_TRACE_LOGFILEW {
            LoggerName: PWSTR(session.name.as_ptr() as *mut u16),
            Anonymous1: windows::Win32::System::Diagnostics::Etw::EVENT_TRACE_LOGFILEW_0 {
                ProcessTraceMode: PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD,
            },
            Anonymous2: windows::Win32::System::Diagnostics::Etw::EVENT_TRACE_LOGFILEW_1 {
                EventRecordCallback: Some(capture_callback),
            },
            // `state` outlives the consumer thread join below, so a borrowed
            // pointer is sound here (unlike the process-lifetime session in
            // `crate::etw`, nothing needs to leak).
            Context: Arc::as_ptr(&state) as *mut c_void,
            ..Default::default()
        };
        let processing = unsafe { OpenTraceW(&mut logfile) };
        if processing == PROCESSTRACE_HANDLE::default() || processing.Value == u64::MAX {
            let _ = session.stop();
            self.sessions_stopped += 1;
            bail!("OpenTraceW failed for the ISR/DPC consumer");
        }
        self.traces_opened += 1;
        let processing_value = processing.Value;
        let consumer = thread::Builder::new()
            .name("pcpulse-isrdpc".into())
            .spawn(move || unsafe {
                // The callback burst during a storm is real CPU; keep it from
                // competing with foreground work.
                let _ = SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
                let handle = PROCESSTRACE_HANDLE {
                    Value: processing_value,
                };
                let _ = ProcessTrace(&[handle], None, None);
                let _ = CloseTrace(handle);
            });
        let consumer = match consumer {
            Ok(consumer) => consumer,
            Err(error) => {
                unsafe {
                    let _ = CloseTrace(processing);
                }
                self.traces_closed += 1;
                let _ = session.stop();
                self.sessions_stopped += 1;
                bail!("ISR/DPC consumer thread failed to spawn: {error}");
            }
        };
        let started = Instant::now();
        let window = Duration::from_millis(u64::from(window_ms));
        while started.elapsed() < window && !state.capped.load(Ordering::Acquire) {
            thread::sleep(Duration::from_millis(100));
        }
        let capped = state.capped.load(Ordering::Acquire);
        let elapsed_ms = if capped {
            u32::try_from(started.elapsed().as_millis()).unwrap_or(window_ms)
        } else {
            window_ms
        };
        // Stopping the session makes ProcessTrace drain and return; the
        // consumer then closes its own processing handle.
        let stop_status = session.stop();
        self.sessions_stopped += 1;
        let joined = consumer.join();
        self.traces_closed += 1;
        if joined.is_err() {
            bail!("ISR/DPC consumer thread panicked");
        }
        if stop_status != ERROR_SUCCESS {
            bail!("system logger stop failed (0x{:08x})", stop_status.0);
        }
        let buckets = state
            .buckets
            .lock()
            .map(|buckets| buckets.clone())
            .unwrap_or_default();
        Ok(InterruptCapture {
            window_ms: elapsed_ms,
            isr_events: state.isr.load(Ordering::Relaxed),
            dpc_events: state.dpc.load(Ordering::Relaxed),
            buckets,
            capped,
        })
    }

    fn driver_bases(&mut self) -> Vec<(u64, String)> {
        let mut bases: Vec<*mut c_void> = vec![ptr::null_mut(); 1_024];
        loop {
            let capacity_bytes = (bases.len() * size_of::<*mut c_void>()) as u32;
            let mut needed = 0u32;
            if unsafe { EnumDeviceDrivers(bases.as_mut_ptr(), capacity_bytes, &mut needed) }
                .is_err()
            {
                return Vec::new();
            }
            let count = needed as usize / size_of::<*mut c_void>();
            if needed <= capacity_bytes {
                bases.truncate(count);
                break;
            }
            bases.resize(count + 64, ptr::null_mut());
        }
        self.file_paths.clear();
        let mut ranges = Vec::with_capacity(bases.len());
        for base in bases {
            if base.is_null() {
                continue;
            }
            let mut name = [0u16; 64];
            let length = unsafe { K32GetDeviceDriverBaseNameW(base, &mut name) } as usize;
            if length == 0 {
                continue;
            }
            let base_name = String::from_utf16_lossy(&name[..length.min(name.len())]);
            let mut path = [0u16; 260];
            let path_length = unsafe { K32GetDeviceDriverFileNameW(base, &mut path) } as usize;
            if path_length > 0 {
                self.file_paths.insert(
                    base_name.to_ascii_lowercase(),
                    String::from_utf16_lossy(&path[..path_length.min(path.len())]),
                );
            }
            ranges.push((base as u64, base_name));
        }
        ranges.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
        ranges
    }

    fn driver_description(&mut self, base_name: &str) -> Option<String> {
        let key = base_name.to_ascii_lowercase();
        if let Some(cached) = self.descriptions.get(&key) {
            return cached.clone();
        }
        let described = self
            .file_paths
            .get(&key)
            .map(|raw| normalize_driver_path(raw))
            .and_then(|path| file_description(&path));
        self.descriptions.insert(key, described.clone());
        described
    }
}

/// Kernel image paths arrive as `\SystemRoot\...`, `\??\C:\...`, or bare
/// `System32\...`; normalize to a Win32 path the version APIs accept.
fn normalize_driver_path(raw: &str) -> String {
    let system_root =
        std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    let lower = raw.to_ascii_lowercase();
    if lower.starts_with(r"\systemroot") {
        format!("{system_root}{}", &raw[r"\SystemRoot".len()..])
    } else if lower.starts_with(r"\??\") {
        raw[r"\??\".len()..].to_string()
    } else if lower.starts_with(r"system32\") {
        format!(r"{system_root}\{raw}")
    } else {
        raw.to_string()
    }
}

/// Version-resource `FileDescription` (preferred) or `CompanyName` of a
/// driver image, tried across the file's declared translations plus the
/// common US-English fallbacks.
fn file_description(path: &str) -> Option<String> {
    let wide: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
    let size = unsafe { GetFileVersionInfoSizeW(PCWSTR(wide.as_ptr()), None) };
    if size == 0 {
        return None;
    }
    let mut data = vec![0u8; size as usize];
    unsafe { GetFileVersionInfoW(PCWSTR(wide.as_ptr()), None, size, data.as_mut_ptr().cast()) }
        .ok()?;
    let mut translations = version_translations(&data);
    translations.push((0x0409, 0x04B0));
    translations.push((0x0409, 0x04E4));
    for field in ["FileDescription", "CompanyName"] {
        for (language, codepage) in &translations {
            let sub_block = format!("\\StringFileInfo\\{language:04x}{codepage:04x}\\{field}");
            if let Some(value) = query_version_string(&data, &sub_block) {
                return Some(value);
            }
        }
    }
    None
}

fn version_translations(data: &[u8]) -> Vec<(u16, u16)> {
    let sub_block: Vec<u16> = r"\VarFileInfo\Translation"
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut value_ptr: *mut c_void = ptr::null_mut();
    let mut value_len = 0u32;
    let ok = unsafe {
        VerQueryValueW(
            data.as_ptr().cast(),
            PCWSTR(sub_block.as_ptr()),
            &mut value_ptr,
            &mut value_len,
        )
    };
    if !ok.as_bool() || value_ptr.is_null() {
        return Vec::new();
    }
    let pair_count = value_len as usize / size_of::<u32>();
    (0..pair_count)
        .map(|index| unsafe {
            let entry = ptr::read_unaligned(value_ptr.cast::<u32>().add(index));
            ((entry & 0xFFFF) as u16, (entry >> 16) as u16)
        })
        .collect()
}

fn query_version_string(data: &[u8], sub_block: &str) -> Option<String> {
    let wide: Vec<u16> = sub_block.encode_utf16().chain(Some(0)).collect();
    let mut value_ptr: *mut c_void = ptr::null_mut();
    let mut value_len = 0u32;
    let ok = unsafe {
        VerQueryValueW(
            data.as_ptr().cast(),
            PCWSTR(wide.as_ptr()),
            &mut value_ptr,
            &mut value_len,
        )
    };
    if !ok.as_bool() || value_ptr.is_null() || value_len == 0 {
        return None;
    }
    let chars =
        unsafe { std::slice::from_raw_parts(value_ptr.cast::<u16>(), value_len as usize) };
    let text = String::from_utf16_lossy(chars)
        .trim_end_matches('\0')
        .trim()
        .to_string();
    (!text.is_empty()).then_some(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Severity;

    fn dpc_alert(id: &str) -> Alert {
        Alert {
            id: id.into(),
            kind: DPC_INTERRUPT_KIND.into(),
            severity: Severity::Warning,
            first_seen_ms: 0,
            last_seen_ms: 0,
            process_id: None,
            process_name: None,
            title: "High DPC or interrupt activity".into(),
            explanation: String::new(),
            evidence: vec![
                Evidence {
                    label: "DPC rate".into(),
                    value: "42000/s".into(),
                },
                Evidence {
                    label: "Interrupt rate".into(),
                    value: "18000/s".into(),
                },
            ],
            recommendation: String::new(),
            acknowledged: false,
            occurrence_count: 1,
            resolved_at_ms: None,
        }
    }

    fn other_alert(id: &str, kind: &str) -> Alert {
        Alert {
            kind: kind.into(),
            ..dpc_alert(id)
        }
    }

    fn capture(buckets: &[(u64, u64)]) -> InterruptCapture {
        InterruptCapture {
            window_ms: 8_000,
            isr_events: buckets.iter().map(|(_, count)| count).sum::<u64>() / 4,
            dpc_events: buckets.iter().map(|(_, count)| count).sum::<u64>()
                - buckets.iter().map(|(_, count)| count).sum::<u64>() / 4,
            buckets: buckets.iter().copied().collect(),
            capped: false,
        }
    }

    #[derive(Default)]
    struct StubSource {
        capture_calls: usize,
        driver_calls: usize,
        capture: InterruptCapture,
        drivers: Vec<(u64, String)>,
        descriptions: HashMap<String, String>,
        fail_capture: bool,
    }

    impl InterruptSource for StubSource {
        fn capture(&mut self, window_ms: u32, _event_cap: u64) -> Result<InterruptCapture> {
            self.capture_calls += 1;
            if self.fail_capture {
                bail!("system logger denied; ISR/DPC capture needs the elevated collector");
            }
            let mut capture = self.capture.clone();
            if capture.window_ms == 0 {
                capture.window_ms = window_ms;
            }
            Ok(capture)
        }

        fn driver_bases(&mut self) -> Vec<(u64, String)> {
            self.driver_calls += 1;
            self.drivers.clone()
        }

        fn driver_description(&mut self, base_name: &str) -> Option<String> {
            self.descriptions.get(base_name).cloned()
        }
    }

    fn drivers(pairs: &[(u64, &str)]) -> Vec<(u64, String)> {
        pairs
            .iter()
            .map(|(base, name)| (*base, (*name).to_string()))
            .collect()
    }

    #[test]
    fn no_finding_means_no_source_calls() {
        let mut engine = InterruptEngine::new(StubSource::default());
        engine.observe(&[], 0);
        engine.observe(&[other_alert("a", "handleGrowth")], 2_000);
        engine.observe(&[other_alert("b", "kernelPoolGrowth")], 4_000);
        assert_eq!(engine.source().capture_calls, 0);
        assert_eq!(engine.source().driver_calls, 0);
    }

    #[test]
    fn capture_on_first_fire_then_cooldown_gates_recapture() {
        let mut engine = InterruptEngine::new(StubSource::default());
        engine.source_mut().capture = capture(&[(0xFFFF_F800_0001_0000, 100)]);
        engine.source_mut().drivers = drivers(&[(0xFFFF_F800_0000_0000, "storport.sys")]);
        let alerts = [dpc_alert("d1")];
        engine.observe(&alerts, 0);
        assert_eq!(engine.source().capture_calls, 1, "captures when it fires");
        engine.observe(&alerts, 2_000);
        engine.observe(&alerts, 9 * 60_000);
        assert_eq!(engine.source().capture_calls, 1, "cooldown holds");
        engine.observe(&alerts, 10 * 60_000);
        assert_eq!(engine.source().capture_calls, 2, "recaptures after ten minutes");
        // Resolution: rows survive exactly one grace pass, then clear.
        engine.observe(&[], 11 * 60_000);
        assert_eq!(engine.debug_counts(), (1, 1), "final rows kept for write-back");
        engine.observe(&[], 12 * 60_000);
        assert_eq!(engine.debug_counts(), (0, 0), "grace pass expired");
        // A refire is a new alert ID and captures immediately.
        engine.observe(&[dpc_alert("d2")], 13 * 60_000);
        assert_eq!(engine.source().capture_calls, 3);
    }

    #[test]
    fn buckets_map_to_nearest_driver_at_or_below() {
        let map = drivers(&[
            (0x4000_0000, "ntoskrnl.exe"),
            (0x9000_0000, "storport.sys"),
            (0xC000_0000, "ndis.sys"),
        ]);
        let buckets: HashMap<u64, u64> = [
            (0x1000_0000, 7),  // below every base -> unattributed
            (0xA000_0000, 40), // between storport and ndis -> nearest below
            (0x9000_0000, 2),  // exactly at a base
            (0xF000_0000, 10), // above the highest base -> last driver
        ]
        .into();
        let ranked = attribute_buckets(&buckets, &map);
        assert_eq!(
            ranked,
            vec![
                ("storport.sys".to_string(), 42),
                ("ndis.sys".to_string(), 10),
                (UNATTRIBUTED.to_string(), 7),
            ]
        );
    }

    #[test]
    fn shares_format_ranks_and_truncates_to_three() {
        let ranked = vec![
            ("storport.sys".to_string(), 41_u64),
            ("ndis.sys".to_string(), 27),
            ("nvlddmkm.sys".to_string(), 12),
            ("acpi.sys".to_string(), 11),
            ("hal.dll".to_string(), 9),
        ];
        assert_eq!(
            format_shares(&ranked),
            "storport.sys 41% · ndis.sys 27% · nvlddmkm.sys 12%"
        );
        assert!(format_shares(&ranked).chars().count() <= MAX_VALUE_CHARS);
        assert_eq!(
            format_shares(&[("a.sys".to_string(), 100_000), ("b.sys".to_string(), 1)]),
            "a.sys 100% · b.sys <1%"
        );
        assert_eq!(format_shares(&[]), "routine addresses could not be decoded");
        assert_eq!(
            format_top_driver("storport.sys", Some("Microsoft Storage Port Driver")),
            "storport.sys — Microsoft Storage Port Driver"
        );
        assert!(
            format_top_driver("nvlddmkm.sys", Some(&"x".repeat(200)))
                .chars()
                .count()
                <= MAX_VALUE_CHARS
        );
        assert_eq!(format_top_driver("ndis.sys", None), "ndis.sys");
    }

    #[test]
    fn trace_window_formats_events_and_storm_cap() {
        let mut sample = capture(&[(0xFFFF_0000, 214_231)]);
        assert_eq!(format_trace_window(&sample), "8 s · 214k events");
        sample.capped = true;
        sample.window_ms = 5_200;
        assert_eq!(format_trace_window(&sample), "5.2 s · 214k events (capped)");
        assert_eq!(format_event_count(999), "999");
        assert_eq!(format_event_count(1_500_000), "1.5M");
    }

    #[test]
    fn storm_cap_reaches_evidence_as_a_note() {
        let mut engine = InterruptEngine::new(StubSource::default());
        let mut capped = capture(&[(0xFFFF_F800_0001_0000, 400_000)]);
        capped.capped = true;
        capped.window_ms = 3_100;
        engine.source_mut().capture = capped;
        engine.source_mut().drivers = drivers(&[(0xFFFF_F800_0000_0000, "storport.sys")]);
        let mut alerts = [dpc_alert("d1")];
        engine.observe(&alerts, 0);
        engine.decorate(&mut alerts);
        let window = alerts[0]
            .evidence
            .iter()
            .find(|item| item.label == WINDOW_LABEL)
            .map(|item| item.value.as_str());
        assert_eq!(window, Some("3.1 s · 400k events (capped)"));
    }

    #[test]
    fn evidence_rows_are_replaced_not_accumulated() {
        let mut engine = InterruptEngine::new(StubSource::default());
        engine.source_mut().capture = capture(&[(0xFFFF_F800_0001_0000, 100)]);
        engine.source_mut().drivers = drivers(&[(0xFFFF_F800_0000_0000, "storport.sys")]);
        engine
            .source_mut()
            .descriptions
            .insert("storport.sys".into(), "Microsoft Storage Port Driver".into());
        let mut alerts = [dpc_alert("d1")];
        // Simulate a stale attribution row arriving from persisted state.
        alerts[0].evidence.push(Evidence {
            label: ATTRIBUTION_LABEL.into(),
            value: "ndis.sys 99%".into(),
        });
        engine.observe(&alerts, 0);
        engine.decorate(&mut alerts);
        engine.decorate(&mut alerts);
        engine.decorate(&mut alerts);
        let attribution_rows: Vec<&Evidence> = alerts[0]
            .evidence
            .iter()
            .filter(|item| item.label == ATTRIBUTION_LABEL)
            .collect();
        assert_eq!(attribution_rows.len(), 1, "replaced, not appended");
        assert_eq!(attribution_rows[0].value, "storport.sys 100%");
        let top: Vec<&Evidence> = alerts[0]
            .evidence
            .iter()
            .filter(|item| item.label == TOP_DRIVER_LABEL)
            .collect();
        assert_eq!(top.len(), 1);
        assert_eq!(top[0].value, "storport.sys — Microsoft Storage Port Driver");
        // The detector's own rows are untouched.
        assert!(alerts[0].evidence.iter().any(|item| item.label == "DPC rate"));
        assert!(
            alerts[0]
                .evidence
                .iter()
                .all(|item| item.value.chars().count() <= MAX_VALUE_CHARS)
        );
    }

    #[test]
    fn degraded_capture_is_surfaced_as_evidence_and_respects_cooldown() {
        let mut engine = InterruptEngine::new(StubSource::default());
        engine.source_mut().fail_capture = true;
        let mut alerts = [dpc_alert("d1")];
        engine.observe(&alerts, 0);
        engine.observe(&alerts, 2_000);
        engine.observe(&alerts, 4_000);
        assert_eq!(
            engine.source().capture_calls,
            1,
            "a failing session is not retried on every sample"
        );
        engine.decorate(&mut alerts);
        let attribution = alerts[0]
            .evidence
            .iter()
            .find(|item| item.label == ATTRIBUTION_LABEL)
            .map(|item| item.value.as_str())
            .unwrap_or_default();
        assert!(attribution.contains("capture degraded"));
        assert!(attribution.contains("elevated collector"));
    }

    #[test]
    fn zero_event_capture_is_honest() {
        let mut engine = InterruptEngine::new(StubSource::default());
        engine.source_mut().capture = capture(&[]);
        let mut alerts = [dpc_alert("d1")];
        engine.observe(&alerts, 0);
        engine.decorate(&mut alerts);
        let attribution = alerts[0]
            .evidence
            .iter()
            .find(|item| item.label == ATTRIBUTION_LABEL)
            .map(|item| item.value.as_str());
        assert_eq!(attribution, Some("no ISR/DPC events in the trace window"));
        assert!(
            !alerts[0].evidence.iter().any(|item| item.label == TOP_DRIVER_LABEL),
            "no top-driver row without events"
        );
        assert_eq!(
            engine.source().driver_calls,
            0,
            "no driver enumeration without events"
        );
    }

    #[test]
    fn normalizes_kernel_image_paths() {
        let system_root =
            std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
        assert_eq!(
            normalize_driver_path(r"\SystemRoot\System32\drivers\storport.sys"),
            format!(r"{system_root}\System32\drivers\storport.sys")
        );
        assert_eq!(
            normalize_driver_path(r"\??\C:\Windows\system32\drivers\x.sys"),
            r"C:\Windows\system32\drivers\x.sys"
        );
        assert_eq!(
            normalize_driver_path(r"System32\drivers\y.sys"),
            format!(r"{system_root}\System32\drivers\y.sys")
        );
    }

    #[test]
    fn windows_driver_map_is_sorted_and_described() {
        // Real but cheap syscalls; kernel base addresses may be withheld from
        // an unelevated test run, which must degrade to an empty map rather
        // than fail.
        let mut source = WindowsInterruptSource::default();
        let map = source.driver_bases();
        if map.is_empty() {
            eprintln!("driver enumeration returned nothing (unelevated?); degraded path exercised");
            return;
        }
        assert!(map.windows(2).all(|pair| pair[0].0 <= pair[1].0), "sorted by base");
        let kernel = map
            .iter()
            .find(|(_, name)| name.to_ascii_lowercase().starts_with("ntoskrnl"));
        assert!(kernel.is_some(), "kernel image present in the driver map");
        if let Some((_, name)) = kernel {
            let description = source.driver_description(name);
            println!("kernel image description: {description:?}");
        }
    }

    #[test]
    #[ignore = "dev harness: captures a real 3 s ISR/DPC system-logger trace on this machine and prints driver attribution"]
    fn dev_probe_real_isr_dpc_capture() {
        let mut engine = InterruptEngine::new(WindowsInterruptSource::default());
        let map = engine.source_mut().driver_bases();
        println!("driver map: {} drivers", map.len());
        for (base, name) in map.iter().take(3) {
            println!("  {base:#018x} {name}");
        }
        match engine.source_mut().capture(3_000, EVENT_CAP) {
            Err(error) => {
                // Expected without SeSystemProfilePrivilege; the degraded
                // note is exactly what the finding's evidence would carry.
                println!("capture degraded: {error:#}");
            }
            Ok(result) => {
                println!(
                    "window {} ms · {} events (ISR {} / DPC {}) · {} buckets · capped {}",
                    result.window_ms,
                    result.total_events(),
                    result.isr_events,
                    result.dpc_events,
                    result.buckets.len(),
                    result.capped
                );
                let ranked = attribute_buckets(&result.buckets, &map);
                let total: u64 = ranked.iter().map(|(_, count)| count).sum();
                for (name, count) in ranked.iter().take(5) {
                    let percent = (count * 100).checked_div(total).unwrap_or(0);
                    let description = engine
                        .source_mut()
                        .driver_description(name)
                        .unwrap_or_else(|| "(no version resource)".into());
                    println!("  {name:<20} {percent:>3}% ({count})  {description}");
                }
                println!("evidence rows:");
                let rows = engine.build_rows(&result);
                for row in &rows {
                    println!("  {} = {}", row.label, row.value);
                }
                if result.total_events() > 0 {
                    assert!(
                        ranked.iter().any(|(name, _)| name != UNATTRIBUTED),
                        "expected at least one bucket to attribute to a known driver"
                    );
                }
            }
        }
        let (started, stopped, opened, closed) = engine.source().session_balance();
        println!("session balance: started {started} stopped {stopped} · traces opened {opened} closed {closed}");
        assert_eq!(started, stopped, "every session started was stopped");
        assert_eq!(opened, closed, "every processing handle was closed");
    }
}
