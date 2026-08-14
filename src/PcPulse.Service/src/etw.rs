use crate::etw_props::{ParsedProcessEvent, parse_process_event};
use anyhow::{Result, bail};
use chrono::Utc;
use crossbeam_channel::{Receiver, Sender, TrySendError, bounded};
use std::{
    collections::HashMap,
    mem::size_of,
    ptr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
    time::Instant,
};
use windows::{
    Win32::{
        Foundation::{ERROR_ALREADY_EXISTS, ERROR_SUCCESS, WIN32_ERROR},
        System::Diagnostics::Etw::{
            CONTROLTRACE_HANDLE, CloseTrace, ControlTraceW, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
            EVENT_HEADER_FLAG_32_BIT_HEADER, EVENT_RECORD, EVENT_TRACE_CONTROL_QUERY,
            EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_FLAG_PROCESS, EVENT_TRACE_LOGFILEW,
            EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE, EVENT_TRACE_SYSTEM_LOGGER_MODE,
            EnableTraceEx2, OpenTraceW, PROCESS_TRACE_MODE_EVENT_RECORD,
            PROCESS_TRACE_MODE_REAL_TIME, PROCESSTRACE_HANDLE, ProcessTrace, StartTraceW,
            TRACE_LEVEL_INFORMATION, WNODE_FLAG_TRACED_GUID,
        },
    },
    core::{GUID, PCWSTR, PWSTR},
};

// Microsoft-Windows-Kernel-Process. The process keyword keeps the session low-volume;
// high-frequency CPU and I/O values are deliberately obtained from PDH/Win32 instead.
const KERNEL_PROCESS_PROVIDER: GUID = GUID::from_u128(0x22fb2cd6_0e7b_422b_a0c7_2fad1fd0e716);
const PROCESS_KEYWORD: u64 = 0x10;
const PROCESS_START_EVENT_ID: u16 = 1;
const PROCESS_STOP_EVENT_ID: u16 = 2;
/// Bound on the launch-history queue. At the process keyword's real-world
/// rate (single-digit events/sec) this is minutes of slack; it exists so a
/// stalled consumer costs bounded memory instead of unbounded growth.
const PROCESS_EVENT_CAPACITY: usize = 4096;
/// WCHARs reserved for each of the two names a query writes back. 1024 is the
/// canonical slack used with `ControlTraceW`.
const QUERY_NAME_SLOT_CHARS: usize = 1024;

/// Session name for the manifest (Kernel-Process) session.
///
/// Deliberately *fixed*, not suffixed with the process id. ETW sessions
/// outlive the process that created them: a service killed non-gracefully
/// (`taskkill /f`, a crash, a hard power event) leaves its session running,
/// and a pid-suffixed name means the next run picks a *different* name and
/// never reclaims the orphan. With a fixed name the orphan is found on the
/// next start (`ERROR_ALREADY_EXISTS`) and stopped, so a session can leak at
/// most once. See [`start_trace_reclaiming_stale`].
const PROCESS_SESSION_NAME: &str = "PcPulse";
/// Session name for the opt-in command-line system logger. Fixed for the
/// reason above, and doubly important here: a machine allows only eight
/// system-logger sessions in total, so four hard kills of a pid-named
/// session would burn half the pool permanently.
const CMDLINE_SESSION_NAME: &str = "PcPulse-Cmdline";

fn wide_session_name(name: &str) -> Vec<u16> {
    name.encode_utf16().chain(Some(0)).collect()
}

#[derive(Debug, Clone, Default)]
pub struct EtwSnapshot {
    pub active: bool,
    pub events_per_sec: f64,
    pub dropped_events: u64,
    pub process_starts: HashMap<u32, i64>,
}

/// Loss and integrity counters for the ETW pipeline.
///
/// Every field is an absolute running total *for one collector session*, and
/// consumers diff successive reads. Crucially, these totals are **not
/// monotonic across the process lifetime**: when ETW dies and `runtime.rs`
/// restarts the collector, it builds a fresh `EtwCollector` with a fresh
/// `Arc<EtwHealth>`, and every counter here restarts at zero. A naive
/// `current - previous` therefore underflows across a restart. Consumers must
/// use `saturating_sub` and treat any decrease as a restart (report the new
/// absolute value as the delta, or zero), never as negative loss.
#[derive(Debug, Default)]
pub struct EtwHealth {
    /// Events discarded because the bounded process queue was full.
    pub dropped_channel: AtomicU64,
    /// `EventsLost` as reported by `EVENT_TRACE_CONTROL_QUERY` — events the
    /// kernel dropped before the callback ever saw them. Stale (and, if the
    /// very first query failed, zero) whenever `events_lost_query_failures`
    /// is nonzero: read the two together.
    pub etw_events_lost: AtomicU64,
    /// Events the TDH decode rejected; dropped rather than guessed at.
    pub malformed_events: AtomicU64,
    /// Failed `EVENT_TRACE_CONTROL_QUERY` calls. Nonzero means
    /// `etw_events_lost` is not trustworthy — it distinguishes "no events
    /// lost" from "never successfully asked".
    pub events_lost_query_failures: AtomicU64,
}

/// Producer half of the bounded process-event queue, held by the ETW
/// callback. `offer` never blocks and never panics: a full queue costs the
/// newest event and one counter increment, so the ETW consumer thread can
/// never be stalled by a slow reader.
pub struct EtwEventSink {
    tx: Sender<ParsedProcessEvent>,
    health: Arc<EtwHealth>,
}

impl EtwEventSink {
    pub fn offer(&self, event: ParsedProcessEvent) {
        match self.tx.try_send(event) {
            Ok(()) => {}
            // Deviation from the spec's "drop oldest": a bounded channel
            // cannot evict its head from the producer side, so a full queue
            // drops the newest event instead. Counter semantics are
            // unchanged — every discarded event is one `dropped_channel`.
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                self.health.dropped_channel.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// Consumer half of the bounded process-event queue, drained once per
/// runtime tick.
pub struct EtwProcessQueue {
    rx: Receiver<ParsedProcessEvent>,
    health: Arc<EtwHealth>,
}

impl EtwProcessQueue {
    fn new(capacity: usize) -> (Self, EtwEventSink) {
        let (tx, rx) = bounded(capacity);
        let health = Arc::new(EtwHealth::default());
        (
            Self {
                rx,
                health: Arc::clone(&health),
            },
            EtwEventSink { tx, health },
        )
    }

    #[cfg(test)]
    fn new_for_test(capacity: usize) -> (Self, EtwEventSink) {
        Self::new(capacity)
    }

    pub fn health(&self) -> &Arc<EtwHealth> {
        &self.health
    }

    /// Drains everything queued since the last call. Never blocks.
    pub fn take_process_events(&self) -> Vec<ParsedProcessEvent> {
        self.rx.try_iter().collect()
    }
}

struct CallbackState {
    event_count: AtomicU64,
    process_starts: Mutex<HashMap<u32, i64>>,
    sink: EtwEventSink,
}

struct SampleState {
    count: u64,
    at: Instant,
}

pub struct EtwCollector {
    callback: Arc<CallbackState>,
    queue: EtwProcessQueue,
    sample: Mutex<SampleState>,
    session_name: Vec<u16>,
    control_handle: CONTROLTRACE_HANDLE,
    /// Guards the one-shot events-lost-query failure log; a broken query
    /// fails on every tick and must not flood the log.
    events_lost_query_logged: AtomicBool,
    worker: Option<JoinHandle<()>>,
}

unsafe impl Send for EtwCollector {}
unsafe impl Sync for EtwCollector {}

impl EtwCollector {
    pub fn start() -> Result<Self> {
        let session_name = wide_session_name(PROCESS_SESSION_NAME);
        let (queue, sink) = EtwProcessQueue::new(PROCESS_EVENT_CAPACITY);
        let callback = Arc::new(CallbackState {
            event_count: AtomicU64::new(0),
            process_starts: Mutex::new(HashMap::new()),
            sink,
        });
        let worker_state = Arc::clone(&callback);
        let worker_name = session_name.clone();
        let (initialized_tx, initialized_rx) = mpsc::sync_channel::<Result<u64>>(1);
        let worker = thread::Builder::new()
            .name("pcpulse-etw".into())
            .spawn(move || {
                match run_trace(&worker_name, worker_state) {
                    Ok((control, processing, context)) => {
                        let _ = initialized_tx.send(Ok(control.Value));
                        unsafe {
                            let status = ProcessTrace(&[processing], None, None);
                            if status != ERROR_SUCCESS {
                                // A stop normally returns success; count unexpected exits as loss.
                            }
                            let _ = CloseTrace(processing);
                            drop(Arc::from_raw(context));
                        }
                    }
                    Err(error) => {
                        let _ = initialized_tx.send(Err(error));
                    }
                }
            })?;
        let control_value = initialized_rx
            .recv()
            .map_err(|_| anyhow::anyhow!("ETW worker exited during initialization"))??;
        Ok(Self {
            callback,
            queue,
            sample: Mutex::new(SampleState {
                count: 0,
                at: Instant::now(),
            }),
            session_name,
            control_handle: CONTROLTRACE_HANDLE {
                Value: control_value,
            },
            events_lost_query_logged: AtomicBool::new(false),
            worker: Some(worker),
        })
    }

    /// Loss counters for this session. Absolute totals; consumers diff.
    pub fn health(&self) -> &Arc<EtwHealth> {
        self.queue.health()
    }

    /// Drains the launch-history queue. Called once per runtime tick.
    pub fn take_process_events(&self) -> Vec<ParsedProcessEvent> {
        self.queue.take_process_events()
    }

    /// Issues one `EVENT_TRACE_CONTROL_QUERY` and returns the session's
    /// `EventsLost`, or the failing status.
    ///
    /// Uses [`control_property_buffer`] rather than the start path's buffer:
    /// on QUERY, ETW writes the logger name *and* the log file name back into
    /// the caller's buffer, so it must carry room for both regardless of how
    /// short the session name is.
    fn query_events_lost(&self) -> Result<u32, WIN32_ERROR> {
        let mut properties = control_property_buffer(&self.session_name);
        let properties_ptr = properties.as_mut_ptr().cast::<EVENT_TRACE_PROPERTIES>();
        let status = unsafe {
            ControlTraceW(
                self.control_handle,
                PCWSTR(self.session_name.as_ptr()),
                properties_ptr,
                EVENT_TRACE_CONTROL_QUERY,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(status);
        }
        Ok(unsafe { (*properties_ptr).EventsLost })
    }

    /// Asks the kernel how many events this session has lost, and records the
    /// absolute total. A failed query leaves the previous value in place —
    /// health reporting must never be able to fail the sampling tick — but it
    /// is never silent: the first failure is logged and every failure bumps
    /// `events_lost_query_failures`, so a permanently zero `etw_events_lost`
    /// can always be told apart from a genuinely lossless session.
    fn refresh_events_lost(&self) {
        match self.query_events_lost() {
            Ok(events_lost) => {
                self.queue
                    .health()
                    .etw_events_lost
                    .store(u64::from(events_lost), Ordering::Relaxed);
            }
            Err(status) => {
                self.queue
                    .health()
                    .events_lost_query_failures
                    .fetch_add(1, Ordering::Relaxed);
                // One line per collector, not one per tick: a failing query
                // fails every second and would otherwise flood the log.
                if !self.events_lost_query_logged.swap(true, Ordering::Relaxed) {
                    eprintln!(
                        "ETW events-lost query failed with status 0x{:08x}; \
                         etwEventsLost will remain stale for this session",
                        status.0
                    );
                }
            }
        }
    }

    pub fn snapshot(&self) -> EtwSnapshot {
        self.refresh_events_lost();
        let now = Instant::now();
        let current = self.callback.event_count.load(Ordering::Relaxed);
        let events_per_sec = if let Ok(mut sample) = self.sample.lock() {
            let elapsed = now.duration_since(sample.at).as_secs_f64().max(0.001);
            let rate = current.saturating_sub(sample.count) as f64 / elapsed;
            sample.count = current;
            sample.at = now;
            rate
        } else {
            0.0
        };
        let cutoff = Utc::now().timestamp_millis() - 15 * 60 * 1_000;
        let process_starts = self.callback.process_starts.lock().map_or_else(
            |_| HashMap::new(),
            |mut starts| {
                starts.retain(|_, timestamp| *timestamp >= cutoff);
                starts.clone()
            },
        );
        EtwSnapshot {
            active: true,
            events_per_sec,
            dropped_events: self.queue.health().dropped_channel.load(Ordering::Relaxed),
            process_starts,
        }
    }
}

impl Drop for EtwCollector {
    fn drop(&mut self) {
        // Correctly sized for a control operation (see
        // `control_property_buffer`); a stop that fails here is what leaves
        // the orphan the next start has to reclaim.
        let status = stop_session(self.control_handle, &self.session_name);
        if status != ERROR_SUCCESS {
            eprintln!(
                "stopping the ETW session returned 0x{:08x}; it may be left running until \
                 the next start reclaims it",
                status.0
            );
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

/// What to do with a `StartTraceW` status. Pure so the reclaim policy is
/// testable without a live ETW session.
#[derive(Debug, PartialEq)]
enum StartOutcome {
    Started,
    /// The name is taken by a session this process does not own -- an orphan
    /// left by a previous, non-graceful termination. Stop it and retry once.
    ReclaimStale,
    Failed(WIN32_ERROR),
}

fn classify_start_status(status: WIN32_ERROR) -> StartOutcome {
    match status {
        ERROR_SUCCESS => StartOutcome::Started,
        ERROR_ALREADY_EXISTS => StartOutcome::ReclaimStale,
        other => StartOutcome::Failed(other),
    }
}

/// Stops a session by name, returning the status. Used both for
/// teardown-on-failure and for reclaiming an orphan; a name-based stop needs
/// no handle, which is exactly why an orphan left by a *previous process* can
/// be stopped at all.
///
/// The status is returned rather than swallowed because the reclaim path has
/// to be able to tell "the stale session would not stop" (a privilege
/// problem, say) from "it stopped and the restart still failed" -- the two
/// call for completely different operator action, and a discarded status
/// makes them read identically.
fn stop_session_by_name(name: &[u16]) -> WIN32_ERROR {
    stop_session(CONTROLTRACE_HANDLE::default(), name)
}

/// Stops a session, preferring `handle` when the caller owns one (a zeroed
/// handle falls back to the name). Owners pass their handle so the stop can
/// only ever hit the session they started, never a same-named session that
/// something else has since created.
fn stop_session(handle: CONTROLTRACE_HANDLE, name: &[u16]) -> WIN32_ERROR {
    let mut properties = control_property_buffer(name);
    unsafe {
        ControlTraceW(
            handle,
            PCWSTR(name.as_ptr()),
            properties.as_mut_ptr().cast::<EVENT_TRACE_PROPERTIES>(),
            EVENT_TRACE_CONTROL_STOP,
        )
    }
}

/// Starts a trace session, reclaiming an orphan of the same name if one is
/// already running.
///
/// Both sessions here are named after the *service*, not the process, so an
/// instance killed non-gracefully leaves a session that would otherwise sit
/// there forever with the kernel buffering events nobody consumes -- and for
/// the command-line system logger, holding one of the machine's eight slots.
/// A single `ERROR_ALREADY_EXISTS` retry turns that permanent leak into a
/// self-healing one. The retry is deliberately once: a second failure is a
/// real error, not something to loop on.
///
/// `properties` is rebuilt for the retry because `StartTraceW` writes into
/// the buffer it is given.
fn start_trace_reclaiming_stale(
    name: &[u16],
    properties: fn(&[u16]) -> Vec<u64>,
) -> Result<CONTROLTRACE_HANDLE> {
    let mut buffer = properties(name);
    let mut control = CONTROLTRACE_HANDLE::default();
    let status = unsafe {
        StartTraceW(
            &mut control,
            PCWSTR(name.as_ptr()),
            buffer.as_mut_ptr().cast::<EVENT_TRACE_PROPERTIES>(),
        )
    };
    match classify_start_status(status) {
        StartOutcome::Started => return Ok(control),
        StartOutcome::Failed(status) => {
            bail!("StartTraceW failed with status 0x{:08x}", status.0)
        }
        StartOutcome::ReclaimStale => {}
    }

    let stop_status = stop_session_by_name(name);
    eprintln!(
        "reclaiming an orphaned ETW session left by a previous run (its name was already \
         in use); stop returned 0x{:08x}",
        stop_status.0
    );
    let mut buffer = properties(name);
    let mut control = CONTROLTRACE_HANDLE::default();
    let status = unsafe {
        StartTraceW(
            &mut control,
            PCWSTR(name.as_ptr()),
            buffer.as_mut_ptr().cast::<EVENT_TRACE_PROPERTIES>(),
        )
    };
    if status != ERROR_SUCCESS {
        // Both statuses, because they say different things: a failed stop
        // means the orphan is still there (and why), while a successful stop
        // followed by a failed start means something else took the name or
        // the session could not be created at all.
        bail!(
            "StartTraceW failed with status 0x{:08x} after attempting to stop a stale session \
             of the same name (stop returned 0x{:08x})",
            status.0,
            stop_status.0
        );
    }
    Ok(control)
}

fn run_trace(
    name: &[u16],
    state: Arc<CallbackState>,
) -> Result<(
    CONTROLTRACE_HANDLE,
    PROCESSTRACE_HANDLE,
    *const CallbackState,
)> {
    let control = start_trace_reclaiming_stale(name, property_buffer)?;
    let enable_status = unsafe {
        EnableTraceEx2(
            control,
            &KERNEL_PROCESS_PROVIDER,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
            TRACE_LEVEL_INFORMATION as u8,
            PROCESS_KEYWORD,
            0,
            0,
            None,
        )
    };
    if enable_status != ERROR_SUCCESS {
        let stop_status = stop_session_by_name(name);
        bail!(
            "EnableTraceEx2 failed with status 0x{:08x} (teardown stop returned 0x{:08x})",
            enable_status.0,
            stop_status.0
        );
    }

    let context = Arc::into_raw(state) as *mut core::ffi::c_void;
    let mut logfile = EVENT_TRACE_LOGFILEW {
        LoggerName: PWSTR(name.as_ptr() as *mut u16),
        Anonymous1: windows::Win32::System::Diagnostics::Etw::EVENT_TRACE_LOGFILEW_0 {
            ProcessTraceMode: PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD,
        },
        Anonymous2: windows::Win32::System::Diagnostics::Etw::EVENT_TRACE_LOGFILEW_1 {
            EventRecordCallback: Some(event_record_callback),
        },
        Context: context,
        ..Default::default()
    };
    let processing = unsafe { OpenTraceW(&mut logfile) };
    if processing == PROCESSTRACE_HANDLE::default() || processing.Value == u64::MAX {
        unsafe {
            drop(Arc::from_raw(context.cast::<CallbackState>()));
        }
        let stop_status = stop_session_by_name(name);
        bail!(
            "OpenTraceW failed (teardown stop returned 0x{:08x})",
            stop_status.0
        );
    }
    // ProcessTrace owns the callback context until the processing handle is closed.
    // Reconstructing the Arc after ProcessTrace is not safe from this function, so the
    // callback keeps one intentionally process-lifetime reference (one small allocation).
    Ok((control, processing, context.cast::<CallbackState>()))
}

unsafe extern "system" fn event_record_callback(record: *mut EVENT_RECORD) {
    if record.is_null() {
        return;
    }
    unsafe {
        let event = &*record;
        let state = (event.UserContext as *const CallbackState).as_ref();
        let Some(state) = state else { return };
        state.event_count.fetch_add(1, Ordering::Relaxed);
        if event.EventHeader.ProviderId == KERNEL_PROCESS_PROVIDER
            && event.EventHeader.EventDescriptor.Id == PROCESS_START_EVENT_ID
        {
            let payload_pid =
                if event.UserDataLength >= size_of::<u32>() as u16 && !event.UserData.is_null() {
                    ptr::read_unaligned(event.UserData.cast::<u32>())
                } else {
                    0
                };
            let pid = if payload_pid != 0 {
                payload_pid
            } else {
                event.EventHeader.ProcessId
            };
            if pid != 0
                && let Ok(mut starts) = state.process_starts.lock()
            {
                starts.insert(pid, Utc::now().timestamp_millis());
            }
        }
        // Launch history: full TDH decode of both start and stop events,
        // independent of the 4-byte fast path above. A decode failure is
        // counted and dropped — this callback runs on the ETW consumer
        // thread and must never panic or block.
        if event.EventHeader.ProviderId == KERNEL_PROCESS_PROVIDER
            && matches!(
                event.EventHeader.EventDescriptor.Id,
                PROCESS_START_EVENT_ID | PROCESS_STOP_EVENT_ID
            )
        {
            match parse_process_event(record) {
                Ok(parsed) => state.sink.offer(parsed),
                Err(_) => {
                    state
                        .sink
                        .health
                        .malformed_events
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }
}

fn property_buffer(name: &[u16]) -> Vec<u64> {
    let property_bytes = size_of::<EVENT_TRACE_PROPERTIES>();
    let name_bytes = std::mem::size_of_val(name);
    let total_bytes = property_bytes + name_bytes;
    let mut buffer = vec![0u64; total_bytes.div_ceil(size_of::<u64>())];
    let properties = unsafe { &mut *buffer.as_mut_ptr().cast::<EVENT_TRACE_PROPERTIES>() };
    properties.Wnode.BufferSize = total_bytes as u32;
    properties.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    properties.Wnode.ClientContext = 1;
    properties.BufferSize = 16; // KiB per ETW buffer.
    properties.MinimumBuffers = 2;
    properties.MaximumBuffers = 4;
    properties.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
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

/// Buffer for every `ControlTraceW` operation — `EVENT_TRACE_CONTROL_QUERY`
/// *and* `EVENT_TRACE_CONTROL_STOP`.
///
/// Both control codes make ETW write the session's properties back into the
/// caller's buffer, including the logger name and the log file name, so the
/// canonical sizing is the struct plus two `MAX_SESSION_NAME_CHARS`-style
/// 1024-WCHAR slots with `LoggerNameOffset` and `LogFileNameOffset` pointing
/// at them. Sizing a control buffer as `struct + session-name bytes` (what
/// [`property_buffer`] does, correctly, for *starting* a session) leaves no
/// room for the names ETW writes back: `ControlTraceW` would either reject
/// the call with `ERROR_BAD_LENGTH` — a query leaving `etw_events_lost`
/// permanently zero, a stop leaving an orphaned session unreclaimed — or
/// write past the allocation.
fn control_property_buffer(name: &[u16]) -> Vec<u64> {
    let property_bytes = size_of::<EVENT_TRACE_PROPERTIES>();
    let name_slot_bytes = QUERY_NAME_SLOT_CHARS * size_of::<u16>();
    let total_bytes = property_bytes + 2 * name_slot_bytes;
    let mut buffer = vec![0u64; total_bytes.div_ceil(size_of::<u64>())];
    let properties = unsafe { &mut *buffer.as_mut_ptr().cast::<EVENT_TRACE_PROPERTIES>() };
    properties.Wnode.BufferSize = total_bytes as u32;
    properties.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    properties.LoggerNameOffset = property_bytes as u32;
    properties.LogFileNameOffset = (property_bytes + name_slot_bytes) as u32;
    // Copy the session name into its slot, truncating rather than overflowing
    // if it somehow exceeds the slot (it cannot: the names are constants).
    let name_bytes = std::mem::size_of_val(name).min(name_slot_bytes);
    unsafe {
        ptr::copy_nonoverlapping(
            name.as_ptr().cast::<u8>(),
            buffer.as_mut_ptr().cast::<u8>().add(property_bytes),
            name_bytes,
        );
    }
    buffer
}

fn _status_is_success(status: WIN32_ERROR) -> bool {
    status == ERROR_SUCCESS
}

// ---------------------------------------------------------------------------
// Opt-in command-line capture: a second, classic (MOF) system-logger session.
//
// PRIVACY INVARIANT: nothing below runs unless `captureCommandLines` is on.
// The runtime constructs `CmdlineCollector` when the setting flips on and
// drops it when the setting flips off; with the setting off there is no
// session, no callback, and no command-line data anywhere in this process.
// ---------------------------------------------------------------------------

/// Classic MOF `Process` event class GUID. Kernel (system-logger) sessions
/// report classic events with the MOF class GUID in `ProviderId` when the
/// trace is opened in `EVENT_RECORD` mode.
const PROCESS_MOF_GUID: GUID = GUID::from_u128(0x3d6fa8d0_fe05_11d0_9dda_00c04fd7ba7c);
/// `Process_TypeGroup1` Start opcode. Rundown (`DCStart`, opcode 3) is
/// deliberately ignored: its timestamp is the session's start, not the
/// process's, so joining it by start-time proximity would attach a command
/// line to the wrong launch.
const PROCESS_MOF_START_OPCODE: u8 = 1;
/// Bound on the command-line queue, mirroring [`PROCESS_EVENT_CAPACITY`].
const CMDLINE_EVENT_CAPACITY: usize = 4096;

/// One command line observed by the MOF session, as it left the kernel:
/// **not yet redacted**. It is redacted the moment it reaches
/// `CmdlineJoiner::offer`, which is the only consumer.
///
/// `Debug` is hand-written to elide the line itself: this is the one place a
/// raw, unredacted command line exists, and a stray `{:?}` in a log or a
/// panic message would put the credentials the pipeline exists to strip
/// straight into a diagnostic file.
#[derive(Clone, PartialEq)]
pub struct CapturedCmdline {
    pub pid: u32,
    /// The MOF event's own timestamp, in epoch milliseconds. The MOF
    /// `Process_TypeGroup1` payload carries no create-time field, so the
    /// event header's timestamp (which ETW converts to FILETIME for
    /// non-raw-timestamp sessions) stands in for it. It is within
    /// milliseconds of the manifest session's `CreateTime`, comfortably
    /// inside the joiner's 2s window.
    pub start_ms: i64,
    pub command_line: String,
}

impl std::fmt::Debug for CapturedCmdline {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CapturedCmdline")
            .field("pid", &self.pid)
            .field("start_ms", &self.start_ms)
            .field("command_line", &"‹elided›")
            .finish()
    }
}

struct CmdlineCallbackState {
    tx: Sender<CapturedCmdline>,
    health: Arc<EtwHealth>,
}

impl CmdlineCallbackState {
    fn offer(&self, captured: CapturedCmdline) {
        match self.tx.try_send(captured) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                self.health.dropped_channel.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// The opt-in MOF session. Constructing it starts the session; dropping it
/// stops the session and joins its consumer thread, which is what makes the
/// live setting toggle work without a service restart.
pub struct CmdlineCollector {
    rx: Receiver<CapturedCmdline>,
    health: Arc<EtwHealth>,
    session_name: Vec<u16>,
    control_handle: CONTROLTRACE_HANDLE,
    worker: Option<JoinHandle<()>>,
}

unsafe impl Send for CmdlineCollector {}
unsafe impl Sync for CmdlineCollector {}

impl CmdlineCollector {
    /// Starts the command-line session. Fails soft for the caller's
    /// purposes: the system-logger pool is only eight sessions machine-wide,
    /// and an exhausted pool surfaces here as an error the runtime logs
    /// before reporting `cmdlineSessionActive = false`.
    pub fn start() -> Result<Self> {
        let session_name = wide_session_name(CMDLINE_SESSION_NAME);
        let (tx, rx) = bounded(CMDLINE_EVENT_CAPACITY);
        let health = Arc::new(EtwHealth::default());
        let state = Arc::new(CmdlineCallbackState {
            tx,
            health: Arc::clone(&health),
        });
        let worker_name = session_name.clone();
        let (initialized_tx, initialized_rx) = mpsc::sync_channel::<Result<u64>>(1);
        let worker = thread::Builder::new()
            .name("pcpulse-etw-cmdline".into())
            .spawn(move || match run_cmdline_trace(&worker_name, state) {
                Ok((control, processing, context)) => {
                    let _ = initialized_tx.send(Ok(control.Value));
                    unsafe {
                        let _ = ProcessTrace(&[processing], None, None);
                        let _ = CloseTrace(processing);
                        drop(Arc::from_raw(context));
                    }
                }
                Err(error) => {
                    let _ = initialized_tx.send(Err(error));
                }
            })?;
        let control_value = initialized_rx.recv().map_err(|_| {
            anyhow::anyhow!("command-line ETW worker exited during initialization")
        })??;
        Ok(Self {
            rx,
            health,
            session_name,
            control_handle: CONTROLTRACE_HANDLE {
                Value: control_value,
            },
            worker: Some(worker),
        })
    }

    /// Loss/integrity counters for this session, same semantics (and same
    /// restart caveat) as [`EtwCollector::health`]. Only `dropped_channel`
    /// and `malformed_events` are populated here: this session is never
    /// queried for `EventsLost`.
    pub fn health(&self) -> &Arc<EtwHealth> {
        &self.health
    }

    /// Drains everything captured since the last call. Never blocks.
    pub fn take_cmdlines(&self) -> Vec<CapturedCmdline> {
        self.rx.try_iter().collect()
    }
}

impl Drop for CmdlineCollector {
    fn drop(&mut self) {
        // A failed stop here costs one of the machine's eight system-logger
        // slots until the next start reclaims the name, so it is said out
        // loud rather than discarded.
        let status = stop_session(self.control_handle, &self.session_name);
        if status != ERROR_SUCCESS {
            eprintln!(
                "stopping the command-line ETW session returned 0x{:08x}; it may be left \
                 holding a system-logger slot until the next start reclaims it",
                status.0
            );
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn run_cmdline_trace(
    name: &[u16],
    state: Arc<CmdlineCallbackState>,
) -> Result<(
    CONTROLTRACE_HANDLE,
    PROCESSTRACE_HANDLE,
    *const CmdlineCallbackState,
)> {
    // A failure here (typically `windows::Win32::Foundation::ERROR_NO_SYSTEM_RESOURCES`: the eight-slot
    // system-logger pool is full) is reported to the caller, which logs it and
    // reports the session as inactive rather than failing the sample. An
    // orphan of this same name left by a killed instance is reclaimed rather
    // than counted against that pool forever.
    let control = start_trace_reclaiming_stale(name, system_property_buffer)?;
    // A system logger's providers come from EnableFlags at start time, so
    // there is no EnableTraceEx2 step here.

    let context = Arc::into_raw(state) as *mut core::ffi::c_void;
    let mut logfile = EVENT_TRACE_LOGFILEW {
        LoggerName: PWSTR(name.as_ptr() as *mut u16),
        Anonymous1: windows::Win32::System::Diagnostics::Etw::EVENT_TRACE_LOGFILEW_0 {
            ProcessTraceMode: PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD,
        },
        Anonymous2: windows::Win32::System::Diagnostics::Etw::EVENT_TRACE_LOGFILEW_1 {
            EventRecordCallback: Some(cmdline_record_callback),
        },
        Context: context,
        ..Default::default()
    };
    let processing = unsafe { OpenTraceW(&mut logfile) };
    if processing == PROCESSTRACE_HANDLE::default() || processing.Value == u64::MAX {
        unsafe {
            drop(Arc::from_raw(context.cast::<CmdlineCallbackState>()));
        }
        let stop_status = stop_session_by_name(name);
        bail!(
            "OpenTraceW failed for the command-line session (teardown stop returned 0x{:08x})",
            stop_status.0
        );
    }
    Ok((control, processing, context.cast::<CmdlineCallbackState>()))
}

unsafe extern "system" fn cmdline_record_callback(record: *mut EVENT_RECORD) {
    if record.is_null() {
        return;
    }
    unsafe {
        let event = &*record;
        let Some(state) = (event.UserContext as *const CmdlineCallbackState).as_ref() else {
            return;
        };
        if event.EventHeader.ProviderId != PROCESS_MOF_GUID
            || event.EventHeader.EventDescriptor.Opcode != PROCESS_MOF_START_OPCODE
        {
            return;
        }
        if event.UserData.is_null() {
            state
                .health
                .malformed_events
                .fetch_add(1, Ordering::Relaxed);
            return;
        }
        let payload =
            std::slice::from_raw_parts(event.UserData.cast::<u8>(), event.UserDataLength as usize);
        let pointer_size = if event.EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER as u16 != 0
        {
            4
        } else {
            8
        };
        match parse_mof_process_start(
            payload,
            pointer_size,
            event.EventHeader.EventDescriptor.Version,
        ) {
            Some(parsed) => state.offer(CapturedCmdline {
                pid: parsed.pid,
                start_ms: crate::etw_props::filetime_to_epoch_ms(
                    event.EventHeader.TimeStamp as u64,
                ),
                command_line: parsed.command_line,
            }),
            None => {
                state
                    .health
                    .malformed_events
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// Property buffer for a *system logger* session: same layout as
/// [`property_buffer`], plus `EVENT_TRACE_SYSTEM_LOGGER_MODE` and the kernel
/// `EnableFlags` that select which kernel providers the session carries.
///
/// The name is this service's own (`PcPulse-Cmdline-<pid>`), not
/// `NT Kernel Logger`: since Windows 8 a process may run its own
/// system-logger session, of which the machine supports eight in total.
/// `Wnode.Guid` is deliberately left zeroed -- setting it to
/// `SystemTraceControlGuid` is what asks for the single, global NT Kernel
/// Logger instead.
fn system_property_buffer(name: &[u16]) -> Vec<u64> {
    let mut buffer = property_buffer(name);
    let properties = unsafe { &mut *buffer.as_mut_ptr().cast::<EVENT_TRACE_PROPERTIES>() };
    properties.LogFileMode = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE;
    properties.EnableFlags = EVENT_TRACE_FLAG_PROCESS;
    buffer
}

/// What this module needs out of a classic `Process_TypeGroup1` payload.
///
/// Like [`CapturedCmdline`], `Debug` elides the command line: it is still raw
/// and unredacted at this point, and a derived `Debug` is exactly how such a
/// line ends up in a log or a panic message.
#[derive(PartialEq)]
struct MofProcessStart {
    pid: u32,
    command_line: String,
}

impl std::fmt::Debug for MofProcessStart {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MofProcessStart")
            .field("pid", &self.pid)
            .field("command_line", &"‹elided›")
            .finish()
    }
}

/// Parses a classic MOF `Process_TypeGroup1` start payload.
///
/// MOF events carry no per-property metadata: the layout is fixed, and its
/// field offsets depend on the *emitting* process's pointer size and on the
/// event version. Anything unexpected -- an unsupported version, a truncated
/// payload, a malformed SID, an unterminated string -- returns `None` so the
/// caller can count it as malformed rather than guess at bytes.
///
/// ```text
/// v2:  ptr PageDirectoryBase | u32 pid | u32 ppid | u32 session | i32 exit
///      | SID | ANSI ImageFileName | UTF-16 CommandLine
/// v3:  ptr UniqueProcessKey  | u32 pid | u32 ppid | u32 session | i32 exit
///      | ptr DirectoryTableBase | SID | ANSI ImageFileName | UTF-16 CommandLine
/// v4+: v3 with a u32 Flags between DirectoryTableBase and the SID
///      (trailing fields after CommandLine are irrelevant here).
/// ```
fn parse_mof_process_start(
    payload: &[u8],
    pointer_size: usize,
    version: u8,
) -> Option<MofProcessStart> {
    // Only the layouts documented above are parsed. A future version could
    // insert a field anywhere ahead of `CommandLine`, and parsing it as v4
    // would not fail loudly -- it would hand back plausible-looking garbage.
    // An unknown version is counted as malformed instead.
    if !(2..=4).contains(&version) {
        return None;
    }
    // PageDirectoryBase (v2) / UniqueProcessKey (v3+).
    let mut offset = pointer_size;
    let pid = read_u32_at(payload, offset)?;
    // ProcessId, ParentId, SessionId, ExitStatus.
    offset = offset.checked_add(16)?;
    if version >= 3 {
        offset = offset.checked_add(pointer_size)?; // DirectoryTableBase
    }
    if version >= 4 {
        offset = offset.checked_add(4)?; // Flags
    }
    offset = skip_sid(payload, offset, pointer_size)?;
    offset = skip_ansi_string(payload, offset)?; // ImageFileName
    let command_line = read_wide_string_at(payload, offset)?;
    Some(MofProcessStart { pid, command_line })
}

fn read_u32_at(payload: &[u8], offset: usize) -> Option<u32> {
    let bytes: [u8; 4] = payload
        .get(offset..offset.checked_add(4)?)?
        .try_into()
        .ok()?;
    Some(u32::from_ne_bytes(bytes))
}

/// Skips the variable-length `UserSID` field, returning the offset just past
/// it. An absent SID is encoded as a single 4-byte zero; a present one is a
/// `TOKEN_USER` (a pointer-sized pair) followed by the `SID` itself, whose
/// length is `8 + 4 * SubAuthorityCount`.
fn skip_sid(payload: &[u8], offset: usize, pointer_size: usize) -> Option<usize> {
    if read_u32_at(payload, offset)? == 0 {
        return offset.checked_add(4);
    }
    let sid = offset.checked_add(pointer_size.checked_mul(2)?)?;
    let revision = *payload.get(sid)?;
    let sub_authority_count = *payload.get(sid.checked_add(1)?)?;
    // A SID always has revision 1 and at most 15 sub-authorities; anything
    // else means the offsets are wrong and the rest of the parse would be
    // fiction.
    if revision != 1 || sub_authority_count > 15 {
        return None;
    }
    let end = sid.checked_add(8 + 4 * sub_authority_count as usize)?;
    (end <= payload.len()).then_some(end)
}

/// Skips a NUL-terminated ANSI string, returning the offset just past its
/// terminator, or `None` if the payload ends without one.
fn skip_ansi_string(payload: &[u8], offset: usize) -> Option<usize> {
    let rest = payload.get(offset..)?;
    let nul = rest.iter().position(|&byte| byte == 0)?;
    offset.checked_add(nul)?.checked_add(1)
}

/// Reads a NUL-terminated UTF-16LE string at `offset`, byte-pair by byte-pair
/// so an odd (unaligned) offset is safe. `None` if the payload ends without a
/// terminator -- a truncated command line is dropped, never half-reported.
fn read_wide_string_at(payload: &[u8], offset: usize) -> Option<String> {
    let rest = payload.get(offset..)?;
    let mut units: Vec<u16> = Vec::new();
    for chunk in rest.chunks_exact(2) {
        let unit = u16::from_ne_bytes([chunk[0], chunk[1]]);
        if unit == 0 {
            return Some(String::from_utf16_lossy(&units));
        }
        units.push(unit);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::etw_props::ProcessStopProps;

    #[test]
    fn channel_full_increments_dropped_and_keeps_collector_alive() {
        let (queue, sink) = EtwProcessQueue::new_for_test(4);
        for pid in 0..10 {
            sink.offer(ParsedProcessEvent::Stop(ProcessStopProps {
                pid,
                exit_code: 0,
            }));
        }
        assert_eq!(queue.health().dropped_channel.load(Ordering::Relaxed), 6);
        assert_eq!(queue.take_process_events().len(), 4);
        assert_eq!(queue.take_process_events().len(), 0);
    }

    #[test]
    fn drains_in_order_and_drops_nothing_below_capacity() {
        let (queue, sink) = EtwProcessQueue::new_for_test(4);
        for pid in [7, 8, 9] {
            sink.offer(ParsedProcessEvent::Stop(ProcessStopProps {
                pid,
                exit_code: pid,
            }));
        }
        let drained = queue.take_process_events();
        assert_eq!(queue.health().dropped_channel.load(Ordering::Relaxed), 0);
        assert_eq!(
            drained,
            vec![
                ParsedProcessEvent::Stop(ProcessStopProps {
                    pid: 7,
                    exit_code: 7
                }),
                ParsedProcessEvent::Stop(ProcessStopProps {
                    pid: 8,
                    exit_code: 8
                }),
                ParsedProcessEvent::Stop(ProcessStopProps {
                    pid: 9,
                    exit_code: 9
                }),
            ]
        );
    }

    #[test]
    fn control_buffer_reserves_room_for_both_names_etw_writes_back() {
        // Both control codes this buffer serves -- QUERY and STOP -- make ETW
        // write the names back, so an under-sized buffer breaks the
        // events-lost query *and* the stale-session stop.
        let name: Vec<u16> = "PcPulse-1234".encode_utf16().chain(Some(0)).collect();
        let mut buffer = control_property_buffer(&name);
        let struct_bytes = size_of::<EVENT_TRACE_PROPERTIES>();
        let slot_bytes = QUERY_NAME_SLOT_CHARS * size_of::<u16>();
        let properties = unsafe { &*buffer.as_mut_ptr().cast::<EVENT_TRACE_PROPERTIES>() };
        // BufferSize must cover the struct plus both name slots, and the
        // allocation must actually be at least that large — an under-sized
        // buffer is what makes ETW either reject the query or write past the
        // end of the Vec.
        assert_eq!(
            properties.Wnode.BufferSize as usize,
            struct_bytes + 2 * slot_bytes
        );
        assert!(std::mem::size_of_val(&buffer[..]) >= properties.Wnode.BufferSize as usize);
        assert_eq!(properties.LoggerNameOffset as usize, struct_bytes);
        assert_eq!(
            properties.LogFileNameOffset as usize,
            struct_bytes + slot_bytes
        );
        // Both name slots must lie entirely inside the allocation.
        assert!(
            properties.LogFileNameOffset as usize + slot_bytes
                <= std::mem::size_of_val(&buffer[..])
        );
    }

    // -- classic MOF Process_TypeGroup1 payload parsing --------------------

    /// Builds a synthetic `Process_TypeGroup1` payload the way the kernel
    /// lays one out, so the offset arithmetic is exercised without a live
    /// kernel session.
    fn mof_payload(
        pointer_size: usize,
        version: u8,
        pid: u32,
        image: &str,
        command_line: &str,
        with_sid: bool,
    ) -> Vec<u8> {
        let mut payload = vec![0u8; pointer_size]; // UniqueProcessKey
        payload.extend_from_slice(&pid.to_ne_bytes());
        payload.extend_from_slice(&7u32.to_ne_bytes()); // ParentId
        payload.extend_from_slice(&1u32.to_ne_bytes()); // SessionId
        payload.extend_from_slice(&0u32.to_ne_bytes()); // ExitStatus
        if version >= 3 {
            payload.extend_from_slice(&vec![0u8; pointer_size]); // DirectoryTableBase
        }
        if version >= 4 {
            payload.extend_from_slice(&0u32.to_ne_bytes()); // Flags
        }
        if with_sid {
            // TOKEN_USER (pointer-sized pair), then a 3-sub-authority SID.
            payload.extend_from_slice(&vec![0x11u8; pointer_size * 2]);
            payload.push(1); // Revision
            payload.push(3); // SubAuthorityCount
            payload.extend_from_slice(&[0, 0, 0, 0, 0, 5]); // IdentifierAuthority
            payload.extend_from_slice(&[0u8; 12]); // three sub-authorities
        } else {
            payload.extend_from_slice(&0u32.to_ne_bytes()); // empty-SID encoding
        }
        payload.extend_from_slice(image.as_bytes());
        payload.push(0);
        for unit in command_line.encode_utf16() {
            payload.extend_from_slice(&unit.to_ne_bytes());
        }
        payload.extend_from_slice(&0u16.to_ne_bytes());
        payload
    }

    #[test]
    fn mof_start_parses_pid_and_command_line_across_versions_and_pointer_sizes() {
        for pointer_size in [4usize, 8] {
            for version in [2u8, 3, 4] {
                for with_sid in [true, false] {
                    let payload = mof_payload(
                        pointer_size,
                        version,
                        4242,
                        "notepad.exe",
                        r#"notepad.exe "c:\a b\notes.txt""#,
                        with_sid,
                    );
                    let parsed = parse_mof_process_start(&payload, pointer_size, version)
                        .unwrap_or_else(|| {
                            panic!("v{version} ptr{pointer_size} sid={with_sid} failed to parse")
                        });
                    assert_eq!(parsed.pid, 4242);
                    assert_eq!(parsed.command_line, r#"notepad.exe "c:\a b\notes.txt""#);
                }
            }
        }
    }

    #[test]
    fn mof_start_rejects_truncation_at_every_length_without_panicking() {
        let full = mof_payload(8, 4, 99, "x.exe", "x.exe --go", true);
        for length in 0..full.len() {
            // Every prefix is malformed (the command line's terminator is the
            // last thing in the payload) and must be refused, not guessed at.
            assert!(
                parse_mof_process_start(&full[..length], 8, 4).is_none(),
                "prefix of length {length} was accepted"
            );
        }
        assert!(parse_mof_process_start(&full, 8, 4).is_some());
    }

    #[test]
    fn mof_start_rejects_unsupported_versions_and_bogus_sids() {
        let payload = mof_payload(8, 4, 1, "x.exe", "x", true);
        assert!(parse_mof_process_start(&payload, 8, 1).is_none());
        // A version past the layouts documented here is refused rather than
        // parsed as v4 and quietly mis-read.
        assert!(parse_mof_process_start(&payload, 8, 5).is_none());
        assert!(parse_mof_process_start(&payload, 8, 9).is_none());

        // Corrupt the SID revision byte: the rest of the layout would be
        // fiction, so the event is refused rather than mis-parsed.
        let mut corrupt = payload.clone();
        let sid_revision = 8 + 16 + 8 + 4 + 16;
        corrupt[sid_revision] = 9;
        assert!(parse_mof_process_start(&corrupt, 8, 4).is_none());
    }

    #[test]
    fn mof_start_with_empty_command_line_parses_as_empty_not_missing() {
        let payload = mof_payload(8, 4, 7, "svc.exe", "", true);
        let parsed = parse_mof_process_start(&payload, 8, 4).unwrap();
        assert_eq!(parsed.pid, 7);
        assert_eq!(parsed.command_line, "");
    }

    #[test]
    fn session_names_are_fixed_so_an_orphan_is_reclaimable() {
        // A pid in the name would mean a killed instance's session is never
        // found again by the next run -- and for the system logger, one of
        // the machine's eight slots gone until reboot.
        let pid = std::process::id().to_string();
        for name in [PROCESS_SESSION_NAME, CMDLINE_SESSION_NAME] {
            assert!(!name.contains(&pid), "{name} embeds the process id");
            assert!(
                !name.chars().any(|character| character.is_ascii_digit()),
                "{name} looks process-specific"
            );
        }
        assert_ne!(PROCESS_SESSION_NAME, CMDLINE_SESSION_NAME);
        // NUL-terminated, as every PCWSTR session name must be.
        assert_eq!(wide_session_name(CMDLINE_SESSION_NAME).last(), Some(&0));
    }

    #[test]
    fn an_already_existing_session_name_asks_for_a_reclaim_not_a_failure() {
        assert_eq!(
            classify_start_status(ERROR_ALREADY_EXISTS),
            StartOutcome::ReclaimStale
        );
        assert_eq!(classify_start_status(ERROR_SUCCESS), StartOutcome::Started);
        assert_eq!(
            classify_start_status(windows::Win32::Foundation::ERROR_NO_SYSTEM_RESOURCES),
            StartOutcome::Failed(windows::Win32::Foundation::ERROR_NO_SYSTEM_RESOURCES),
            "a full system-logger pool is a real failure, not a stale session"
        );
    }

    #[test]
    fn system_property_buffer_requests_a_process_system_logger() {
        let name: Vec<u16> = "PcPulse-Cmdline-1".encode_utf16().chain(Some(0)).collect();
        let mut buffer = system_property_buffer(&name);
        let properties = unsafe { &*buffer.as_mut_ptr().cast::<EVENT_TRACE_PROPERTIES>() };
        assert_eq!(
            properties.LogFileMode,
            EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE
        );
        assert_eq!(properties.EnableFlags, EVENT_TRACE_FLAG_PROCESS);
        // Never the global NT Kernel Logger: that is what a
        // SystemTraceControlGuid here would ask for.
        assert_eq!(properties.Wnode.Guid, GUID::zeroed());
    }

    #[test]
    #[ignore = "dev harness: starts a real ETW session on this machine and asserts EVENT_TRACE_CONTROL_QUERY succeeds; requires elevation"]
    fn dev_probe_real_events_lost_query() {
        let collector = EtwCollector::start().expect("ETW session start requires elevation");
        let events_lost = collector
            .query_events_lost()
            .unwrap_or_else(|status| panic!("QUERY failed with status 0x{:08x}", status.0));
        println!("events lost: {events_lost}");
        collector.snapshot();
        assert_eq!(
            collector
                .health()
                .events_lost_query_failures
                .load(Ordering::Relaxed),
            0
        );
    }
}
