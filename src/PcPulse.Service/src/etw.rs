use anyhow::{Result, bail};
use chrono::Utc;
use std::{
    collections::HashMap,
    mem::size_of,
    ptr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
    time::Instant,
};
use windows::{
    Win32::{
        Foundation::{ERROR_SUCCESS, WIN32_ERROR},
        System::Diagnostics::Etw::{
            CONTROLTRACE_HANDLE, CloseTrace, ControlTraceW, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
            EVENT_RECORD, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES,
            EVENT_TRACE_REAL_TIME_MODE, EnableTraceEx2, OpenTraceW,
            PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME, PROCESSTRACE_HANDLE,
            ProcessTrace, StartTraceW, TRACE_LEVEL_INFORMATION, WNODE_FLAG_TRACED_GUID,
        },
    },
    core::{GUID, PCWSTR, PWSTR},
};

// Microsoft-Windows-Kernel-Process. The process keyword keeps the session low-volume;
// high-frequency CPU and I/O values are deliberately obtained from PDH/Win32 instead.
const KERNEL_PROCESS_PROVIDER: GUID = GUID::from_u128(0x22fb2cd6_0e7b_422b_a0c7_2fad1fd0e716);
const PROCESS_KEYWORD: u64 = 0x10;
const PROCESS_START_EVENT_ID: u16 = 1;

#[derive(Debug, Clone, Default)]
pub struct EtwSnapshot {
    pub active: bool,
    pub events_per_sec: f64,
    pub dropped_events: u64,
    pub process_starts: HashMap<u32, i64>,
}

#[derive(Default)]
struct CallbackState {
    event_count: AtomicU64,
    dropped_events: AtomicU64,
    process_starts: Mutex<HashMap<u32, i64>>,
}

struct SampleState {
    count: u64,
    at: Instant,
}

pub struct EtwCollector {
    callback: Arc<CallbackState>,
    sample: Mutex<SampleState>,
    session_name: Vec<u16>,
    control_handle: CONTROLTRACE_HANDLE,
    worker: Option<JoinHandle<()>>,
}

unsafe impl Send for EtwCollector {}
unsafe impl Sync for EtwCollector {}

impl EtwCollector {
    pub fn start() -> Result<Self> {
        let session = format!("PcPulse-{}", std::process::id());
        let session_name: Vec<u16> = session.encode_utf16().chain(Some(0)).collect();
        let callback = Arc::new(CallbackState::default());
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
            sample: Mutex::new(SampleState {
                count: 0,
                at: Instant::now(),
            }),
            session_name,
            control_handle: CONTROLTRACE_HANDLE {
                Value: control_value,
            },
            worker: Some(worker),
        })
    }

    pub fn snapshot(&self) -> EtwSnapshot {
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
            dropped_events: self.callback.dropped_events.load(Ordering::Relaxed),
            process_starts,
        }
    }
}

impl Drop for EtwCollector {
    fn drop(&mut self) {
        let mut properties = property_buffer(&self.session_name);
        unsafe {
            let _ = ControlTraceW(
                self.control_handle,
                PCWSTR(self.session_name.as_ptr()),
                properties.as_mut_ptr().cast::<EVENT_TRACE_PROPERTIES>(),
                EVENT_TRACE_CONTROL_STOP,
            );
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn run_trace(
    name: &[u16],
    state: Arc<CallbackState>,
) -> Result<(
    CONTROLTRACE_HANDLE,
    PROCESSTRACE_HANDLE,
    *const CallbackState,
)> {
    let mut properties = property_buffer(name);
    let properties_ptr = properties.as_mut_ptr().cast::<EVENT_TRACE_PROPERTIES>();
    let mut control = CONTROLTRACE_HANDLE::default();
    let status = unsafe { StartTraceW(&mut control, PCWSTR(name.as_ptr()), properties_ptr) };
    if status != ERROR_SUCCESS {
        bail!("StartTraceW failed with status 0x{:08x}", status.0);
    }
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
        unsafe {
            let _ = ControlTraceW(
                control,
                PCWSTR(name.as_ptr()),
                properties_ptr,
                EVENT_TRACE_CONTROL_STOP,
            );
        }
        bail!(
            "EnableTraceEx2 failed with status 0x{:08x}",
            enable_status.0
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
            let _ = ControlTraceW(
                control,
                PCWSTR(name.as_ptr()),
                properties_ptr,
                EVENT_TRACE_CONTROL_STOP,
            );
        }
        bail!("OpenTraceW failed");
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

fn _status_is_success(status: WIN32_ERROR) -> bool {
    status == ERROR_SUCCESS
}
