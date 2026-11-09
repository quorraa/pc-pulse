use crate::{
    config::Settings,
    etw::EtwSnapshot,
    models::{ProcessMetric, SystemMetric},
};
use anyhow::{Result, bail};
use std::{
    collections::{HashMap, HashSet},
    mem::size_of,
};
use windows::{
    Win32::{
        Foundation::{CloseHandle, FILETIME, HWND, LPARAM},
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
                TH32CS_SNAPPROCESS,
            },
            ProcessStatus::{
                GetPerformanceInfo, GetProcessMemoryInfo, PERFORMANCE_INFORMATION,
                PROCESS_MEMORY_COUNTERS, PROCESS_MEMORY_COUNTERS_EX,
            },
            RemoteDesktop::ProcessIdToSessionId,
            SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX},
            Threading::{
                GetProcessHandleCount, GetProcessIoCounters, GetProcessTimes, IO_COUNTERS,
                OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
                PROCESS_TERMINATE, QueryFullProcessImageNameW, TerminateProcess,
            },
        },
        UI::WindowsAndMessaging::{
            EnumWindows, GetWindowThreadProcessId, IsHungAppWindow, IsWindowVisible,
        },
    },
    core::PWSTR,
};

const FILETIME_UNIX_EPOCH_100NS: u64 = 116_444_736_000_000_000;

#[derive(Debug, Clone)]
struct PreviousProcess {
    cpu_ticks: u64,
    read_bytes: u64,
    write_bytes: u64,
    started_at_ms: i64,
    metadata: Option<ProcessMetadata>,
}

#[derive(Debug, Clone)]
struct ProcessMetadata {
    identity_start_time_ms: i64,
    path: String,
    session_id: u32,
}

impl ProcessMetadata {
    fn from_query(
        identity_start_time_ms: Option<i64>,
        path: &str,
        session_id: Option<u32>,
    ) -> Option<Self> {
        if path.is_empty() {
            return None;
        }
        Some(Self {
            identity_start_time_ms: identity_start_time_ms?,
            path: path.to_owned(),
            session_id: session_id?,
        })
    }

    fn matches(&self, identity_start_time_ms: Option<i64>) -> bool {
        // A reused PID or unavailable identity must never inherit old data.
        identity_start_time_ms == Some(self.identity_start_time_ms) && !self.path.is_empty()
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct WindowState {
    visible: bool,
    responsive: bool,
}

#[derive(Default)]
pub struct ProcessCollector {
    previous: HashMap<u32, PreviousProcess>,
    ready_at: HashMap<(u32, i64), i64>,
}

impl ProcessCollector {
    pub fn collect(
        &mut self,
        timestamp_ms: i64,
        elapsed_seconds: f64,
        settings: &Settings,
        etw: &EtwSnapshot,
    ) -> Result<Vec<ProcessMetric>> {
        let windows = enumerate_windows();
        let logical_processors =
            std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get) as f64;
        let agent_patterns: Vec<String> = settings
            .agent_process_patterns
            .iter()
            .map(|pattern| pattern.trim().to_ascii_lowercase())
            .filter(|pattern| !pattern.is_empty())
            .collect();
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)? };
        let mut entry = PROCESSENTRY32W {
            dwSize: size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        let mut result = Vec::with_capacity(256);
        if unsafe { Process32FirstW(snapshot, &mut entry) }.is_ok() {
            loop {
                if let Some(metric) = self.read_process(
                    &entry,
                    timestamp_ms,
                    elapsed_seconds,
                    &agent_patterns,
                    logical_processors,
                    etw,
                    &windows,
                ) {
                    result.push(metric);
                }
                if unsafe { Process32NextW(snapshot, &mut entry) }.is_err() {
                    break;
                }
            }
        }
        unsafe {
            let _ = CloseHandle(snapshot);
        }
        let live: HashSet<(u32, i64)> = result
            .iter()
            .map(|process| (process.pid, process.started_at_ms))
            .collect();
        self.previous
            .retain(|pid, previous| live.contains(&(*pid, previous.started_at_ms)));
        self.ready_at.retain(|identity, _| live.contains(identity));
        Ok(result)
    }

    #[allow(clippy::too_many_arguments)]
    fn read_process(
        &mut self,
        entry: &PROCESSENTRY32W,
        timestamp_ms: i64,
        elapsed_seconds: f64,
        agent_patterns: &[String],
        logical_processors: f64,
        etw: &EtwSnapshot,
        windows: &HashMap<u32, WindowState>,
    ) -> Option<ProcessMetric> {
        let pid = entry.th32ProcessID;
        if pid == 0 {
            return None;
        }
        let name = wide_z_to_string(&entry.szExeFile);
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
        let mut creation = FILETIME::default();
        let mut exit = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        let times_ok =
            unsafe { GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) }
                .is_ok();
        let started_at_ms = if times_ok {
            filetime_to_unix_ms(creation)
        } else {
            etw.process_starts
                .get(&pid)
                .copied()
                .unwrap_or(timestamp_ms)
        };
        // Cache metadata only when Windows verified this exact process instance.
        let identity_start_time_ms = times_ok.then_some(started_at_ms);
        let cpu_ticks = filetime_ticks(kernel).saturating_add(filetime_ticks(user));
        let mut memory = PROCESS_MEMORY_COUNTERS_EX {
            cb: size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32,
            ..Default::default()
        };
        let _ = unsafe {
            GetProcessMemoryInfo(
                handle,
                (&mut memory as *mut PROCESS_MEMORY_COUNTERS_EX).cast::<PROCESS_MEMORY_COUNTERS>(),
                size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32,
            )
        };
        let mut io = IO_COUNTERS::default();
        let _ = unsafe { GetProcessIoCounters(handle, &mut io) };
        let mut handles = 0;
        let _ = unsafe { GetProcessHandleCount(handle, &mut handles) };
        // These values are immutable for a process instance. Avoid repeated
        // path/session syscalls for every live process on every sample.
        let cached = self
            .previous
            .get(&pid)
            .and_then(|previous| previous.metadata.as_ref())
            .filter(|metadata| metadata.matches(identity_start_time_ms));
        let (path, session_id) = if let Some(metadata) = cached {
            (metadata.path.clone(), Some(metadata.session_id))
        } else {
            let mut path_buffer = [0u16; 1024];
            let mut path_len = path_buffer.len() as u32;
            let path = if unsafe {
                QueryFullProcessImageNameW(
                    handle,
                    PROCESS_NAME_WIN32,
                    PWSTR(path_buffer.as_mut_ptr()),
                    &mut path_len,
                )
            }
            .is_ok()
            {
                String::from_utf16_lossy(&path_buffer[..path_len as usize])
            } else {
                String::new()
            };
            let mut session_id = 0;
            let session_id = unsafe { ProcessIdToSessionId(pid, &mut session_id) }
                .ok()
                .map(|()| session_id);
            (path, session_id)
        };
        unsafe {
            let _ = CloseHandle(handle);
        }

        let current = PreviousProcess {
            cpu_ticks,
            read_bytes: io.ReadTransferCount,
            write_bytes: io.WriteTransferCount,
            started_at_ms,
            metadata: ProcessMetadata::from_query(identity_start_time_ms, &path, session_id),
        };
        let previous = self
            .previous
            .insert(pid, current)
            .filter(|old| old.started_at_ms == started_at_ms);
        let cpu_percent = previous.as_ref().map_or(0.0, |old| {
            let cpu_seconds = cpu_ticks.saturating_sub(old.cpu_ticks) as f64 / 10_000_000.0;
            (cpu_seconds / elapsed_seconds / logical_processors * 100.0).clamp(0.0, 100.0)
        });
        let read_rate = previous.as_ref().map_or(0.0, |old| {
            io.ReadTransferCount.saturating_sub(old.read_bytes) as f64 / elapsed_seconds
        });
        let write_rate = previous.as_ref().map_or(0.0, |old| {
            io.WriteTransferCount.saturating_sub(old.write_bytes) as f64 / elapsed_seconds
        });
        let window = windows.get(&pid).copied().unwrap_or_default();
        let identity = (pid, started_at_ms);
        let launch_duration_ms = if window.visible {
            let ready = *self.ready_at.entry(identity).or_insert(timestamp_ms);
            let observed_start = etw
                .process_starts
                .get(&pid)
                .copied()
                .unwrap_or(started_at_ms);
            let duration = ready.saturating_sub(observed_start).max(0) as u64;
            // Ignore processes that predate this service run and therefore have no ETW start.
            etw.process_starts.contains_key(&pid).then_some(duration)
        } else {
            None
        };
        let lowered = format!(
            "{} {}",
            name.to_ascii_lowercase(),
            path.to_ascii_lowercase()
        );
        let is_agent_candidate = agent_patterns
            .iter()
            .any(|pattern| lowered.contains(pattern));
        Some(ProcessMetric {
            timestamp_ms,
            pid,
            parent_pid: entry.th32ParentProcessID,
            name,
            executable_path: path,
            cpu_percent,
            working_set_bytes: memory.WorkingSetSize as u64,
            private_bytes: memory.PrivateUsage as u64,
            handle_count: handles,
            thread_count: entry.cntThreads,
            read_bytes_per_sec: read_rate,
            write_bytes_per_sec: write_rate,
            total_read_bytes: io.ReadTransferCount,
            total_write_bytes: io.WriteTransferCount,
            started_at_ms,
            session_id: session_id.unwrap_or(0),
            responsive: !window.visible || window.responsive,
            has_visible_window: window.visible,
            launch_duration_ms,
            is_agent_candidate,
        })
    }
}

/// `(total, used)` physical memory in bytes — one `GlobalMemoryStatusEx`
/// call, shared by the 2-second snapshot and the high-rate live sampler.
pub(super) fn physical_memory() -> Result<(u64, u64)> {
    let mut memory = MEMORYSTATUSEX {
        dwLength: size_of::<MEMORYSTATUSEX>() as u32,
        ..Default::default()
    };
    unsafe {
        GlobalMemoryStatusEx(&mut memory)?;
    }
    Ok((
        memory.ullTotalPhys,
        memory.ullTotalPhys.saturating_sub(memory.ullAvailPhys),
    ))
}

pub fn system_metric(timestamp_ms: i64) -> Result<SystemMetric> {
    let (memory_total_bytes, memory_used_bytes) = physical_memory()?;
    let mut performance = PERFORMANCE_INFORMATION {
        cb: size_of::<PERFORMANCE_INFORMATION>() as u32,
        ..Default::default()
    };
    unsafe {
        GetPerformanceInfo(
            &mut performance,
            size_of::<PERFORMANCE_INFORMATION>() as u32,
        )?;
    }
    Ok(SystemMetric {
        timestamp_ms,
        memory_total_bytes,
        memory_used_bytes,
        paged_pool_bytes: performance.KernelPaged.saturating_mul(performance.PageSize) as u64,
        nonpaged_pool_bytes: performance
            .KernelNonpaged
            .saturating_mul(performance.PageSize) as u64,
        process_count: performance.ProcessCount,
        thread_count: performance.ThreadCount,
        handle_count: performance.HandleCount,
        ..SystemMetric::default()
    })
}

pub fn terminate_process(pid: u32, confirmed: bool) -> Result<()> {
    if !confirmed {
        bail!("termination requires explicit confirmation");
    }
    if pid == 0 || pid == 4 || pid == std::process::id() {
        bail!("refusing to terminate a protected or collector process");
    }
    let handle = unsafe { OpenProcess(PROCESS_TERMINATE, false, pid) }?;
    let result = unsafe { TerminateProcess(handle, 1) };
    unsafe {
        let _ = CloseHandle(handle);
    }
    result?;
    Ok(())
}

fn enumerate_windows() -> HashMap<u32, WindowState> {
    unsafe extern "system" fn callback(hwnd: HWND, lparam: LPARAM) -> windows::core::BOOL {
        unsafe {
            if !IsWindowVisible(hwnd).as_bool() {
                return true.into();
            }
            let mut pid = 0;
            GetWindowThreadProcessId(hwnd, Some(&mut pid));
            if pid != 0 {
                let states = &mut *(lparam.0 as *mut HashMap<u32, WindowState>);
                let state = states.entry(pid).or_default();
                state.visible = true;
                state.responsive |= !IsHungAppWindow(hwnd).as_bool();
            }
            true.into()
        }
    }
    let mut states = HashMap::new();
    unsafe {
        let _ = EnumWindows(
            Some(callback),
            LPARAM((&mut states as *mut HashMap<u32, WindowState>) as isize),
        );
    }
    states
}

fn filetime_ticks(value: FILETIME) -> u64 {
    (u64::from(value.dwHighDateTime) << 32) | u64::from(value.dwLowDateTime)
}

fn filetime_to_unix_ms(value: FILETIME) -> i64 {
    let ticks = filetime_ticks(value);
    ticks
        .saturating_sub(FILETIME_UNIX_EPOCH_100NS)
        .saturating_div(10_000) as i64
}

fn wide_z_to_string(value: &[u16]) -> String {
    let length = value
        .iter()
        .position(|character| *character == 0)
        .unwrap_or(value.len());
    String::from_utf16_lossy(&value[..length])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_cache_requires_verified_same_instance_and_retries_missing_paths() {
        let mut metadata = ProcessMetadata {
            identity_start_time_ms: 100,
            path: r"C:\Windows\test.exe".into(),
            session_id: 1,
        };
        assert!(metadata.matches(Some(100)));
        assert!(
            !metadata.matches(Some(101)),
            "reused PID must be queried again"
        );
        assert!(
            !metadata.matches(None),
            "unverified identity cannot reuse metadata"
        );
        metadata.path.clear();
        assert!(!metadata.matches(Some(100)), "failed paths must be retried");
    }

    #[test]
    fn metadata_cache_retries_failed_session_lookup_but_accepts_session_zero() {
        let path = r"C:\Windows\test.exe";
        assert!(ProcessMetadata::from_query(Some(100), path, None).is_none());
        let recovered = ProcessMetadata::from_query(Some(100), path, Some(0))
            .expect("session zero is valid when the lookup succeeded");
        assert!(recovered.matches(Some(100)));
        assert_eq!(recovered.session_id, 0);
        assert!(ProcessMetadata::from_query(Some(100), "", Some(0)).is_none());
        assert!(ProcessMetadata::from_query(None, path, Some(0)).is_none());
    }

    #[test]
    fn filetime_epoch_is_zero() {
        let value = FILETIME {
            dwLowDateTime: FILETIME_UNIX_EPOCH_100NS as u32,
            dwHighDateTime: (FILETIME_UNIX_EPOCH_100NS >> 32) as u32,
        };
        assert_eq!(filetime_to_unix_ms(value), 0);
    }

    #[test]
    fn refuses_unconfirmed_termination() {
        assert!(terminate_process(1234, false).is_err());
    }
}
