//! Leak forensics for active handle-growth and thread-growth findings.
//!
//! When the detector confirms that a process is leaking handles or threads,
//! this module answers the follow-up question the finding itself cannot:
//! *what kind* of handles grew, and *whose code* is spawning the threads.
//!
//! Privacy boundary: only system metadata is captured — kernel object type
//! names (`Event`, `Section`, …) and module base file names (`xul.dll`).
//! Never command lines, window text, memory content, or handle names.
//!
//! Budget discipline: the engine performs **zero syscalls** while no
//! handle/thread-growth finding is active. While one is active it captures at
//! most once per [`CAPTURE_INTERVAL_MS`], plus one baseline capture when a
//! finding first fires. The multi-megabyte system handle table is bucketed and
//! dropped inside a single call so the collector working set returns
//! immediately, and every process/thread/snapshot handle opened during a pass
//! is closed in the same pass (checked by a debug counter).

use crate::models::{Alert, Evidence};
use anyhow::{Result, bail};
use std::collections::{HashMap, HashSet};
use std::ffi::c_void;
use std::mem::size_of;
use windows::Win32::{
    Foundation::{CloseHandle, HMODULE},
    System::{
        Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First,
            Thread32Next,
        },
        Memory::{MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, VirtualAlloc, VirtualFree},
        ProcessStatus::{
            EnumProcessModulesEx, GetModuleBaseNameW, GetModuleInformation, K32EmptyWorkingSet,
            LIST_MODULES_ALL, MODULEINFO,
        },
        Threading::{
            GetCurrentProcess, OpenProcess, OpenThread, PROCESS_QUERY_LIMITED_INFORMATION,
            PROCESS_VM_READ, THREAD_QUERY_INFORMATION, THREAD_QUERY_LIMITED_INFORMATION,
        },
    },
};

/// Captures run at most this often while a leak finding is active.
pub const CAPTURE_INTERVAL_MS: i64 = 60_000;

const HANDLE_GROWTH_KIND: &str = "handleGrowth";
const THREAD_GROWTH_KIND: &str = "threadGrowth";
const HANDLE_TYPES_LABEL: &str = "Handle types";
const THREAD_MODULES_LABEL: &str = "New-thread modules";
const WINDOW_LABEL: &str = "Forensics window";
const FORENSIC_LABELS: [&str; 3] = [HANDLE_TYPES_LABEL, THREAD_MODULES_LABEL, WINDOW_LABEL];
const UNATTRIBUTED: &str = "unattributed";

/// The syscall layer behind the engine, stubbed in unit tests.
pub trait ForensicsSource {
    /// One pass over the system handle table, bucketed per requested PID as
    /// `type name -> handle count`.
    fn handle_histograms(&mut self, pids: &HashSet<u32>) -> Result<HashMap<u32, HashMap<String, u64>>>;
    /// The live thread IDs owned by `pid`.
    fn thread_ids(&mut self, pid: u32) -> Result<HashSet<u32>>;
    /// The module base name owning each thread's Win32 start address, or
    /// `"unattributed"` where access is denied. Same order as `new_tids`.
    fn thread_start_modules(&mut self, pid: u32, new_tids: &[u32]) -> Vec<String>;
}

#[derive(Debug, Clone)]
struct HandleBaseline {
    captured_at_ms: i64,
    histogram: HashMap<String, u64>,
}

#[derive(Debug, Clone)]
struct ThreadBaseline {
    captured_at_ms: i64,
    tids: HashSet<u32>,
}

/// Holds per-finding baselines and the latest forensic evidence rows.
///
/// Baselines are keyed by alert ID (each handle/thread-growth alert is already
/// unique per process identity); a finding resolving clears its baseline on
/// the next observation pass.
pub struct ForensicsEngine<S> {
    source: S,
    handle_baselines: HashMap<String, HandleBaseline>,
    thread_baselines: HashMap<String, ThreadBaseline>,
    /// Latest rows per alert ID; replaced wholesale by each capture so
    /// evidence stays bounded.
    latest: HashMap<String, Vec<Evidence>>,
    /// Rows for findings that just resolved survive exactly one extra pass so
    /// the resolution write-back keeps its final forensic state.
    stale: HashSet<String>,
    last_capture_ms: Option<i64>,
}

impl<S: ForensicsSource> ForensicsEngine<S> {
    pub fn new(source: S) -> Self {
        Self {
            source,
            handle_baselines: HashMap::new(),
            thread_baselines: HashMap::new(),
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

    /// Drives baselines and captures from the sampling cadence.
    ///
    /// With no active handle/thread-growth findings this returns before any
    /// source call — the engine is a strict no-op.
    pub fn observe(&mut self, active: &[Alert], now_ms: i64) {
        let mut handle_targets: HashMap<String, u32> = HashMap::new();
        let mut thread_targets: HashMap<String, u32> = HashMap::new();
        for alert in active {
            if let Some(pid) = alert.process_id {
                match alert.kind.as_str() {
                    HANDLE_GROWTH_KIND => {
                        handle_targets.insert(alert.id.clone(), pid);
                    }
                    THREAD_GROWTH_KIND => {
                        thread_targets.insert(alert.id.clone(), pid);
                    }
                    _ => {}
                }
            }
        }
        self.handle_baselines
            .retain(|id, _| handle_targets.contains_key(id));
        self.thread_baselines
            .retain(|id, _| thread_targets.contains_key(id));
        // Grace pass: rows for findings that resolved on the *previous* pass
        // are dropped now; findings resolving on this pass keep their final
        // rows for the resolution write-back.
        let is_target =
            |id: &String| handle_targets.contains_key(id) || thread_targets.contains_key(id);
        let stale = &self.stale;
        self.latest
            .retain(|id, _| is_target(id) || !stale.contains(id));
        self.stale = self
            .latest
            .keys()
            .filter(|id| !is_target(id))
            .cloned()
            .collect();

        if handle_targets.is_empty() && thread_targets.is_empty() {
            self.last_capture_ms = None;
            return;
        }
        let due = self
            .last_capture_ms
            .is_none_or(|last| now_ms.saturating_sub(last) >= CAPTURE_INTERVAL_MS);
        let new_handle_pids: HashSet<u32> = handle_targets
            .iter()
            .filter(|(id, _)| !self.handle_baselines.contains_key(*id))
            .map(|(_, pid)| *pid)
            .collect();
        let has_new_threads = thread_targets
            .keys()
            .any(|id| !self.thread_baselines.contains_key(id));
        if !due && new_handle_pids.is_empty() && !has_new_threads {
            return;
        }

        let capture_pids: HashSet<u32> = if due {
            handle_targets.values().copied().collect()
        } else {
            new_handle_pids
        };
        if !capture_pids.is_empty() {
            match self.source.handle_histograms(&capture_pids) {
                Ok(histograms) => {
                    for (id, pid) in &handle_targets {
                        if !capture_pids.contains(pid) {
                            continue;
                        }
                        let current = histograms.get(pid).cloned().unwrap_or_default();
                        if let Some(baseline) = self.handle_baselines.get(id) {
                            self.latest.insert(
                                id.clone(),
                                vec![
                                    evidence(
                                        HANDLE_TYPES_LABEL,
                                        format_handle_deltas(&baseline.histogram, &current),
                                    ),
                                    evidence(
                                        WINDOW_LABEL,
                                        format_window(
                                            now_ms.saturating_sub(baseline.captured_at_ms),
                                        ),
                                    ),
                                ],
                            );
                        } else {
                            self.handle_baselines.insert(
                                id.clone(),
                                HandleBaseline {
                                    captured_at_ms: now_ms,
                                    histogram: current,
                                },
                            );
                        }
                    }
                }
                Err(error) => {
                    for id in handle_targets.keys() {
                        if self.handle_baselines.contains_key(id) {
                            self.latest.insert(
                                id.clone(),
                                vec![evidence(
                                    HANDLE_TYPES_LABEL,
                                    format!("capture degraded: {error:#}"),
                                )],
                            );
                        }
                    }
                }
            }
        }

        for (id, pid) in &thread_targets {
            match self.thread_baselines.get(id) {
                None => {
                    if let Ok(tids) = self.source.thread_ids(*pid) {
                        self.thread_baselines.insert(
                            id.clone(),
                            ThreadBaseline {
                                captured_at_ms: now_ms,
                                tids,
                            },
                        );
                    }
                }
                Some(baseline) if due => {
                    let window = format_window(now_ms.saturating_sub(baseline.captured_at_ms));
                    match self.source.thread_ids(*pid) {
                        Ok(current) => {
                            let mut new_tids: Vec<u32> =
                                current.difference(&baseline.tids).copied().collect();
                            new_tids.sort_unstable();
                            let summary = if new_tids.is_empty() {
                                "no new threads since baseline".to_string()
                            } else {
                                format_module_counts(
                                    &self.source.thread_start_modules(*pid, &new_tids),
                                )
                            };
                            self.latest.insert(
                                id.clone(),
                                vec![
                                    evidence(THREAD_MODULES_LABEL, summary),
                                    evidence(WINDOW_LABEL, window),
                                ],
                            );
                        }
                        Err(error) => {
                            self.latest.insert(
                                id.clone(),
                                vec![evidence(
                                    THREAD_MODULES_LABEL,
                                    format!("capture degraded: {error:#}"),
                                )],
                            );
                        }
                    }
                }
                Some(_) => {}
            }
        }
        if due {
            self.last_capture_ms = Some(now_ms);
        }
    }

    /// Attaches the latest forensic rows to matching alerts, replacing any
    /// forensic rows already present so evidence never accumulates.
    pub fn decorate(&self, alerts: &mut [Alert]) {
        for alert in alerts.iter_mut() {
            if let Some(rows) = self.latest.get(&alert.id) {
                alert
                    .evidence
                    .retain(|item| !FORENSIC_LABELS.contains(&item.label.as_str()));
                alert.evidence.extend(rows.iter().cloned());
            }
        }
    }

    #[cfg(test)]
    fn debug_counts(&self) -> (usize, usize, usize) {
        (
            self.handle_baselines.len(),
            self.thread_baselines.len(),
            self.latest.len(),
        )
    }
}

fn evidence(label: &str, value: String) -> Evidence {
    Evidence {
        label: label.into(),
        value,
    }
}

/// Top three positive per-type deltas, largest first, e.g.
/// `Event +1870 · Section +40 · File +12`.
fn format_handle_deltas(baseline: &HashMap<String, u64>, current: &HashMap<String, u64>) -> String {
    let mut deltas: Vec<(&str, u64)> = current
        .iter()
        .filter_map(|(name, count)| {
            let grown = count.saturating_sub(baseline.get(name).copied().unwrap_or(0));
            (grown > 0).then_some((name.as_str(), grown))
        })
        .collect();
    if deltas.is_empty() {
        return "no net growth by type".into();
    }
    deltas.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    deltas.truncate(3);
    deltas
        .iter()
        .map(|(name, delta)| format!("{name} +{delta}"))
        .collect::<Vec<_>>()
        .join(" · ")
}

/// Top three module counts, largest first, e.g. `xul.dll x34 · nvwgf2umx.dll x3`.
fn format_module_counts(modules: &[String]) -> String {
    if modules.is_empty() {
        return "no new threads since baseline".into();
    }
    let mut counts: HashMap<&str, u64> = HashMap::new();
    for module in modules {
        *counts.entry(module.as_str()).or_insert(0) += 1;
    }
    let mut ranked: Vec<(&str, u64)> = counts.into_iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    ranked.truncate(3);
    ranked
        .iter()
        .map(|(name, count)| format!("{name} x{count}"))
        .collect::<Vec<_>>()
        .join(" · ")
}

fn format_window(ms: i64) -> String {
    let ms = ms.max(0);
    if ms < 90_000 {
        format!("{} seconds", ms / 1_000)
    } else {
        format!("{} minutes", (ms + 30_000) / 60_000)
    }
}

// ---------------------------------------------------------------------------
// Windows implementation
// ---------------------------------------------------------------------------

const SYSTEM_EXTENDED_HANDLE_INFORMATION: u32 = 0x40;
const OBJECT_TYPES_INFORMATION: u32 = 3;
const THREAD_QUERY_SET_WIN32_START_ADDRESS: u32 = 9;
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004_u32 as i32;
/// The system handle table is several MB; beyond this cap the capture bails
/// with a degraded note rather than pressuring the 25 MB working-set budget.
const HANDLE_TABLE_CAP_BYTES: usize = 64 << 20;
const TYPE_TABLE_CAP_BYTES: usize = 8 << 20;

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQuerySystemInformation(
        system_information_class: u32,
        system_information: *mut c_void,
        system_information_length: u32,
        return_length: *mut u32,
    ) -> i32;
    fn NtQueryObject(
        handle: *mut c_void,
        object_information_class: u32,
        object_information: *mut c_void,
        object_information_length: u32,
        return_length: *mut u32,
    ) -> i32;
    fn NtQueryInformationThread(
        thread_handle: *mut c_void,
        thread_information_class: u32,
        thread_information: *mut c_void,
        thread_information_length: u32,
        return_length: *mut u32,
    ) -> i32;
}

/// `SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX`: only `UniqueProcessId` and
/// `ObjectTypeIndex` are consumed. No per-handle `NtQueryObject` and no
/// `DuplicateHandle` — both can hang on pipe handles in blocking states.
#[repr(C)]
#[derive(Clone, Copy)]
struct SystemHandleEntry {
    object: *mut c_void,
    unique_process_id: usize,
    handle_value: usize,
    granted_access: u32,
    creator_back_trace_index: u16,
    object_type_index: u16,
    handle_attributes: u32,
    reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *const u16,
}

/// `OBJECT_TYPE_INFORMATION` (0x68 bytes on x64). `type_index` is the
/// authoritative link to the handle table's `ObjectTypeIndex` on Windows
/// 8.1+; the enumeration-order + 2 fallback covers a zeroed field.
#[repr(C)]
#[derive(Clone, Copy)]
struct ObjectTypeInformation {
    type_name: UnicodeString,
    counters: [u32; 13],
    generic_mapping: [u32; 4],
    valid_access_mask: u32,
    security_required: u8,
    maintain_handle_count: u8,
    type_index: u8,
    reserved_byte: u8,
    pool_type: u32,
    default_paged_pool_charge: u32,
    default_non_paged_pool_charge: u32,
}

const fn align_up(value: usize, alignment: usize) -> usize {
    (value + alignment - 1) & !(alignment - 1)
}

/// Page-backed buffer for the large NT queries. Heap frees keep their pages
/// in the process working set (the residue tripped the collector's own
/// budget detector at 44 MB in the field); `VirtualFree(MEM_RELEASE)`
/// returns them to the OS the moment the buffer drops. VirtualAlloc's
/// page alignment also satisfies every structure the kernel writes.
struct PageBuffer {
    ptr: *mut c_void,
    bytes: usize,
}

impl PageBuffer {
    fn allocate(bytes: usize) -> Result<Self> {
        let ptr = unsafe { VirtualAlloc(None, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) };
        if ptr.is_null() {
            bail!("VirtualAlloc failed for a {bytes}-byte forensics buffer");
        }
        Ok(Self { ptr, bytes })
    }

    fn as_mut_ptr(&mut self) -> *mut c_void {
        self.ptr
    }

    fn as_ptr(&self) -> *const u8 {
        self.ptr.cast()
    }

    const fn bytes(&self) -> usize {
        self.bytes
    }
}

impl Drop for PageBuffer {
    fn drop(&mut self) {
        let _ = unsafe { VirtualFree(self.ptr, 0, MEM_RELEASE) };
    }
}

/// Trim the working set after a capture pass: even with page-backed
/// buffers, soft page-ins accumulated while walking a ~16 MB table linger
/// in the working set, and the collector budgets itself at 25 MB. Pages
/// still in use fault back in cheaply.
pub(crate) fn trim_working_set() {
    unsafe {
        let _ = K32EmptyWorkingSet(GetCurrentProcess());
    }
}

/// Growth loop shared by both NT queries.
fn query_growing(
    query: impl Fn(*mut c_void, u32, *mut u32) -> i32,
    initial_bytes: usize,
    cap_bytes: usize,
) -> Result<(PageBuffer, usize)> {
    let mut size = initial_bytes;
    loop {
        if size > cap_bytes {
            bail!("forensics buffer exceeded the {} MB cap", cap_bytes >> 20);
        }
        let mut buffer = PageBuffer::allocate(align_up(size, 4096))?;
        let mut returned = 0_u32;
        let status = query(buffer.as_mut_ptr(), size as u32, &mut returned);
        if status == STATUS_INFO_LENGTH_MISMATCH {
            size = size
                .saturating_mul(2)
                .max((returned as usize).saturating_add(1 << 20));
            continue;
        }
        if status < 0 {
            bail!("NT query failed with status {status:#010x}");
        }
        let filled = if returned == 0 {
            size.min(buffer.bytes())
        } else {
            (returned as usize).min(size)
        };
        return Ok((buffer, filled));
    }
}

fn load_type_names() -> Result<(HashMap<u16, String>, &'static str)> {
    let (buffer, filled) = query_growing(
        |ptr, len, ret| unsafe {
            NtQueryObject(std::ptr::null_mut(), OBJECT_TYPES_INFORMATION, ptr, len, ret)
        },
        64 << 10,
        TYPE_TABLE_CAP_BYTES,
    )?;
    let base = buffer.as_ptr();
    let count = unsafe { std::ptr::read_unaligned(base.cast::<u32>()) } as usize;
    let entry_size = size_of::<ObjectTypeInformation>();
    let mut offset = align_up(size_of::<u32>(), size_of::<usize>());
    let mut names = HashMap::with_capacity(count);
    let mut field_based = false;
    for ordinal in 0..count {
        if offset + entry_size > filled {
            break;
        }
        let info = unsafe {
            std::ptr::read_unaligned(base.add(offset).cast::<ObjectTypeInformation>())
        };
        // The handle table's type indexes start at 2 on modern Windows; the
        // probe harness asserts this alignment empirically against a real
        // Event-handle burst rather than trusting either path blindly.
        let index = if info.type_index != 0 {
            field_based = true;
            u16::from(info.type_index)
        } else {
            ordinal as u16 + 2
        };
        let name_offset = (info.type_name.buffer as usize).wrapping_sub(base as usize);
        let name_bytes = usize::from(info.type_name.length);
        let name = if !info.type_name.buffer.is_null()
            && name_offset.checked_add(name_bytes).is_some_and(|end| end <= filled)
        {
            let chars = unsafe {
                std::slice::from_raw_parts(base.add(name_offset).cast::<u16>(), name_bytes / 2)
            };
            String::from_utf16_lossy(chars)
        } else {
            format!("Type {index}")
        };
        names.insert(index, name);
        offset = align_up(
            offset + entry_size + usize::from(info.type_name.maximum_length),
            size_of::<usize>(),
        );
    }
    Ok((
        names,
        if field_based {
            "OBJECT_TYPE_INFORMATION.TypeIndex field"
        } else {
            "enumeration order + 2"
        },
    ))
}

/// The real syscall layer. Tracks a handle-discipline counter: every
/// snapshot/thread/process handle opened by a pass is closed in that pass.
#[derive(Default)]
pub struct WindowsForensicsSource {
    type_names: HashMap<u16, String>,
    type_index_source: &'static str,
    last_table_bytes: usize,
    opened: u64,
    closed: u64,
}

impl WindowsForensicsSource {
    /// (opened, closed) kernel handles across all passes; equal when the
    /// per-pass discipline holds.
    pub fn handle_balance(&self) -> (u64, u64) {
        (self.opened, self.closed)
    }

    /// How type indexes were aligned to type names, decided empirically at
    /// first capture.
    pub fn type_index_source(&self) -> &'static str {
        self.type_index_source
    }

    /// Bytes of the last system handle table capture.
    pub fn last_table_bytes(&self) -> usize {
        self.last_table_bytes
    }

    fn thread_start_address(&mut self, tid: u32) -> Option<usize> {
        // Verified empirically on Windows 11: ThreadQuerySetWin32StartAddress
        // returns STATUS_ACCESS_DENIED under THREAD_QUERY_LIMITED_INFORMATION,
        // so full query rights are requested first (always granted to the
        // LocalSystem collector for normal processes) with a limited fallback
        // that keeps protected threads on the degrade path.
        let handle = unsafe { OpenThread(THREAD_QUERY_INFORMATION, false, tid) }
            .or_else(|_| unsafe { OpenThread(THREAD_QUERY_LIMITED_INFORMATION, false, tid) })
            .ok()?;
        self.opened += 1;
        let mut address = 0_usize;
        let status = unsafe {
            NtQueryInformationThread(
                handle.0,
                THREAD_QUERY_SET_WIN32_START_ADDRESS,
                (&raw mut address).cast(),
                size_of::<usize>() as u32,
                std::ptr::null_mut(),
            )
        };
        unsafe {
            let _ = CloseHandle(handle);
        }
        self.closed += 1;
        (status >= 0 && address != 0).then_some(address)
    }

    /// (base, size, base name) for every module in `pid`. Requires
    /// `PROCESS_VM_READ`; a denial degrades to an empty list, which callers
    /// surface as `unattributed`.
    fn module_ranges(&mut self, pid: u32) -> Vec<(usize, usize, String)> {
        let Ok(process) = (unsafe {
            OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, false, pid)
        }) else {
            return Vec::new();
        };
        self.opened += 1;
        let mut modules = vec![HMODULE::default(); 1024];
        let mut needed = 0_u32;
        let mut ranges = Vec::new();
        if unsafe {
            EnumProcessModulesEx(
                process,
                modules.as_mut_ptr(),
                (modules.len() * size_of::<HMODULE>()) as u32,
                &mut needed,
                LIST_MODULES_ALL,
            )
        }
        .is_ok()
        {
            let count = (needed as usize / size_of::<HMODULE>()).min(modules.len());
            for module in modules.iter().take(count).copied() {
                let mut info = MODULEINFO::default();
                if unsafe {
                    GetModuleInformation(process, module, &mut info, size_of::<MODULEINFO>() as u32)
                }
                .is_err()
                {
                    continue;
                }
                let mut name = [0_u16; 260];
                let length = unsafe { GetModuleBaseNameW(process, Some(module), &mut name) } as usize;
                if length == 0 {
                    continue;
                }
                ranges.push((
                    info.lpBaseOfDll as usize,
                    info.SizeOfImage as usize,
                    String::from_utf16_lossy(&name[..length.min(name.len())]),
                ));
            }
        }
        unsafe {
            let _ = CloseHandle(process);
        }
        self.closed += 1;
        ranges
    }
}

impl ForensicsSource for WindowsForensicsSource {
    fn handle_histograms(&mut self, pids: &HashSet<u32>) -> Result<HashMap<u32, HashMap<String, u64>>> {
        if self.type_names.is_empty() {
            let (names, source) = load_type_names()?;
            self.type_names = names;
            self.type_index_source = source;
        }
        let mut by_index: HashMap<u32, HashMap<u16, u64>> =
            pids.iter().map(|pid| (*pid, HashMap::new())).collect();
        {
            // The table lives only inside this scope; it is bucketed and
            // dropped before names are resolved so the working set returns.
            let (buffer, filled) = query_growing(
                |ptr, len, ret| unsafe {
                    NtQuerySystemInformation(SYSTEM_EXTENDED_HANDLE_INFORMATION, ptr, len, ret)
                },
                4 << 20,
                HANDLE_TABLE_CAP_BYTES,
            )?;
            self.last_table_bytes = filled;
            let base = buffer.as_ptr();
            let declared = unsafe { std::ptr::read_unaligned(base.cast::<usize>()) };
            let header = 2 * size_of::<usize>();
            let entry_size = size_of::<SystemHandleEntry>();
            let count = declared.min(filled.saturating_sub(header) / entry_size);
            for slot in 0..count {
                let entry = unsafe {
                    std::ptr::read_unaligned(
                        base.add(header + slot * entry_size).cast::<SystemHandleEntry>(),
                    )
                };
                if let Some(histogram) = by_index.get_mut(&(entry.unique_process_id as u32)) {
                    *histogram.entry(entry.object_type_index).or_insert(0) += 1;
                }
            }
        }
        trim_working_set();
        Ok(by_index
            .into_iter()
            .map(|(pid, histogram)| {
                let named = histogram
                    .into_iter()
                    .map(|(index, count)| {
                        (
                            self.type_names
                                .get(&index)
                                .cloned()
                                .unwrap_or_else(|| format!("Type {index}")),
                            count,
                        )
                    })
                    .collect();
                (pid, named)
            })
            .collect())
    }

    fn thread_ids(&mut self, pid: u32) -> Result<HashSet<u32>> {
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) }?;
        self.opened += 1;
        let mut entry = THREADENTRY32 {
            dwSize: size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };
        let mut tids = HashSet::new();
        if unsafe { Thread32First(snapshot, &mut entry) }.is_ok() {
            loop {
                if entry.th32OwnerProcessID == pid {
                    tids.insert(entry.th32ThreadID);
                }
                if unsafe { Thread32Next(snapshot, &mut entry) }.is_err() {
                    break;
                }
            }
        }
        unsafe {
            let _ = CloseHandle(snapshot);
        }
        self.closed += 1;
        debug_assert_eq!(self.opened, self.closed, "forensics handle discipline");
        Ok(tids)
    }

    fn thread_start_modules(&mut self, pid: u32, new_tids: &[u32]) -> Vec<String> {
        let addresses: Vec<Option<usize>> = new_tids
            .iter()
            .map(|tid| self.thread_start_address(*tid))
            .collect();
        let ranges = self.module_ranges(pid);
        let attributed = addresses
            .into_iter()
            .map(|address| {
                address
                    .and_then(|address| {
                        ranges
                            .iter()
                            .find(|(base, size, _)| {
                                address >= *base && address < base.saturating_add(*size)
                            })
                            .map(|(_, _, name)| name.clone())
                    })
                    .unwrap_or_else(|| UNATTRIBUTED.to_string())
            })
            .collect();
        debug_assert_eq!(self.opened, self.closed, "forensics handle discipline");
        attributed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Severity;

    fn alert(id: &str, kind: &str, pid: u32) -> Alert {
        Alert {
            id: id.into(),
            kind: kind.into(),
            severity: Severity::Warning,
            first_seen_ms: 0,
            last_seen_ms: 0,
            process_id: Some(pid),
            process_name: Some("worker.exe".into()),
            title: "Handle count is growing".into(),
            explanation: String::new(),
            evidence: vec![
                Evidence {
                    label: "New handles".into(),
                    value: "300".into(),
                },
                Evidence {
                    label: "Window".into(),
                    value: "120 seconds".into(),
                },
            ],
            recommendation: String::new(),
            acknowledged: false,
            occurrence_count: 1,
            resolved_at_ms: None,
            archived: false,
            fingerprint: String::new(),
            state: crate::models::IncidentState::Open,
            quality: crate::models::AlertQuality::default(),
            notify: true,
            notify_generation: 0,
        }
    }

    fn histogram(pairs: &[(&str, u64)]) -> HashMap<String, u64> {
        pairs
            .iter()
            .map(|(name, count)| ((*name).to_string(), *count))
            .collect()
    }

    #[derive(Default)]
    struct StubSource {
        histogram_calls: usize,
        thread_calls: usize,
        module_calls: usize,
        histogram: HashMap<u32, HashMap<String, u64>>,
        threads: HashMap<u32, HashSet<u32>>,
        module_by_tid: HashMap<u32, String>,
        fail_histograms: bool,
    }

    impl ForensicsSource for StubSource {
        fn handle_histograms(
            &mut self,
            pids: &HashSet<u32>,
        ) -> Result<HashMap<u32, HashMap<String, u64>>> {
            self.histogram_calls += 1;
            if self.fail_histograms {
                bail!("handle table exceeded the 64 MB cap");
            }
            Ok(pids
                .iter()
                .map(|pid| (*pid, self.histogram.get(pid).cloned().unwrap_or_default()))
                .collect())
        }

        fn thread_ids(&mut self, pid: u32) -> Result<HashSet<u32>> {
            self.thread_calls += 1;
            Ok(self.threads.get(&pid).cloned().unwrap_or_default())
        }

        fn thread_start_modules(&mut self, _pid: u32, new_tids: &[u32]) -> Vec<String> {
            self.module_calls += 1;
            new_tids
                .iter()
                .map(|tid| {
                    self.module_by_tid
                        .get(tid)
                        .cloned()
                        .unwrap_or_else(|| UNATTRIBUTED.to_string())
                })
                .collect()
        }
    }

    #[test]
    fn no_leak_findings_means_no_source_calls() {
        let mut engine = ForensicsEngine::new(StubSource::default());
        engine.observe(&[], 0);
        engine.observe(&[alert("a", "memoryGrowth", 7)], 60_000);
        engine.observe(&[alert("b", "sustainedCpu", 7)], 120_000);
        assert_eq!(engine.source().histogram_calls, 0);
        assert_eq!(engine.source().thread_calls, 0);
        assert_eq!(engine.source().module_calls, 0);
    }

    #[test]
    fn cadence_gates_captures_to_the_interval() {
        let mut engine = ForensicsEngine::new(StubSource::default());
        let alerts = [alert("a", "handleGrowth", 7)];
        engine.observe(&alerts, 0); // baseline
        assert_eq!(engine.source().histogram_calls, 1);
        engine.observe(&alerts, 10_000);
        engine.observe(&alerts, 30_000);
        assert_eq!(engine.source().histogram_calls, 1, "not due yet");
        engine.observe(&alerts, 60_000);
        assert_eq!(engine.source().histogram_calls, 2);
    }

    #[test]
    fn handle_baseline_capture_resolve_lifecycle() {
        let mut engine = ForensicsEngine::new(StubSource::default());
        engine.source_mut().histogram =
            [(7, histogram(&[("Event", 100), ("File", 20)]))].into();
        let mut alerts = [alert("a", "handleGrowth", 7)];
        engine.observe(&alerts, 0);
        engine.decorate(&mut alerts);
        assert!(
            !alerts[0].evidence.iter().any(|e| e.label == "Handle types"),
            "baseline capture produces no delta rows yet"
        );
        engine.source_mut().histogram = [(
            7,
            histogram(&[("Event", 1_970), ("Section", 60), ("File", 32), ("Key", 21)]),
        )]
        .into();
        engine.observe(&alerts, 9 * 60_000);
        engine.decorate(&mut alerts);
        let types = alerts[0]
            .evidence
            .iter()
            .find(|e| e.label == "Handle types")
            .expect("handle-type evidence");
        assert_eq!(types.value, "Event +1870 · Section +60 · Key +21");
        let window = alerts[0]
            .evidence
            .iter()
            .find(|e| e.label == "Forensics window")
            .expect("window evidence");
        assert_eq!(window.value, "9 minutes");
        // Resolution clears the baseline; the rows survive exactly one pass.
        engine.observe(&[], 10 * 60_000);
        assert_eq!(engine.debug_counts().0, 0, "baseline cleared on resolve");
        assert_eq!(engine.debug_counts().2, 1, "final rows kept for write-back");
        engine.observe(&[], 11 * 60_000);
        assert_eq!(engine.debug_counts().2, 0, "grace pass expired");
        // A reoccurrence starts a fresh baseline.
        engine.observe(&[alert("a2", "handleGrowth", 7)], 12 * 60_000);
        assert_eq!(engine.debug_counts().0, 1);
    }

    #[test]
    fn thread_capture_attributes_new_tids_to_modules() {
        let mut engine = ForensicsEngine::new(StubSource::default());
        engine.source_mut().threads = [(9, HashSet::from([1, 2]))].into();
        let mut alerts = [alert("t", "threadGrowth", 9)];
        engine.observe(&alerts, 0);
        engine.source_mut().threads =
            [(9, HashSet::from([1, 2, 30, 31, 32, 33, 40]))].into();
        engine.source_mut().module_by_tid = [
            (30, "xul.dll".to_string()),
            (31, "xul.dll".to_string()),
            (32, "xul.dll".to_string()),
            (33, "nvwgf2umx.dll".to_string()),
        ]
        .into();
        engine.observe(&alerts, 60_000);
        engine.decorate(&mut alerts);
        let modules = alerts[0]
            .evidence
            .iter()
            .find(|e| e.label == "New-thread modules")
            .expect("thread-module evidence");
        assert_eq!(modules.value, "xul.dll x3 · nvwgf2umx.dll x1 · unattributed x1");
    }

    #[test]
    fn evidence_rows_are_replaced_not_accumulated() {
        let mut engine = ForensicsEngine::new(StubSource::default());
        engine.source_mut().histogram = [(7, histogram(&[("Event", 100)]))].into();
        let mut alerts = [alert("a", "handleGrowth", 7)];
        // Simulate a stale forensic row arriving from persisted state.
        alerts[0].evidence.push(Evidence {
            label: "Handle types".into(),
            value: "Mutant +5".into(),
        });
        engine.observe(&alerts, 0);
        engine.source_mut().histogram = [(7, histogram(&[("Event", 600)]))].into();
        engine.observe(&alerts, 60_000);
        engine.decorate(&mut alerts);
        engine.decorate(&mut alerts);
        engine.decorate(&mut alerts);
        let type_rows: Vec<&Evidence> = alerts[0]
            .evidence
            .iter()
            .filter(|e| e.label == "Handle types")
            .collect();
        assert_eq!(type_rows.len(), 1, "replaced, not appended");
        assert_eq!(type_rows[0].value, "Event +500");
        assert_eq!(
            alerts[0]
                .evidence
                .iter()
                .filter(|e| e.label == "Forensics window")
                .count(),
            1
        );
        // The detector's own rows are untouched.
        assert!(alerts[0].evidence.iter().any(|e| e.label == "New handles"));
        // A later capture replaces the cached rows too.
        engine.source_mut().histogram = [(7, histogram(&[("Event", 700)]))].into();
        engine.observe(&alerts, 120_000);
        engine.decorate(&mut alerts);
        let types = alerts[0]
            .evidence
            .iter()
            .find(|e| e.label == "Handle types")
            .expect("handle-type evidence");
        assert_eq!(types.value, "Event +600");
    }

    #[test]
    fn degraded_capture_is_surfaced_as_evidence() {
        let mut engine = ForensicsEngine::new(StubSource::default());
        let mut alerts = [alert("a", "handleGrowth", 7)];
        engine.observe(&alerts, 0);
        engine.source_mut().fail_histograms = true;
        engine.observe(&alerts, 60_000);
        engine.decorate(&mut alerts);
        let types = alerts[0]
            .evidence
            .iter()
            .find(|e| e.label == "Handle types")
            .expect("degraded evidence");
        assert!(types.value.contains("capture degraded"));
        assert!(types.value.contains("64 MB cap"));
    }

    #[test]
    fn formatting_helpers_bound_and_rank() {
        let baseline = histogram(&[("Event", 10), ("File", 5), ("Key", 9)]);
        let current = histogram(&[
            ("Event", 1_880),
            ("Section", 40),
            ("File", 17),
            ("Key", 11),
            ("Mutant", 1),
        ]);
        assert_eq!(
            format_handle_deltas(&baseline, &current),
            "Event +1870 · Section +40 · File +12"
        );
        assert_eq!(format_handle_deltas(&current, &current), "no net growth by type");
        assert_eq!(
            format_module_counts(&[
                "xul.dll".into(),
                "xul.dll".into(),
                "nvwgf2umx.dll".into(),
                "a.dll".into(),
                "b.dll".into(),
                "xul.dll".into(),
            ]),
            "xul.dll x3 · a.dll x1 · b.dll x1"
        );
        assert_eq!(format_window(45_000), "45 seconds");
        assert_eq!(format_window(9 * 60_000 - 10_000), "9 minutes");
    }

    #[test]
    fn windows_source_balances_every_handle_it_opens() {
        // Real but cheap syscalls against our own process: the discipline
        // counter must balance without needing elevated rights.
        let mut source = WindowsForensicsSource::default();
        let pid = std::process::id();
        let tids = source.thread_ids(pid).expect("thread snapshot");
        assert!(!tids.is_empty());
        let sample: Vec<u32> = tids.into_iter().take(2).collect();
        let modules = source.thread_start_modules(pid, &sample);
        assert_eq!(modules.len(), sample.len());
        let (opened, closed) = source.handle_balance();
        assert_eq!(opened, closed);
        assert!(opened > 0);
    }

    #[test]
    #[ignore = "dev harness: prints the handle-type histogram of the process named by PCPULSE_TARGET_PID"]
    fn dev_probe_target_process_handles() {
        let pid: u32 = std::env::var("PCPULSE_TARGET_PID")
            .expect("set PCPULSE_TARGET_PID")
            .parse()
            .expect("PCPULSE_TARGET_PID must be a pid");
        let mut source = WindowsForensicsSource::default();
        let histograms = source
            .handle_histograms(&HashSet::from([pid]))
            .expect("capture handle table");
        let mut rows: Vec<(String, u64)> = histograms
            .get(&pid)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect();
        rows.sort_by_key(|row| std::cmp::Reverse(row.1));
        let total: u64 = rows.iter().map(|(_, count)| count).sum();
        println!("pid {pid}: {total} handles");
        for (name, count) in rows.iter().take(12) {
            println!("  {name:<24} {count}");
        }
    }

    #[test]
    #[ignore = "dev harness: probes the real system handle table and thread start modules on this machine and prints the resulting forensic evidence"]
    fn dev_probe_real_leak_forensics() {
        use windows::Win32::System::Threading::CreateEventW;
        use windows::core::PCWSTR;

        let pid = std::process::id();
        let mut engine = ForensicsEngine::new(WindowsForensicsSource::default());
        let mut alerts = [
            alert("probe-handles", "handleGrowth", pid),
            alert("probe-threads", "threadGrowth", pid),
        ];
        // Baseline capture at t0, exactly as a freshly fired finding would get.
        engine.observe(&alerts, 0);
        println!(
            "type-index alignment: {}",
            engine.source().type_index_source()
        );
        println!(
            "handle table bytes (baseline): {}",
            engine.source().last_table_bytes()
        );

        // Leak 500 event handles and park 8 threads on a sleep.
        let events: Vec<_> = (0..500)
            .map(|_| {
                unsafe { CreateEventW(None, false, false, PCWSTR::null()) }
                    .expect("create event handle")
            })
            .collect();
        let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let done = std::sync::Arc::clone(&done);
                std::thread::spawn(move || {
                    while !done.load(std::sync::atomic::Ordering::Acquire) {
                        std::thread::sleep(std::time::Duration::from_millis(25));
                    }
                })
            })
            .collect();
        std::thread::sleep(std::time::Duration::from_millis(200));

        let ranges = engine.source_mut().module_ranges(pid);
        println!("module ranges resolved: {}", ranges.len());
        let own_tids = engine.source_mut().thread_ids(pid).expect("own thread ids");
        let sample_addresses: Vec<Option<usize>> = own_tids
            .iter()
            .take(4)
            .map(|tid| engine.source_mut().thread_start_address(*tid))
            .collect();
        println!("sample start addresses: {sample_addresses:x?}");

        // The 60-second cadence is simulated by advancing the clock.
        engine.observe(&alerts, 9 * 60_000);
        engine.decorate(&mut alerts);
        for alert in &alerts {
            for evidence in &alert.evidence {
                println!("{} :: {} = {}", alert.id, evidence.label, evidence.value);
            }
        }
        println!(
            "handle table bytes (capture): {}",
            engine.source().last_table_bytes()
        );
        let (opened, closed) = engine.source().handle_balance();
        println!("handle discipline: opened {opened} closed {closed}");

        let handle_row = alerts[0]
            .evidence
            .iter()
            .find(|e| e.label == "Handle types")
            .expect("handle-type evidence");
        assert!(
            handle_row.value.starts_with("Event +"),
            "expected the Event bucket to dominate, got: {}",
            handle_row.value
        );
        let event_delta: u64 = handle_row.value["Event +".len()..]
            .split(|c: char| !c.is_ascii_digit())
            .next()
            .and_then(|digits| digits.parse().ok())
            .expect("parse Event delta");
        assert!(
            event_delta >= 500,
            "expected at least the 500 leaked events, got {event_delta}"
        );
        let module_row = alerts[1]
            .evidence
            .iter()
            .find(|e| e.label == "New-thread modules")
            .expect("thread-module evidence");
        assert!(
            module_row.value.contains(".exe") || module_row.value.contains("ntdll.dll"),
            "expected attribution to the test executable or ntdll, got: {}",
            module_row.value
        );
        assert_eq!(opened, closed, "handle discipline broke");

        // Regression guard for the field-reported 44 MB breach: repeated
        // captures must not park the handle-table pages in the working set.
        // Ten passes with the cadence advanced past the interval each time,
        // then the working set must sit well under the 25 MB budget even in
        // this test process (which carries the test harness itself).
        for round in 2..12_i64 {
            engine.observe(&alerts, round * 10 * 60_000);
        }
        let mut counters = windows::Win32::System::ProcessStatus::PROCESS_MEMORY_COUNTERS::default();
        unsafe {
            windows::Win32::System::ProcessStatus::K32GetProcessMemoryInfo(
                GetCurrentProcess(),
                &mut counters,
                size_of::<windows::Win32::System::ProcessStatus::PROCESS_MEMORY_COUNTERS>() as u32,
            )
            .expect("query own memory counters");
        }
        let working_set_mb = counters.WorkingSetSize as f64 / (1024.0 * 1024.0);
        println!("working set after 10 capture rounds: {working_set_mb:.1} MB");
        assert!(
            working_set_mb < 25.0,
            "working set stayed inflated after captures: {working_set_mb:.1} MB"
        );

        done.store(true, std::sync::atomic::Ordering::Release);
        for thread in threads {
            thread.join().expect("join parked thread");
        }
        for event in events {
            unsafe {
                let _ = CloseHandle(event);
            }
        }
    }
}
