//! Crash-dump discovery and native triage.
//!
//! On a slow cadence (first scan shortly after start, then every five
//! minutes) the engine enumerates the standard Windows crash-dump
//! locations — `%SystemRoot%\Minidump\*.dmp`, `%SystemRoot%\MEMORY.DMP`,
//! and each user profile's `AppData\Local\CrashDumps\*.dmp` (WER) — and
//! raises one `crashDump` finding per dump it can see. Profiles the
//! collector cannot enter degrade silently; a dump disappearing resolves
//! its finding on the next scan.
//!
//! Triage is native and bounded: kernel dumps (`PAGEDU64`/`PAGEDUMP`)
//! have their bugcheck code and four parameters read straight from the
//! documented header offsets; user-mode minidumps (`MDMP`) have their
//! exception stream and module list walked by hand to name the exception
//! code and the faulting module. The Mozilla `minidump` crate was
//! evaluated for the MDMP side and rejected: it drags ~20 transitive
//! crates (prost, procfs-core, encoding_rs, tracing, time, …) into a
//! collector that budgets itself at 25 MB, while the three structures we
//! need are a few dozen lines of offset arithmetic in the same style as
//! the forensics engine's NT parsing.
//!
//! Budget discipline: between scans `observe` is a single timestamp
//! comparison. A scan is file metadata plus one bounded header read per
//! **new** dump — triage results are cached by `(path, modified)` and a
//! cached dump costs nothing to rescan. No dump content beyond the parsed
//! headers/streams ever leaves the machine or enters evidence.
//!
//! Privacy boundary: findings carry metadata and codes only — bugcheck
//! numbers, exception codes, module base names, file sizes, and ages.
//! User-profile path segments are replaced with `%USERPROFILE%` via the
//! same redaction the event-log collector uses.

use crate::models::{Alert, Evidence, Severity};
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// Scans run at most this often once the first scan has happened.
pub const SCAN_INTERVAL_MS: i64 = 5 * 60_000;
/// The first scan runs this long after the engine first observes.
pub const FIRST_SCAN_DELAY_MS: i64 = 15_000;
/// A kernel dump younger than this makes its finding critical.
const FRESH_KERNEL_MS: i64 = 48 * 3_600_000;
/// The rolling window behind the `Crash count` evidence row.
const CRASH_COUNT_WINDOW_MS: i64 = 30 * 24 * 3_600_000;
/// Sanity caps for the hand-parsed minidump structures.
const MAX_STREAMS: u32 = 256;
const MAX_MODULES: u32 = 2_048;
const MAX_MODULE_NAME_BYTES: u32 = 1_024;

const CRASH_DUMP_KIND: &str = "crashDump";

/// One discovered dump file: metadata only, no content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DumpFileMeta {
    pub path: PathBuf,
    pub size_bytes: u64,
    pub modified_ms: i64,
}

/// What the bounded header read established about a dump.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DumpTriage {
    /// `PAGEDU64` / `PAGEDUMP` kernel dump: bugcheck code and parameters.
    Kernel {
        bugcheck_code: u32,
        parameters: [u64; 4],
    },
    /// `MDMP` user-mode minidump. Hang dumps carry no exception stream,
    /// so both fields are optional and never fabricated.
    UserMode {
        exception_code: Option<u32>,
        faulting_module: Option<String>,
    },
    /// The file did not present a recognizable dump signature.
    Unrecognized,
}

/// The filesystem layer behind the engine, stubbed in unit tests.
pub trait DumpSource {
    /// Enumerate every visible dump across the standard locations.
    /// Inaccessible directories degrade to absence, never to an error.
    fn discover(&mut self) -> Vec<DumpFileMeta>;
    /// One bounded header/stream read for a single dump file.
    fn triage(&mut self, path: &Path) -> Result<DumpTriage>;
}

/// Cached triage state for one `(path, modified)` identity.
#[derive(Debug, Clone)]
enum TriageOutcome {
    Parsed(DumpTriage),
    Degraded(String),
}

/// Raises and resolves `crashDump` findings from the scan cadence.
///
/// Between scans `observe` compares one timestamp and returns. Alerts use
/// deterministic IDs derived from `(path, modified)`, so the same dump is
/// the same finding across collector restarts.
pub struct DumpEngine<S> {
    source: S,
    next_scan_ms: Option<i64>,
    triage_cache: HashMap<(PathBuf, i64), TriageOutcome>,
    active: HashMap<String, Alert>,
}

impl<S: DumpSource> DumpEngine<S> {
    pub fn new(source: S) -> Self {
        Self {
            source,
            next_scan_ms: None,
            triage_cache: HashMap::new(),
            active: HashMap::new(),
        }
    }

    pub fn source(&self) -> &S {
        &self.source
    }

    pub fn source_mut(&mut self) -> &mut S {
        &mut self.source
    }

    /// The currently active crash-dump findings, for the snapshot.
    pub fn active_alerts(&self) -> Vec<Alert> {
        let mut alerts: Vec<Alert> = self.active.values().cloned().collect();
        alerts.sort_by(|a, b| a.id.cmp(&b.id));
        alerts
    }

    /// Drives the scan cadence. Returns the alerts that changed on this
    /// pass (new, refreshed, or resolved) for persistence; between scans
    /// this is a single comparison and an empty vector.
    pub fn observe(&mut self, now_ms: i64) -> Vec<Alert> {
        match self.next_scan_ms {
            None => {
                self.next_scan_ms = Some(now_ms + FIRST_SCAN_DELAY_MS);
                return Vec::new();
            }
            Some(due) if now_ms < due => return Vec::new(),
            Some(_) => {}
        }
        self.next_scan_ms = Some(now_ms + SCAN_INTERVAL_MS);
        self.scan(now_ms)
    }

    fn scan(&mut self, now_ms: i64) -> Vec<Alert> {
        let discovered = self.source.discover();
        // Triage every dump not already cached under its current identity;
        // a dump rewritten in place (new modified stamp) is re-triaged.
        for meta in &discovered {
            let key = (meta.path.clone(), meta.modified_ms);
            if self.triage_cache.contains_key(&key) {
                continue;
            }
            let outcome = match self.source.triage(&meta.path) {
                Ok(triage) => TriageOutcome::Parsed(triage),
                Err(error) => TriageOutcome::Degraded(format!("degraded: {error:#}")),
            };
            self.triage_cache.insert(key, outcome);
        }
        let live_keys: std::collections::HashSet<(PathBuf, i64)> = discovered
            .iter()
            .map(|meta| (meta.path.clone(), meta.modified_ms))
            .collect();
        self.triage_cache.retain(|key, _| live_keys.contains(key));

        let recent_crashes = discovered
            .iter()
            .filter(|meta| now_ms.saturating_sub(meta.modified_ms) <= CRASH_COUNT_WINDOW_MS)
            .count();

        let mut changed = Vec::new();
        let mut present = std::collections::HashSet::new();
        for meta in &discovered {
            let key = (meta.path.clone(), meta.modified_ms);
            let Some(outcome) = self.triage_cache.get(&key) else {
                continue;
            };
            let id = finding_id(meta);
            present.insert(id.clone());
            let candidate = build_alert(&id, meta, outcome, now_ms, recent_crashes);
            match self.active.get_mut(&id) {
                Some(alert) => {
                    alert.last_seen_ms = now_ms;
                    alert.severity = candidate.severity;
                    alert.evidence = candidate.evidence;
                    alert.occurrence_count = alert.occurrence_count.saturating_add(1);
                    changed.push(alert.clone());
                }
                None => {
                    changed.push(candidate.clone());
                    self.active.insert(id, candidate);
                }
            }
        }
        let resolved: Vec<String> = self
            .active
            .keys()
            .filter(|id| !present.contains(*id))
            .cloned()
            .collect();
        for id in resolved {
            if let Some(mut alert) = self.active.remove(&id) {
                alert.resolved_at_ms = Some(now_ms);
                changed.push(alert);
            }
        }
        changed
    }
}

/// Deterministic finding identity from the dump's path and timestamp, so
/// restarts re-attach to the same persisted row instead of duplicating it.
fn finding_id(meta: &DumpFileMeta) -> String {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    let mut mix = |bytes: &[u8]| {
        for byte in bytes {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
    };
    mix(meta.path.to_string_lossy().to_lowercase().as_bytes());
    mix(&meta.modified_ms.to_le_bytes());
    format!("crashDump:{hash:016x}")
}

fn build_alert(
    id: &str,
    meta: &DumpFileMeta,
    outcome: &TriageOutcome,
    now_ms: i64,
    recent_crashes: usize,
) -> Alert {
    let dump_row = evidence(
        "Dump",
        format!(
            "{} · {} · {}",
            crate::eventlog::redact_user_profile(&meta.path.to_string_lossy()),
            format_size(meta.size_bytes),
            format_age(now_ms.saturating_sub(meta.modified_ms)),
        ),
    );
    let count_row = evidence(
        "Crash count",
        format!(
            "{recent_crashes} dump{} in 30 days",
            if recent_crashes == 1 { "" } else { "s" }
        ),
    );
    let mut severity = Severity::Warning;
    let process_name = user_dump_process_name(&meta.path);
    let (title, explanation, mut rows, recommendation) = match outcome {
        TriageOutcome::Parsed(DumpTriage::Kernel {
            bugcheck_code,
            parameters,
        }) => {
            if now_ms.saturating_sub(meta.modified_ms) < FRESH_KERNEL_MS {
                severity = Severity::Critical;
            }
            let label = bugcheck_label(*bugcheck_code);
            (
                "Windows crashed with a bugcheck".to_string(),
                format!("Windows stopped with bugcheck {label} and wrote a kernel crash dump."),
                vec![
                    evidence("Bugcheck", label),
                    evidence(
                        "Parameters",
                        parameters
                            .iter()
                            .map(|parameter| format!("{parameter:#x}"))
                            .collect::<Vec<_>>()
                            .join(" "),
                    ),
                ],
                "Note what changed before the crash — new drivers, Windows updates, or hardware. With the Debugging Tools installed, run the full WinDbg analysis on this dump for the failing module; recurring bugchecks usually point at a driver or failing hardware.",
            )
        }
        TriageOutcome::Parsed(DumpTriage::UserMode {
            exception_code,
            faulting_module,
        }) => {
            let mut rows = Vec::new();
            if let Some(code) = exception_code {
                rows.push(evidence("Exception", exception_label(*code)));
            }
            if let Some(module) = faulting_module {
                rows.push(evidence("Faulting module", module.clone()));
            }
            let subject = process_name.as_deref().unwrap_or("An application");
            (
                "Application crash dump captured".to_string(),
                format!("Windows Error Reporting captured a crash dump for {subject}."),
                rows,
                "Update or repair the application and check the Application event log around the crash time. Recurring dumps from the same module usually indicate a bug in that app or one of its plug-ins.",
            )
        }
        TriageOutcome::Parsed(DumpTriage::Unrecognized) => (
            "Crash dump found".to_string(),
            "A file in a Windows crash-dump location does not present a recognizable dump header."
                .to_string(),
            vec![evidence("Triage", "unrecognized dump format")],
            "Inspect the file manually with the Debugging Tools; it may be truncated or from an unsupported writer.",
        ),
        TriageOutcome::Degraded(note) => (
            "Crash dump found".to_string(),
            "A crash dump exists but its header could not be read for triage.".to_string(),
            vec![evidence("Triage", note.clone())],
            "Check the file's permissions and integrity; with the Debugging Tools installed, run the full WinDbg analysis on it.",
        ),
    };
    rows.push(dump_row);
    rows.push(count_row);
    Alert {
        id: id.to_string(),
        kind: CRASH_DUMP_KIND.into(),
        severity,
        first_seen_ms: now_ms,
        last_seen_ms: now_ms,
        process_id: None,
        process_name,
        title,
        explanation,
        evidence: rows,
        recommendation: recommendation.into(),
        acknowledged: false,
        occurrence_count: 1,
        resolved_at_ms: None,
    }
}

/// WER names user dumps `<image>.<pid>.dmp`; recover the image name. The
/// crashed process is gone, so no PID is ever attached to the finding.
fn user_dump_process_name(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_string_lossy();
    let stem = name.strip_suffix(".dmp").or_else(|| name.strip_suffix(".DMP"))?;
    let (image, pid) = stem.rsplit_once('.')?;
    if pid.chars().all(|c| c.is_ascii_digit()) && !image.is_empty() {
        Some(image.to_string())
    } else {
        None
    }
}

fn evidence(label: &str, value: impl Into<String>) -> Evidence {
    Evidence {
        label: label.into(),
        value: value.into(),
    }
}

fn format_size(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    let bytes = bytes as f64;
    if bytes >= KIB * KIB * KIB {
        format!("{:.1} GB", bytes / (KIB * KIB * KIB))
    } else if bytes >= KIB * KIB {
        format!("{:.1} MB", bytes / (KIB * KIB))
    } else {
        format!("{:.0} KB", (bytes / KIB).max(1.0))
    }
}

fn format_age(ms: i64) -> String {
    let ms = ms.max(0);
    if ms < 3_600_000 {
        format!("{} min ago", (ms / 60_000).max(1))
    } else if ms < 48 * 3_600_000 {
        format!("{} h ago", ms / 3_600_000)
    } else {
        format!("{} d ago", ms / (24 * 3_600_000))
    }
}

// ---------------------------------------------------------------------------
// Native triage parsers (pure, bounded, no_std-style offset arithmetic)
// ---------------------------------------------------------------------------

/// `DUMP_HEADER64` needs the first 0x60 bytes; `DUMP_HEADER` fits in 0x40.
pub const KERNEL_HEADER_PREFIX_BYTES: usize = 0x60;

fn read_u32(buffer: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        buffer.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn read_u64(buffer: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        buffer.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

/// Parses a kernel-dump header prefix. 64-bit `PAGEDU64` keeps its
/// bugcheck code at 0x38 and four 8-byte parameters at 0x40; 32-bit
/// `PAGEDUMP` keeps the code at 0x28 and four 4-byte parameters at 0x2C.
pub fn parse_kernel_header(prefix: &[u8]) -> Option<DumpTriage> {
    if prefix.get(0..4)? != b"PAGE" {
        return None;
    }
    match prefix.get(4..8)? {
        b"DU64" => {
            let bugcheck_code = read_u32(prefix, 0x38)?;
            let mut parameters = [0_u64; 4];
            for (index, slot) in parameters.iter_mut().enumerate() {
                *slot = read_u64(prefix, 0x40 + index * 8)?;
            }
            Some(DumpTriage::Kernel {
                bugcheck_code,
                parameters,
            })
        }
        b"DUMP" => {
            let bugcheck_code = read_u32(prefix, 0x28)?;
            let mut parameters = [0_u64; 4];
            for (index, slot) in parameters.iter_mut().enumerate() {
                *slot = u64::from(read_u32(prefix, 0x2C + index * 4)?);
            }
            Some(DumpTriage::Kernel {
                bugcheck_code,
                parameters,
            })
        }
        _ => None,
    }
}

/// Hand-parses the three MDMP structures triage needs: the header, the
/// exception stream (type 6), and the module list (type 4) to attribute
/// the exception address. Every read is bounded by the caps above; a
/// minidump without an exception stream (a hang dump) parses to `None`
/// fields rather than an error.
pub fn parse_minidump<R: Read + Seek>(reader: &mut R) -> Result<DumpTriage> {
    let mut header = [0_u8; 32];
    reader.seek(SeekFrom::Start(0))?;
    reader
        .read_exact(&mut header)
        .context("minidump header truncated")?;
    if &header[0..4] != b"MDMP" {
        anyhow::bail!("not an MDMP file");
    }
    let stream_count = read_u32(&header, 8).unwrap_or(0).min(MAX_STREAMS);
    let directory_rva = read_u32(&header, 12).unwrap_or(0);
    let mut directory = vec![0_u8; stream_count as usize * 12];
    reader.seek(SeekFrom::Start(u64::from(directory_rva)))?;
    reader
        .read_exact(&mut directory)
        .context("minidump stream directory truncated")?;
    let mut exception_stream: Option<(u32, u32)> = None;
    let mut module_stream: Option<(u32, u32)> = None;
    for slot in 0..stream_count as usize {
        let stream_type = read_u32(&directory, slot * 12).unwrap_or(0);
        let data_size = read_u32(&directory, slot * 12 + 4).unwrap_or(0);
        let rva = read_u32(&directory, slot * 12 + 8).unwrap_or(0);
        match stream_type {
            6 => exception_stream = Some((rva, data_size)),
            4 => module_stream = Some((rva, data_size)),
            _ => {}
        }
    }
    let Some((exception_rva, exception_size)) = exception_stream else {
        return Ok(DumpTriage::UserMode {
            exception_code: None,
            faulting_module: None,
        });
    };
    // MINIDUMP_EXCEPTION_STREAM: ThreadId u32, alignment u32, then
    // MINIDUMP_EXCEPTION whose ExceptionCode sits at stream offset 8 and
    // ExceptionAddress at stream offset 24.
    let mut exception = [0_u8; 32];
    if exception_size < 32 {
        anyhow::bail!("minidump exception stream too small ({exception_size} bytes)");
    }
    reader.seek(SeekFrom::Start(u64::from(exception_rva)))?;
    reader
        .read_exact(&mut exception)
        .context("minidump exception stream truncated")?;
    let exception_code = read_u32(&exception, 8).unwrap_or(0);
    let exception_address = read_u64(&exception, 24).unwrap_or(0);
    let faulting_module = module_stream.and_then(|(rva, size)| {
        faulting_module_name(reader, rva, size, exception_address).ok().flatten()
    });
    Ok(DumpTriage::UserMode {
        exception_code: Some(exception_code),
        faulting_module,
    })
}

/// Walks MINIDUMP_MODULE entries (108 bytes: BaseOfImage u64 at 0,
/// SizeOfImage u32 at 8, ModuleNameRva u32 at 20) for the module whose
/// range contains `address`, then reads its MINIDUMP_STRING (u32 UTF-16
/// byte length, then characters) and keeps only the base file name.
fn faulting_module_name<R: Read + Seek>(
    reader: &mut R,
    list_rva: u32,
    list_size: u32,
    address: u64,
) -> Result<Option<String>> {
    if address == 0 || list_size < 4 {
        return Ok(None);
    }
    let mut count_bytes = [0_u8; 4];
    reader.seek(SeekFrom::Start(u64::from(list_rva)))?;
    reader.read_exact(&mut count_bytes)?;
    let declared = u32::from_le_bytes(count_bytes).min(MAX_MODULES);
    let fitting = list_size.saturating_sub(4) / 108;
    let count = declared.min(fitting) as usize;
    let mut modules = vec![0_u8; count * 108];
    reader.read_exact(&mut modules)?;
    for slot in 0..count {
        let base = read_u64(&modules, slot * 108).unwrap_or(0);
        let size = u64::from(read_u32(&modules, slot * 108 + 8).unwrap_or(0));
        if address < base || address >= base.saturating_add(size) {
            continue;
        }
        let name_rva = read_u32(&modules, slot * 108 + 20).unwrap_or(0);
        if name_rva == 0 {
            return Ok(None);
        }
        let mut length_bytes = [0_u8; 4];
        reader.seek(SeekFrom::Start(u64::from(name_rva)))?;
        reader.read_exact(&mut length_bytes)?;
        let length = u32::from_le_bytes(length_bytes).min(MAX_MODULE_NAME_BYTES) as usize;
        let mut name_bytes = vec![0_u8; length];
        reader.read_exact(&mut name_bytes)?;
        let characters: Vec<u16> = name_bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        let full = String::from_utf16_lossy(&characters);
        let base_name = full
            .rsplit(['\\', '/'])
            .next()
            .unwrap_or(full.as_str())
            .to_string();
        return Ok((!base_name.is_empty()).then_some(base_name));
    }
    Ok(None)
}

/// Well-known bugcheck codes, from the Microsoft bug-check code reference.
const BUGCHECK_NAMES: [(u32, &str); 36] = [
    (0x0A, "IRQL_NOT_LESS_OR_EQUAL"),
    (0x1A, "MEMORY_MANAGEMENT"),
    (0x1E, "KMODE_EXCEPTION_NOT_HANDLED"),
    (0x24, "NTFS_FILE_SYSTEM"),
    (0x3B, "SYSTEM_SERVICE_EXCEPTION"),
    (0x44, "MULTIPLE_IRP_COMPLETE_REQUESTS"),
    (0x4E, "PFN_LIST_CORRUPT"),
    (0x50, "PAGE_FAULT_IN_NONPAGED_AREA"),
    (0x51, "REGISTRY_ERROR"),
    (0x7A, "KERNEL_DATA_INPAGE_ERROR"),
    (0x7B, "INACCESSIBLE_BOOT_DEVICE"),
    (0x7E, "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED"),
    (0x7F, "UNEXPECTED_KERNEL_MODE_TRAP"),
    (0x8E, "KERNEL_MODE_EXCEPTION_NOT_HANDLED"),
    (0x9F, "DRIVER_POWER_STATE_FAILURE"),
    (0xA0, "INTERNAL_POWER_ERROR"),
    (0xB8, "ATTEMPTED_SWITCH_FROM_DPC"),
    (0xBE, "ATTEMPTED_WRITE_TO_READONLY_MEMORY"),
    (0xC2, "BAD_POOL_CALLER"),
    (0xC4, "DRIVER_VERIFIER_DETECTED_VIOLATION"),
    (0xC5, "DRIVER_CORRUPTED_EXPOOL"),
    (0xCE, "DRIVER_UNLOADED_WITHOUT_CANCELLING_PENDING_OPERATIONS"),
    (0xD1, "DRIVER_IRQL_NOT_LESS_OR_EQUAL"),
    (0xE2, "MANUALLY_INITIATED_CRASH"),
    (0xEF, "CRITICAL_PROCESS_DIED"),
    (0xF4, "CRITICAL_OBJECT_TERMINATION"),
    (0xF5, "FLTMGR_FILE_SYSTEM"),
    (0xFC, "ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY"),
    (0xFE, "BUGCODE_USB_DRIVER"),
    (0x101, "CLOCK_WATCHDOG_TIMEOUT"),
    (0x109, "CRITICAL_STRUCTURE_CORRUPTION"),
    (0x116, "VIDEO_TDR_FAILURE"),
    (0x119, "VIDEO_SCHEDULER_INTERNAL_ERROR"),
    (0x124, "WHEA_UNCORRECTABLE_ERROR"),
    (0x133, "DPC_WATCHDOG_VIOLATION"),
    (0x139, "KERNEL_SECURITY_CHECK_FAILURE"),
];

/// Well-known user-mode NT exception codes.
const EXCEPTION_NAMES: [(u32, &str); 11] = [
    (0x8000_0003, "BREAKPOINT"),
    (0xC000_0005, "ACCESS_VIOLATION"),
    (0xC000_001D, "ILLEGAL_INSTRUCTION"),
    (0xC000_008E, "FLOAT_DIVIDE_BY_ZERO"),
    (0xC000_0094, "INTEGER_DIVIDE_BY_ZERO"),
    (0xC000_00FD, "STACK_OVERFLOW"),
    (0xC000_027B, "STOWED_EXCEPTION"),
    (0xC000_0374, "HEAP_CORRUPTION"),
    (0xC000_0409, "STACK_BUFFER_OVERRUN"),
    (0xC000_041D, "FATAL_USER_CALLBACK_EXCEPTION"),
    (0xE043_4352, "CLR_EXCEPTION"),
];

pub fn bugcheck_label(code: u32) -> String {
    match BUGCHECK_NAMES.iter().find(|(known, _)| *known == code) {
        Some((_, name)) => format!("{code:#x} {name}"),
        None => format!("{code:#x}"),
    }
}

pub fn exception_label(code: u32) -> String {
    match EXCEPTION_NAMES.iter().find(|(known, _)| *known == code) {
        Some((_, name)) => format!("{code:#010x} {name}"),
        None => format!("{code:#010x}"),
    }
}

// ---------------------------------------------------------------------------
// Windows implementation
// ---------------------------------------------------------------------------

/// The real filesystem layer: standard dump locations, graceful degrade
/// on any directory or file the collector cannot enter.
#[derive(Default)]
pub struct WindowsDumpSource;

impl WindowsDumpSource {
    fn system_root() -> PathBuf {
        std::env::var_os("SystemRoot")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
    }

    fn users_root() -> PathBuf {
        let drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into());
        PathBuf::from(format!(r"{drive}\Users"))
    }

    fn push_dump_files(directory: &Path, found: &mut Vec<DumpFileMeta>) {
        let Ok(entries) = std::fs::read_dir(directory) else {
            return; // access denied or absent: degrade silently
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let is_dmp = path
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("dmp"));
            if !is_dmp {
                continue;
            }
            if let Some(meta) = Self::meta_for(&path) {
                found.push(meta);
            }
        }
    }

    fn meta_for(path: &Path) -> Option<DumpFileMeta> {
        let metadata = std::fs::metadata(path).ok()?;
        if !metadata.is_file() {
            return None;
        }
        let modified_ms = metadata
            .modified()
            .ok()?
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_millis() as i64;
        Some(DumpFileMeta {
            path: path.to_path_buf(),
            size_bytes: metadata.len(),
            modified_ms,
        })
    }
}

impl DumpSource for WindowsDumpSource {
    fn discover(&mut self) -> Vec<DumpFileMeta> {
        let mut found = Vec::new();
        let system_root = Self::system_root();
        Self::push_dump_files(&system_root.join("Minidump"), &mut found);
        if let Some(meta) = Self::meta_for(&system_root.join("MEMORY.DMP")) {
            found.push(meta);
        }
        // Per-user WER dumps: every profile the collector can enumerate.
        // LocalSystem can enter all of them; an unelevated dev run sees
        // only its own profile and degrades silently on the rest.
        if let Ok(profiles) = std::fs::read_dir(Self::users_root()) {
            for profile in profiles.flatten() {
                let crash_dumps = profile.path().join("AppData").join("Local").join("CrashDumps");
                Self::push_dump_files(&crash_dumps, &mut found);
            }
        }
        found.sort_by(|a, b| a.path.cmp(&b.path));
        found
    }

    fn triage(&mut self, path: &Path) -> Result<DumpTriage> {
        let mut file = std::fs::File::open(path)
            .with_context(|| format!("failed to open {}", path.display()))?;
        let mut prefix = [0_u8; KERNEL_HEADER_PREFIX_BYTES];
        let read = {
            let mut filled = 0;
            loop {
                match file.read(&mut prefix[filled..]) {
                    Ok(0) => break filled,
                    Ok(bytes) => filled += bytes,
                    Err(error) => return Err(error.into()),
                }
            }
        };
        let prefix = &prefix[..read];
        if prefix.len() >= 8 && &prefix[0..4] == b"PAGE" {
            return Ok(parse_kernel_header(prefix).unwrap_or(DumpTriage::Unrecognized));
        }
        if prefix.len() >= 4 && &prefix[0..4] == b"MDMP" {
            return parse_minidump(&mut file);
        }
        Ok(DumpTriage::Unrecognized)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    // -- synthetic dump builders ------------------------------------------

    fn kernel_dump_64(code: u32, parameters: [u64; 4]) -> Vec<u8> {
        let mut bytes = vec![0x45_u8; 0x1000]; // PAGE filler byte
        bytes[0..8].copy_from_slice(b"PAGEDU64");
        bytes[0x38..0x3C].copy_from_slice(&code.to_le_bytes());
        for (index, parameter) in parameters.iter().enumerate() {
            let offset = 0x40 + index * 8;
            bytes[offset..offset + 8].copy_from_slice(&parameter.to_le_bytes());
        }
        bytes
    }

    fn kernel_dump_32(code: u32, parameters: [u32; 4]) -> Vec<u8> {
        let mut bytes = vec![0x45_u8; 0x1000];
        bytes[0..8].copy_from_slice(b"PAGEDUMP");
        bytes[0x28..0x2C].copy_from_slice(&code.to_le_bytes());
        for (index, parameter) in parameters.iter().enumerate() {
            let offset = 0x2C + index * 4;
            bytes[offset..offset + 4].copy_from_slice(&parameter.to_le_bytes());
        }
        bytes
    }

    /// A minimal MDMP: header, two directory entries (exception stream and
    /// module list), one module (`ntdll.dll`) containing the exception
    /// address.
    fn user_minidump(exception_code: u32, exception_address: u64) -> Vec<u8> {
        let mut bytes = vec![0_u8; 4096];
        bytes[0..4].copy_from_slice(b"MDMP");
        bytes[8..12].copy_from_slice(&2_u32.to_le_bytes()); // stream count
        bytes[12..16].copy_from_slice(&32_u32.to_le_bytes()); // directory rva
        // Directory entry 0: exception stream (type 6) at 0x100.
        bytes[32..36].copy_from_slice(&6_u32.to_le_bytes());
        bytes[36..40].copy_from_slice(&168_u32.to_le_bytes());
        bytes[40..44].copy_from_slice(&0x100_u32.to_le_bytes());
        // Directory entry 1: module list (type 4) at 0x300.
        bytes[44..48].copy_from_slice(&4_u32.to_le_bytes());
        bytes[48..52].copy_from_slice(&(4_u32 + 108).to_le_bytes());
        bytes[52..56].copy_from_slice(&0x300_u32.to_le_bytes());
        // Exception stream: code at +8, address at +24.
        bytes[0x108..0x10C].copy_from_slice(&exception_code.to_le_bytes());
        bytes[0x118..0x120].copy_from_slice(&exception_address.to_le_bytes());
        // Module list: one module, base 0x7ff8_0000_0000, size 0x20_0000.
        bytes[0x300..0x304].copy_from_slice(&1_u32.to_le_bytes());
        let module = 0x304;
        bytes[module..module + 8].copy_from_slice(&0x7ff8_0000_0000_u64.to_le_bytes());
        bytes[module + 8..module + 12].copy_from_slice(&0x20_0000_u32.to_le_bytes());
        bytes[module + 20..module + 24].copy_from_slice(&0x400_u32.to_le_bytes()); // name rva
        // MINIDUMP_STRING at 0x400: UTF-16 "C:\\Windows\\System32\\ntdll.dll".
        let name: Vec<u16> = r"C:\Windows\System32\ntdll.dll".encode_utf16().collect();
        bytes[0x400..0x404].copy_from_slice(&((name.len() * 2) as u32).to_le_bytes());
        for (index, character) in name.iter().enumerate() {
            let offset = 0x404 + index * 2;
            bytes[offset..offset + 2].copy_from_slice(&character.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn kernel_header_64_parses_bugcheck_and_parameters() {
        let bytes = kernel_dump_64(0x133, [0x1, 0x1e00, 0, 0]);
        assert_eq!(
            parse_kernel_header(&bytes),
            Some(DumpTriage::Kernel {
                bugcheck_code: 0x133,
                parameters: [0x1, 0x1e00, 0, 0],
            })
        );
    }

    #[test]
    fn kernel_header_32_parses_bugcheck_and_parameters() {
        let bytes = kernel_dump_32(0x50, [0xdead, 0x1, 0xbeef, 0x2]);
        assert_eq!(
            parse_kernel_header(&bytes),
            Some(DumpTriage::Kernel {
                bugcheck_code: 0x50,
                parameters: [0xdead, 0x1, 0xbeef, 0x2],
            })
        );
    }

    #[test]
    fn minidump_parses_exception_and_faulting_module() {
        let bytes = user_minidump(0xC000_0005, 0x7ff8_0010_1000);
        let triage = parse_minidump(&mut Cursor::new(bytes)).expect("parse");
        assert_eq!(
            triage,
            DumpTriage::UserMode {
                exception_code: Some(0xC000_0005),
                faulting_module: Some("ntdll.dll".into()),
            }
        );
    }

    #[test]
    fn minidump_address_outside_all_modules_yields_no_module() {
        let bytes = user_minidump(0xC000_0374, 0x1000);
        let triage = parse_minidump(&mut Cursor::new(bytes)).expect("parse");
        assert_eq!(
            triage,
            DumpTriage::UserMode {
                exception_code: Some(0xC000_0374),
                faulting_module: None,
            }
        );
    }

    #[test]
    fn minidump_without_exception_stream_is_a_hang_dump() {
        let mut bytes = user_minidump(0, 0);
        // Rewrite the exception directory entry to an unknown stream type.
        bytes[32..36].copy_from_slice(&99_u32.to_le_bytes());
        let triage = parse_minidump(&mut Cursor::new(bytes)).expect("parse");
        assert_eq!(
            triage,
            DumpTriage::UserMode {
                exception_code: None,
                faulting_module: None,
            }
        );
    }

    #[test]
    fn labels_cover_known_and_unknown_codes() {
        assert_eq!(bugcheck_label(0x133), "0x133 DPC_WATCHDOG_VIOLATION");
        assert_eq!(bugcheck_label(0xEF), "0xef CRITICAL_PROCESS_DIED");
        assert_eq!(bugcheck_label(0xABCDEF), "0xabcdef");
        assert_eq!(exception_label(0xC000_0005), "0xc0000005 ACCESS_VIOLATION");
        assert_eq!(exception_label(0x1234), "0x00001234");
    }

    #[test]
    fn wer_file_names_recover_the_process_image() {
        assert_eq!(
            user_dump_process_name(Path::new(r"C:\Users\x\AppData\Local\CrashDumps\LEDKeeper2.exe.16656.dmp")),
            Some("LEDKeeper2.exe".into())
        );
        assert_eq!(
            user_dump_process_name(Path::new(r"C:\Windows\MEMORY.DMP")),
            None
        );
        assert_eq!(
            user_dump_process_name(Path::new(r"C:\Windows\Minidump\081026-9906-01.dmp")),
            None
        );
    }

    #[test]
    fn size_and_age_formatting() {
        assert_eq!(format_size(1_288_490_189), "1.2 GB");
        assert_eq!(format_size(45_320_979), "43.2 MB");
        assert_eq!(format_size(262_144), "256 KB");
        assert_eq!(format_age(2 * 24 * 3_600_000 + 3_600_000), "2 d ago");
        assert_eq!(format_age(5 * 3_600_000), "5 h ago");
        assert_eq!(format_age(90_000), "1 min ago");
    }

    // -- engine tests ------------------------------------------------------

    #[derive(Default)]
    struct StubSource {
        discover_calls: usize,
        triage_calls: usize,
        files: Vec<DumpFileMeta>,
        triages: HashMap<PathBuf, DumpTriage>,
        fail_triage: bool,
    }

    impl DumpSource for StubSource {
        fn discover(&mut self) -> Vec<DumpFileMeta> {
            self.discover_calls += 1;
            self.files.clone()
        }

        fn triage(&mut self, path: &Path) -> Result<DumpTriage> {
            self.triage_calls += 1;
            if self.fail_triage {
                anyhow::bail!("access denied");
            }
            Ok(self
                .triages
                .get(path)
                .cloned()
                .unwrap_or(DumpTriage::Unrecognized))
        }
    }

    fn meta(path: &str, modified_ms: i64) -> DumpFileMeta {
        DumpFileMeta {
            path: PathBuf::from(path),
            size_bytes: 45_320_979,
            modified_ms,
        }
    }

    fn engine_with(
        files: Vec<DumpFileMeta>,
        triages: Vec<(&str, DumpTriage)>,
    ) -> DumpEngine<StubSource> {
        DumpEngine::new(StubSource {
            files,
            triages: triages
                .into_iter()
                .map(|(path, triage)| (PathBuf::from(path), triage))
                .collect(),
            ..StubSource::default()
        })
    }

    const HOUR_MS: i64 = 3_600_000;

    #[test]
    fn cadence_first_scan_is_delayed_then_five_minutes_apart() {
        let mut engine = engine_with(Vec::new(), Vec::new());
        assert!(engine.observe(0).is_empty());
        assert_eq!(engine.source().discover_calls, 0, "no scan on first observe");
        engine.observe(FIRST_SCAN_DELAY_MS - 1);
        assert_eq!(engine.source().discover_calls, 0, "not due yet");
        engine.observe(FIRST_SCAN_DELAY_MS);
        assert_eq!(engine.source().discover_calls, 1, "first scan fires");
        engine.observe(FIRST_SCAN_DELAY_MS + SCAN_INTERVAL_MS - 1);
        assert_eq!(engine.source().discover_calls, 1);
        engine.observe(FIRST_SCAN_DELAY_MS + SCAN_INTERVAL_MS);
        assert_eq!(engine.source().discover_calls, 2);
    }

    #[test]
    fn fresh_kernel_dump_is_critical_and_stale_is_warning() {
        let now = 100 * 24 * HOUR_MS;
        let kernel = DumpTriage::Kernel {
            bugcheck_code: 0x133,
            parameters: [0x1, 0x1e00, 0, 0],
        };
        let mut engine = engine_with(
            vec![
                meta(r"C:\Windows\Minidump\fresh.dmp", now - HOUR_MS),
                meta(r"C:\Windows\Minidump\stale.dmp", now - 90 * 24 * HOUR_MS),
            ],
            vec![
                (r"C:\Windows\Minidump\fresh.dmp", kernel.clone()),
                (r"C:\Windows\Minidump\stale.dmp", kernel),
            ],
        );
        engine.observe(now - FIRST_SCAN_DELAY_MS);
        let changed = engine.observe(now);
        assert_eq!(changed.len(), 2);
        let fresh = changed
            .iter()
            .find(|alert| alert.evidence.iter().any(|e| e.value.contains("fresh")))
            .expect("fresh finding");
        let stale = changed
            .iter()
            .find(|alert| alert.evidence.iter().any(|e| e.value.contains("stale")))
            .expect("stale finding");
        assert_eq!(fresh.severity, Severity::Critical);
        assert_eq!(stale.severity, Severity::Warning);
        assert_eq!(fresh.kind, "crashDump");
        let bugcheck = fresh
            .evidence
            .iter()
            .find(|e| e.label == "Bugcheck")
            .expect("bugcheck row");
        assert_eq!(bugcheck.value, "0x133 DPC_WATCHDOG_VIOLATION");
        let parameters = fresh
            .evidence
            .iter()
            .find(|e| e.label == "Parameters")
            .expect("parameters row");
        assert_eq!(parameters.value, "0x1 0x1e00 0x0 0x0");
        // Only the fresh dump falls inside the 30-day crash-count window.
        let count = fresh
            .evidence
            .iter()
            .find(|e| e.label == "Crash count")
            .expect("count row");
        assert_eq!(count.value, "1 dump in 30 days");
    }

    #[test]
    fn user_dump_finding_carries_module_process_and_redacted_path() {
        let now = 40 * 24 * HOUR_MS;
        let path = r"C:\Users\alice\AppData\Local\CrashDumps\LEDKeeper2.exe.16656.dmp";
        let mut engine = engine_with(
            vec![meta(path, now - 2 * 24 * HOUR_MS)],
            vec![(
                path,
                DumpTriage::UserMode {
                    exception_code: Some(0xC000_0005),
                    faulting_module: Some("ndis.sys".into()),
                },
            )],
        );
        engine.observe(0);
        let changed = engine.observe(FIRST_SCAN_DELAY_MS.max(now));
        assert_eq!(changed.len(), 1);
        let alert = &changed[0];
        assert_eq!(alert.severity, Severity::Warning);
        assert_eq!(alert.process_name.as_deref(), Some("LEDKeeper2.exe"));
        assert_eq!(alert.process_id, None);
        let exception = alert
            .evidence
            .iter()
            .find(|e| e.label == "Exception")
            .expect("exception row");
        assert_eq!(exception.value, "0xc0000005 ACCESS_VIOLATION");
        let module = alert
            .evidence
            .iter()
            .find(|e| e.label == "Faulting module")
            .expect("module row");
        assert_eq!(module.value, "ndis.sys");
        let dump = alert
            .evidence
            .iter()
            .find(|e| e.label == "Dump")
            .expect("dump row");
        assert!(dump.value.starts_with(r"%USERPROFILE%\AppData\Local\CrashDumps"),
            "user path must be redacted: {}", dump.value);
        assert!(dump.value.contains("43.2 MB"));
        assert!(dump.value.contains("2 d ago"));
    }

    #[test]
    fn triage_is_cached_by_path_and_mtime() {
        let now = 40 * 24 * HOUR_MS;
        let path = r"C:\Windows\Minidump\a.dmp";
        let mut engine = engine_with(
            vec![meta(path, 1_000)],
            vec![(
                path,
                DumpTriage::Kernel {
                    bugcheck_code: 0x9F,
                    parameters: [0; 4],
                },
            )],
        );
        engine.observe(0);
        engine.observe(now);
        engine.observe(now + SCAN_INTERVAL_MS);
        engine.observe(now + 2 * SCAN_INTERVAL_MS);
        assert_eq!(engine.source().triage_calls, 1, "one header read per identity");
        // A rewritten dump (same path, new mtime) is re-triaged.
        engine.source_mut().files = vec![meta(path, 2_000)];
        engine.observe(now + 3 * SCAN_INTERVAL_MS);
        assert_eq!(engine.source().triage_calls, 2);
    }

    #[test]
    fn disappearing_dump_resolves_its_finding() {
        let now = 40 * 24 * HOUR_MS;
        let path = r"C:\Windows\Minidump\gone.dmp";
        let mut engine = engine_with(
            vec![meta(path, 1_000)],
            vec![(
                path,
                DumpTriage::Kernel {
                    bugcheck_code: 0xEF,
                    parameters: [0; 4],
                },
            )],
        );
        engine.observe(0);
        let fired = engine.observe(now);
        assert_eq!(fired.len(), 1);
        let id = fired[0].id.clone();
        assert!(id.starts_with("crashDump:"));
        assert_eq!(engine.active_alerts().len(), 1);
        engine.source_mut().files = Vec::new();
        let resolved = engine.observe(now + SCAN_INTERVAL_MS);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].id, id, "same deterministic identity");
        assert!(resolved[0].resolved_at_ms.is_some());
        assert!(engine.active_alerts().is_empty());
        // Nothing further changes while nothing exists.
        assert!(engine.observe(now + 2 * SCAN_INTERVAL_MS).is_empty());
    }

    #[test]
    fn degraded_triage_still_surfaces_the_dump() {
        let now = 40 * 24 * HOUR_MS;
        let mut engine = engine_with(vec![meta(r"C:\Windows\MEMORY.DMP", 1_000)], Vec::new());
        engine.source_mut().fail_triage = true;
        engine.observe(0);
        let changed = engine.observe(now);
        assert_eq!(changed.len(), 1);
        let triage = changed[0]
            .evidence
            .iter()
            .find(|e| e.label == "Triage")
            .expect("triage row");
        assert!(triage.value.contains("degraded"));
        assert!(triage.value.contains("access denied"));
    }

    #[test]
    fn finding_ids_are_stable_and_distinct() {
        let a = finding_id(&meta(r"C:\Windows\Minidump\a.dmp", 1_000));
        let same = finding_id(&meta(r"c:\windows\minidump\A.DMP", 1_000));
        let other_time = finding_id(&meta(r"C:\Windows\Minidump\a.dmp", 2_000));
        let other_path = finding_id(&meta(r"C:\Windows\Minidump\b.dmp", 1_000));
        assert_eq!(a, same, "case-insensitive path identity");
        assert_ne!(a, other_time);
        assert_ne!(a, other_path);
    }

    #[test]
    #[ignore = "dev harness: scans this machine's real dump locations and prints the native triage of every dump found"]
    fn dev_probe_real_dump_scan() {
        let mut engine = DumpEngine::new(WindowsDumpSource);
        let now_ms = chrono::Utc::now().timestamp_millis();
        engine.observe(now_ms - FIRST_SCAN_DELAY_MS);
        let changed = engine.observe(now_ms);
        if changed.is_empty() {
            println!("no crash dumps found in the standard locations on this machine");
            return;
        }
        println!("{} crash-dump findings:", changed.len());
        for alert in &changed {
            println!(
                "[{:?}] {} ({})",
                alert.severity,
                alert.title,
                alert.process_name.as_deref().unwrap_or("system"),
            );
            for evidence in &alert.evidence {
                println!("    {} = {}", evidence.label, evidence.value);
            }
        }
    }
}
