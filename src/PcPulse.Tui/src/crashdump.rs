//! On-demand deep crash-dump analysis through WinDbg's `cdb`.
//!
//! The collector's native triage (service `metrics::dumps`) reads bugcheck
//! and exception codes without symbols and without network. This module is
//! the opt-in second tier, mirroring `analyzer.rs`'s Codex pattern: find
//! the locally installed debugger, spawn `cdb -z <dump> -c "!analyze -v; q"`
//! under a timeout, preserve the output as evidence, and parse the headline
//! `!analyze` fields into a bounded [`CrashAnalysis`].
//!
//! Network boundary: this is the **only** place in PC Pulse that touches
//! the network for diagnostics, and only when the user explicitly asks for
//! a deep analysis — `cdb` is passed the Microsoft public symbol server
//! (`msdl.microsoft.com`) with a local cache under
//! `%LOCALAPPDATA%\PcPulse\symbols`. The service-side scanner never does
//! this.
//!
//! Not yet wired into the UI: the key binding and findings-screen action
//! land in a later pass. The public surface is [`find_cdb`],
//! [`analyze_dump`], and [`CrashAnalysis::summarize`], which produces
//! evidence-style rows ready for that wiring and for the Oracle bundle.

use anyhow::{Context, Result, anyhow, bail};
use pcpulse_service::models::Evidence;
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

const DEFAULT_CDB_TIMEOUT_SECS: u64 = 120;
const MIN_CDB_TIMEOUT_SECS: u64 = 30;
const MAX_CDB_TIMEOUT_SECS: u64 = 1_800;
/// Preserved analysis logs rotate through this many slots.
const ANALYSIS_LOG_SLOTS: u32 = 3;
/// Preserved log and parsed-output byte bounds.
const MAX_ANALYSIS_LOG_BYTES: usize = 256 * 1_024;
const MAX_PARSE_BYTES: usize = 4 * 1_024 * 1_024;
const MAX_FIELD_CHARS: usize = 160;

/// The active cdb wait budget in seconds: `PCPULSE_CDB_TIMEOUT_SECS`
/// clamped to 30..=1800, defaulting to 120 when unset or unparsable.
/// First-time symbol downloads can be slow; raise the budget rather than
/// pre-downloading symbols.
pub fn cdb_timeout_secs() -> u64 {
    clamp_timeout_secs(env::var("PCPULSE_CDB_TIMEOUT_SECS").ok().as_deref())
}

fn clamp_timeout_secs(value: Option<&str>) -> u64 {
    value
        .and_then(|text| text.trim().parse::<u64>().ok())
        .map_or(DEFAULT_CDB_TIMEOUT_SECS, |seconds| {
            seconds.clamp(MIN_CDB_TIMEOUT_SECS, MAX_CDB_TIMEOUT_SECS)
        })
}

/// The headline fields of a `!analyze -v` run. Every field is optional —
/// a partial parse (missing symbols, unusual dump) keeps whatever cdb
/// did establish rather than failing the run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CrashAnalysis {
    /// `BUGCHECK_STR`, e.g. `0x133` (kernel dumps only).
    pub bugcheck: Option<String>,
    /// `FAILURE_BUCKET_ID`, e.g. `AV_ndis!NdisReturnNetBufferLists`.
    pub failure_bucket: Option<String>,
    /// `IMAGE_NAME`, e.g. `ndis.sys`.
    pub image_name: Option<String>,
    /// `MODULE_NAME`, e.g. `ndis`.
    pub module_name: Option<String>,
    /// `PROCESS_NAME`, e.g. `System` or `LEDKeeper2.exe`.
    pub process_name: Option<String>,
    /// `SYMBOL_NAME`, e.g. `ndis!NdisReturnNetBufferLists+2a`.
    pub symbol_name: Option<String>,
    /// Where the full cdb output was preserved, when it could be written.
    pub log_path: Option<PathBuf>,
    /// Wall-clock seconds the analysis took.
    pub duration_secs: u64,
}

impl CrashAnalysis {
    /// True when cdb produced at least one attribution field.
    pub fn has_findings(&self) -> bool {
        self.bugcheck.is_some()
            || self.failure_bucket.is_some()
            || self.image_name.is_some()
            || self.module_name.is_some()
            || self.symbol_name.is_some()
    }

    /// Bounded evidence-style rows for the findings screen and the Oracle
    /// bundle. Only fields cdb actually produced appear; nothing is
    /// fabricated for a symbol-less or partial analysis.
    pub fn summarize(&self) -> Vec<Evidence> {
        let mut rows = Vec::new();
        let mut push = |label: &str, value: &Option<String>| {
            if let Some(value) = value {
                rows.push(Evidence {
                    label: label.into(),
                    value: truncate(value, MAX_FIELD_CHARS),
                });
            }
        };
        push("Failure bucket", &self.failure_bucket);
        push("Bugcheck", &self.bugcheck);
        push("Faulting image", &self.image_name);
        push("Module", &self.module_name);
        push("Symbol", &self.symbol_name);
        push("Process", &self.process_name);
        if let Some(log) = &self.log_path
            && let Some(name) = log.file_name()
        {
            rows.push(Evidence {
                label: "Analysis log".into(),
                value: name.to_string_lossy().into_owned(),
            });
        }
        rows.push(Evidence {
            label: "Analysis time".into(),
            value: format!("{} s", self.duration_secs),
        });
        rows
    }
}

/// Locates the WinDbg command-line debugger, probing the standard install
/// locations before PATH:
///
/// 1. `PCPULSE_CDB_PATH` (explicit override, used as-is),
/// 2. the Windows SDK Debugging Tools (`Windows Kits\10\Debuggers\x64\cdb.exe`
///    under both Program Files roots),
/// 3. the winget/Store WinDbg app-execution aliases — the Store package
///    exposes `cdbX64.exe` (not `cdb.exe`) under
///    `%LOCALAPPDATA%\Microsoft\WindowsApps`, verified against a real
///    `Microsoft.WinDbg` install,
/// 4. `cdb.exe` on PATH, last.
pub fn find_cdb() -> Option<PathBuf> {
    if let Some(explicit) = env::var_os("PCPULSE_CDB_PATH") {
        let path = PathBuf::from(explicit);
        return path.is_file().then_some(path);
    }
    let mut candidates: Vec<PathBuf> = Vec::new();
    for root in ["ProgramFiles(x86)", "ProgramFiles"] {
        if let Some(programs) = env::var_os(root) {
            candidates.push(
                PathBuf::from(programs)
                    .join(r"Windows Kits\10\Debuggers\x64\cdb.exe"),
            );
        }
    }
    if let Some(local) = env::var_os("LOCALAPPDATA") {
        let aliases = PathBuf::from(local).join(r"Microsoft\WindowsApps");
        candidates.push(aliases.join("cdbX64.exe"));
        candidates.push(aliases.join("cdb.exe"));
    }
    for candidate in candidates {
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    let path = env::var_os("PATH")?;
    env::split_paths(&path)
        .map(|directory| directory.join("cdb.exe"))
        .find(|candidate| candidate.is_file())
}

/// Runs `cdb -z <dump> -c "!analyze -v; q"` with the Microsoft public
/// symbol server and a local cache, preserves the full output to a rotated
/// `%LOCALAPPDATA%\PcPulse\crash-analysis-<n>.log`, and parses the
/// headline fields. Cancellable and bounded by [`cdb_timeout_secs`].
pub fn analyze_dump(dump: &Path, cancelled: Arc<AtomicBool>) -> Result<CrashAnalysis> {
    let executable = find_cdb().ok_or_else(|| {
        anyhow!(
            "cdb.exe was not found; install the Debugging Tools for Windows (winget install Microsoft.WinDbg, or the Windows SDK) or set PCPULSE_CDB_PATH"
        )
    })?;
    if !dump.is_file() {
        bail!("dump file {} does not exist or is not readable", dump.display());
    }
    let started = Instant::now();
    let scratch = ScratchOutputs::create()?;
    let mut child = spawn_cdb(&executable, dump, &scratch)?;
    let wait = wait_for_cdb(
        &mut child,
        &cancelled,
        Duration::from_secs(cdb_timeout_secs()),
    );
    // Preserve whatever cdb wrote — on success, timeout, or failure — so
    // the evidence survives scratch cleanup, exactly like analyzer.rs
    // preserves the Codex stderr tail.
    let output = read_bounded(&scratch.stdout_path, MAX_PARSE_BYTES).unwrap_or_default();
    let stderr = read_bounded(&scratch.stderr_path, 8 * 1_024).unwrap_or_default();
    let log_path = preserve_analysis_log(dump, &output, &stderr).ok();
    wait?;
    if output.trim().is_empty() {
        bail!(
            "cdb exited without producing analysis output{}",
            log_path
                .as_deref()
                .map(|path| format!(" · details: {}", path.display()))
                .unwrap_or_default()
        );
    }
    let mut analysis = parse_analyze_output(&output);
    analysis.log_path = log_path;
    analysis.duration_secs = started.elapsed().as_secs();
    Ok(analysis)
}

fn spawn_cdb(executable: &Path, dump: &Path, scratch: &ScratchOutputs) -> Result<Child> {
    let stdout = fs::File::create(&scratch.stdout_path)
        .context("failed to create cdb output capture")?;
    let stderr = fs::File::create(&scratch.stderr_path)
        .context("failed to create cdb diagnostic capture")?;
    let symbol_path = format!(
        "srv*{}*https://msdl.microsoft.com/download/symbols",
        symbol_cache_dir().display()
    );
    Command::new(executable)
        .arg("-z")
        .arg(dump)
        .arg("-y")
        .arg(&symbol_path)
        .args(["-c", "!analyze -v; q"])
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .with_context(|| format!("failed to start cdb at {}", executable.display()))
}

/// Mirrors `analyzer.rs`'s `wait_for_codex`: poll, honor cancellation,
/// kill on timeout, and always reap the child.
fn wait_for_cdb(child: &mut Child, cancelled: &AtomicBool, timeout: Duration) -> Result<()> {
    let started = Instant::now();
    loop {
        if cancelled.load(Ordering::Acquire) {
            let _ = child.kill();
            let _ = child.wait();
            bail!("crash-dump analysis was cancelled");
        }
        if let Some(status) = child
            .try_wait()
            .context("failed to monitor the cdb analysis")?
        {
            if !status.success() {
                bail!("cdb analysis failed ({status})");
            }
            return Ok(());
        }
        if started.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            bail!(
                "cdb analysis timed out after {}s (budget {}s, set PCPULSE_CDB_TIMEOUT_SECS to adjust; first runs download symbols)",
                started.elapsed().as_secs(),
                timeout.as_secs()
            );
        }
        thread::sleep(Duration::from_millis(200));
    }
}

/// Extracts the headline `KEY: value` fields `!analyze -v` prints. The
/// keys appear once per analysis; a repeated key keeps the first value.
pub fn parse_analyze_output(output: &str) -> CrashAnalysis {
    let mut analysis = CrashAnalysis::default();
    for line in output.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        let slot = match key.trim() {
            "FAILURE_BUCKET_ID" => &mut analysis.failure_bucket,
            "IMAGE_NAME" => &mut analysis.image_name,
            "MODULE_NAME" => &mut analysis.module_name,
            "PROCESS_NAME" => &mut analysis.process_name,
            "SYMBOL_NAME" => &mut analysis.symbol_name,
            "BUGCHECK_STR" => &mut analysis.bugcheck,
            _ => continue,
        };
        if slot.is_none() {
            *slot = Some(value.to_string());
        }
    }
    analysis
}

fn truncate(value: &str, maximum_chars: usize) -> String {
    if value.chars().count() <= maximum_chars {
        return value.to_string();
    }
    let mut result: String = value.chars().take(maximum_chars.saturating_sub(1)).collect();
    result.push('…');
    result
}

fn pcpulse_local_dir() -> Option<PathBuf> {
    env::var_os("LOCALAPPDATA").map(|root| PathBuf::from(root).join("PcPulse"))
}

fn symbol_cache_dir() -> PathBuf {
    pcpulse_local_dir()
        .unwrap_or_else(env::temp_dir)
        .join("symbols")
}

/// Writes the bounded cdb output to `crash-analysis-<n>.log`, cycling
/// through [`ANALYSIS_LOG_SLOTS`] slots by overwriting the oldest.
fn preserve_analysis_log(dump: &Path, output: &str, stderr: &str) -> Result<PathBuf> {
    let directory =
        pcpulse_local_dir().ok_or_else(|| anyhow!("LOCALAPPDATA is not defined"))?;
    fs::create_dir_all(&directory)
        .with_context(|| format!("failed to create {}", directory.display()))?;
    let slot = (1..=ANALYSIS_LOG_SLOTS)
        .map(|index| directory.join(format!("crash-analysis-{index}.log")))
        .min_by_key(|path| {
            fs::metadata(path)
                .and_then(|metadata| metadata.modified())
                .ok()
        })
        .unwrap_or_else(|| directory.join("crash-analysis-1.log"));
    let mut contents = format!(
        "PC Pulse crash-dump analysis of {} at {}\r\n\r\n",
        dump.display(),
        chrono::Utc::now().to_rfc3339()
    );
    contents.push_str(output);
    if !stderr.trim().is_empty() {
        contents.push_str("\r\n\r\ncdb stderr:\r\n");
        contents.push_str(stderr);
    }
    if contents.len() > MAX_ANALYSIS_LOG_BYTES {
        let mut boundary = MAX_ANALYSIS_LOG_BYTES;
        while !contents.is_char_boundary(boundary) {
            boundary -= 1;
        }
        contents.truncate(boundary);
    }
    fs::write(&slot, contents).with_context(|| format!("failed to write {}", slot.display()))?;
    Ok(slot)
}

fn read_bounded(path: &Path, maximum: usize) -> Result<String> {
    let bytes = fs::read(path)?;
    let start = bytes.len().saturating_sub(maximum);
    Ok(String::from_utf8_lossy(&bytes[start..]).to_string())
}

struct ScratchOutputs {
    directory: PathBuf,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
}

impl ScratchOutputs {
    fn create() -> Result<Self> {
        let directory = env::temp_dir().join(format!(
            "PcPulse-CrashDump-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_millis()
        ));
        fs::create_dir(&directory)
            .with_context(|| format!("failed to create {}", directory.display()))?;
        Ok(Self {
            stdout_path: directory.join("cdb.stdout.log"),
            stderr_path: directory.join("cdb.stderr.log"),
            directory,
        })
    }
}

impl Drop for ScratchOutputs {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.stdout_path);
        let _ = fs::remove_file(&self.stderr_path);
        let _ = fs::remove_dir(&self.directory);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KERNEL_ANALYZE_OUTPUT: &str = r#"
Microsoft (R) Windows Debugger Version 10.0.27829.1001 AMD64
Loading Dump File [C:\Windows\Minidump\081026-9906-01.dmp]
Mini Kernel Dump File: Only registers and stack trace are available

*******************************************************************************
*                        Bugcheck Analysis                                    *
*******************************************************************************

DPC_WATCHDOG_VIOLATION (133)
The DPC watchdog detected a prolonged run time at an IRQL of DISPATCH_LEVEL
or above.
Arguments:
Arg1: 0000000000000001, The system cumulatively spent an extended period of time
Arg2: 0000000000001e00, The watchdog period (in ticks).

BUGCHECK_STR:  0x133

PROCESS_NAME:  System

STACK_TEXT:
fffff803`4f2f5c88 fffff803`4e0d1a4a     : nt!KeBugCheckEx

SYMBOL_NAME:  ndis!NdisReturnNetBufferLists+2a

MODULE_NAME: ndis

IMAGE_NAME:  ndis.sys

FAILURE_BUCKET_ID:  0x133_DPC_ndis!NdisReturnNetBufferLists

Followup:     MachineOwner
---------
"#;

    #[test]
    fn parses_the_headline_fields_from_kernel_analyze_output() {
        let analysis = parse_analyze_output(KERNEL_ANALYZE_OUTPUT);
        assert_eq!(analysis.bugcheck.as_deref(), Some("0x133"));
        assert_eq!(
            analysis.failure_bucket.as_deref(),
            Some("0x133_DPC_ndis!NdisReturnNetBufferLists")
        );
        assert_eq!(analysis.image_name.as_deref(), Some("ndis.sys"));
        assert_eq!(analysis.module_name.as_deref(), Some("ndis"));
        assert_eq!(analysis.process_name.as_deref(), Some("System"));
        assert_eq!(
            analysis.symbol_name.as_deref(),
            Some("ndis!NdisReturnNetBufferLists+2a")
        );
        assert!(analysis.has_findings());
    }

    #[test]
    fn parses_user_mode_analyze_output() {
        let output = "PROCESS_NAME:  LEDKeeper2.exe\r\nSYMBOL_NAME:  RzChromaConnectAPI!Unknown+1a2b\r\nMODULE_NAME: RzChromaConnectAPI\r\nIMAGE_NAME:  RzChromaConnectAPI.dll\r\nFAILURE_BUCKET_ID:  NULL_POINTER_READ_c0000005_RzChromaConnectAPI.dll!Unknown\r\n";
        let analysis = parse_analyze_output(output);
        assert_eq!(analysis.bugcheck, None, "user dumps have no BUGCHECK_STR");
        assert_eq!(analysis.process_name.as_deref(), Some("LEDKeeper2.exe"));
        assert_eq!(analysis.image_name.as_deref(), Some("RzChromaConnectAPI.dll"));
        assert_eq!(
            analysis.failure_bucket.as_deref(),
            Some("NULL_POINTER_READ_c0000005_RzChromaConnectAPI.dll!Unknown")
        );
    }

    #[test]
    fn unrelated_colon_lines_and_empty_values_are_ignored() {
        let output = "STACK_TEXT:\r\nfffff803 : nt!KeBugCheckEx\r\nIMAGE_NAME:\r\nFAILURE_BUCKET_ID:  BUCKET\r\nFAILURE_BUCKET_ID:  SECOND_IGNORED\r\n";
        let analysis = parse_analyze_output(output);
        assert_eq!(analysis.image_name, None, "empty value stays None");
        assert_eq!(analysis.failure_bucket.as_deref(), Some("BUCKET"));
        assert!(!parse_analyze_output("no fields here").has_findings());
    }

    #[test]
    fn summary_rows_are_bounded_and_only_present_fields_appear() {
        let mut analysis = parse_analyze_output(KERNEL_ANALYZE_OUTPUT);
        analysis.log_path = Some(PathBuf::from(
            r"C:\Users\x\AppData\Local\PcPulse\crash-analysis-2.log",
        ));
        analysis.duration_secs = 41;
        let rows = analysis.summarize();
        let labels: Vec<&str> = rows.iter().map(|row| row.label.as_str()).collect();
        assert_eq!(
            labels,
            vec![
                "Failure bucket",
                "Bugcheck",
                "Faulting image",
                "Module",
                "Symbol",
                "Process",
                "Analysis log",
                "Analysis time",
            ]
        );
        assert_eq!(rows[6].value, "crash-analysis-2.log");
        assert_eq!(rows[7].value, "41 s");
        let empty = CrashAnalysis::default().summarize();
        assert_eq!(empty.len(), 1, "only the duration row without findings");
        // Long fields are truncated with an ellipsis.
        let long = CrashAnalysis {
            failure_bucket: Some("B".repeat(400)),
            ..CrashAnalysis::default()
        };
        let row = &long.summarize()[0];
        assert!(row.value.chars().count() <= MAX_FIELD_CHARS);
        assert!(row.value.ends_with('…'));
    }

    #[test]
    fn timeout_budget_is_defaulted_and_clamped() {
        assert_eq!(clamp_timeout_secs(None), 120);
        assert_eq!(clamp_timeout_secs(Some("garbage")), 120);
        assert_eq!(clamp_timeout_secs(Some("5")), 30);
        assert_eq!(clamp_timeout_secs(Some("99999")), 1_800);
        assert_eq!(clamp_timeout_secs(Some(" 300 ")), 300);
    }

    #[test]
    fn wait_kills_the_child_on_timeout() {
        let mut child = Command::new("ping")
            .args(["-n", "30", "127.0.0.1"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn ping");
        let cancelled = AtomicBool::new(false);
        let error = wait_for_cdb(&mut child, &cancelled, Duration::from_millis(250))
            .expect_err("must time out")
            .to_string();
        assert!(error.contains("timed out after"), "{error}");
        assert!(
            child.try_wait().expect("query child").is_some(),
            "child must be reaped after timeout"
        );
    }

    #[test]
    #[ignore = "dev harness: runs the real cdb !analyze against the newest crash dump on this machine, when both exist"]
    fn dev_probe_real_cdb_analysis() {
        use pcpulse_service::metrics::dumps::{DumpSource, WindowsDumpSource};
        let Some(cdb) = find_cdb() else {
            println!("degrade: cdb.exe not found (no SDK Debugging Tools, no Store WinDbg, not on PATH)");
            return;
        };
        println!("cdb: {}", cdb.display());
        let newest = WindowsDumpSource
            .discover()
            .into_iter()
            .max_by_key(|meta| meta.modified_ms);
        let Some(newest) = newest else {
            println!("degrade: no crash dumps found in the standard locations");
            return;
        };
        println!(
            "dump: {} ({} bytes)",
            newest.path.display(),
            newest.size_bytes
        );
        let cancelled = Arc::new(AtomicBool::new(false));
        match analyze_dump(&newest.path, cancelled) {
            Ok(analysis) => {
                for row in analysis.summarize() {
                    println!("{} = {}", row.label, row.value);
                }
            }
            Err(error) => println!("degrade: {error:#}"),
        }
    }
}
