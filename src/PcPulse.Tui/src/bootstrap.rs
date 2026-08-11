//! Launch-time self-heal for the TUI's two companions: the collector
//! service and the tray helper.
//!
//! `ensure_companions` runs once in `run_tui`, before the terminal takes
//! over and before the worker thread spawns. It starts the
//! `PcPulseCollector` service when it is stopped (falling back to one
//! deliberate, visible UAC prompt on installs that never granted standard
//! users start rights) and respawns `PcPulse.Notify.exe` when no tray
//! helper is running. The tray helper deliberately outlives the TUI: it
//! exits only from its own right-click menu, so this module only ever
//! starts it, never stops it.
//!
//! Everything here is best-effort and bounded: SCM round-trips and a
//! Toolhelp snapshot are milliseconds, `StartServiceW` returns without
//! waiting (the existing pipe-retry loop meets the service as it comes
//! up), and every failure — no service installed, no SCM, no binary next
//! to the TUI — degrades silently to today's offline behavior. The SCM and
//! process layers sit behind traits exactly like the service's
//! `ForensicsSource` and this crate's `UpdateTransport`, so tests drive
//! the decision logic with stubs and never touch the real machine.

use pcpulse_service::SERVICE_NAME;
use std::{
    os::windows::process::CommandExt,
    path::PathBuf,
    process::{Command, Stdio},
};
use windows::{
    Win32::{
        Foundation::{
            CloseHandle, ERROR_ACCESS_DENIED, ERROR_SERVICE_ALREADY_RUNNING,
            ERROR_SERVICE_DOES_NOT_EXIST, HANDLE, WIN32_ERROR,
        },
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
                TH32CS_SNAPPROCESS,
            },
            Services::{
                CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatus, SC_HANDLE,
                SC_MANAGER_CONNECT, SERVICE_PAUSED, SERVICE_QUERY_STATUS, SERVICE_START,
                SERVICE_STATUS, SERVICE_STATUS_CURRENT_STATE, SERVICE_STOPPED, StartServiceW,
            },
        },
        UI::{Shell::ShellExecuteW, WindowsAndMessaging::SW_HIDE},
    },
    core::PCWSTR,
};

/// The tray helper's installed executable name; dev runs build
/// `pcpulse-notify.exe` instead, which this module treats as "no binary"
/// and leaves alone.
pub const TRAY_EXE_NAME: &str = "PcPulse.Notify.exe";

/// Windows' own creation flag: the spawned tray helper gets no console and
/// no job/console tie to the TUI, so closing the TUI never takes it down.
const DETACHED_PROCESS: u32 = 0x0000_0008;

/// What one SCM round-trip said about the collector service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceProbe {
    /// Not installed (dev runs from `target/`), or the SCM itself was
    /// unreachable — nothing to heal.
    Absent,
    /// Running or already start-pending; the pipe retry will meet it.
    Healthy,
    /// Stopped or paused, and this user's handle carries `SERVICE_START`.
    Stopped,
    /// Stopped or paused, but this user may only query it — an install
    /// predating the MSI's start-rights grant.
    StoppedDenied,
}

/// What `StartServiceW` answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartOutcome {
    Started,
    AlreadyRunning,
    AccessDenied,
    Failed,
}

/// The SCM seam — the real implementation talks to the service control
/// manager; tests substitute a scripted stub.
pub trait CollectorScm {
    fn probe(&self) -> ServiceProbe;
    fn start(&self) -> StartOutcome;
    /// One deliberate, visible UAC prompt (`sc.exe start PcPulseCollector`
    /// via the `runas` verb). True when the elevated process launched;
    /// false when the user declined or the launch failed. Never called
    /// unless a start was actually needed and denied.
    fn request_elevated_start(&self) -> bool;
}

/// What spawning the tray helper produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraySpawn {
    Spawned,
    /// No `PcPulse.Notify.exe` beside the TUI — a dev run; silent no-op.
    MissingBinary,
    Failed,
}

/// The tray-helper seam: process presence and detached spawn.
pub trait TrayHelper {
    fn is_running(&self) -> bool;
    fn spawn(&self) -> TraySpawn;
}

/// How the service half of the heal ended, when it did anything at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceHeal {
    Started,
    ElevationRequested,
}

/// What this launch healed; `message` renders the one-time status line.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct HealSummary {
    pub service: Option<ServiceHeal>,
    pub tray_started: bool,
}

impl HealSummary {
    /// The single status line the TUI surfaces once, or `None` when
    /// nothing needed healing — the common case stays silent.
    pub fn message(&self) -> Option<String> {
        let service = match self.service {
            Some(ServiceHeal::Started) => Some("Collector service started"),
            Some(ServiceHeal::ElevationRequested) => {
                Some("Collector service start requested — approve the elevation prompt")
            }
            None => None,
        };
        let tray = self.tray_started.then_some("Tray helper started");
        match (service, tray) {
            (Some(service), Some(tray)) => Some(format!("{service} · {tray}")),
            (Some(only), None) | (None, Some(only)) => Some(only.to_owned()),
            (None, None) => None,
        }
    }
}

/// The one launch-time call: heal both companions against the real
/// machine and hand back the status line to surface, if any.
pub fn ensure_companions() -> Option<String> {
    heal(&SystemScm, &SystemTray).message()
}

/// The decision logic, seam-injected so tests drive every branch.
pub fn heal(scm: &dyn CollectorScm, tray: &dyn TrayHelper) -> HealSummary {
    let service = match scm.probe() {
        ServiceProbe::Absent | ServiceProbe::Healthy => None,
        ServiceProbe::Stopped => match scm.start() {
            StartOutcome::Started => Some(ServiceHeal::Started),
            // Someone else won the race, or the SCM refused for a
            // non-rights reason — the offline panel owns whatever follows.
            StartOutcome::AlreadyRunning | StartOutcome::Failed => None,
            // Rights changed between the probe and the start; same
            // fallback as a probe-time denial.
            StartOutcome::AccessDenied => scm
                .request_elevated_start()
                .then_some(ServiceHeal::ElevationRequested),
        },
        ServiceProbe::StoppedDenied => scm
            .request_elevated_start()
            .then_some(ServiceHeal::ElevationRequested),
    };
    let tray_started = !tray.is_running() && tray.spawn() == TraySpawn::Spawned;
    HealSummary {
        service,
        tray_started,
    }
}

/// The real SCM: fresh, short-lived handles per call — no state to hold.
pub struct SystemScm;

impl CollectorScm for SystemScm {
    fn probe(&self) -> ServiceProbe {
        let Ok(manager) = open_manager() else {
            return ServiceProbe::Absent;
        };
        match open_service(&manager, SERVICE_QUERY_STATUS | SERVICE_START) {
            Ok(service) => match query_state(&service) {
                Some(state) if needs_start(state) => ServiceProbe::Stopped,
                Some(_) => ServiceProbe::Healthy,
                None => ServiceProbe::Absent,
            },
            Err(error) if win32(&error) == Some(ERROR_SERVICE_DOES_NOT_EXIST) => {
                ServiceProbe::Absent
            }
            // Old installs never granted standard users SERVICE_START;
            // fall back to a query-only handle to at least learn the state.
            Err(error) if win32(&error) == Some(ERROR_ACCESS_DENIED) => {
                match open_service(&manager, SERVICE_QUERY_STATUS) {
                    Ok(service) => match query_state(&service) {
                        Some(state) if needs_start(state) => ServiceProbe::StoppedDenied,
                        Some(_) => ServiceProbe::Healthy,
                        None => ServiceProbe::Absent,
                    },
                    Err(_) => ServiceProbe::Absent,
                }
            }
            Err(_) => ServiceProbe::Absent,
        }
    }

    fn start(&self) -> StartOutcome {
        let Ok(manager) = open_manager() else {
            return StartOutcome::Failed;
        };
        let service = match open_service(&manager, SERVICE_START) {
            Ok(service) => service,
            Err(error) if win32(&error) == Some(ERROR_ACCESS_DENIED) => {
                return StartOutcome::AccessDenied;
            }
            Err(_) => return StartOutcome::Failed,
        };
        // Returns as soon as the SCM accepts the request — the pipe-retry
        // loop in `client::connect` waits out the actual startup.
        match unsafe { StartServiceW(service.0, None) } {
            Ok(()) => StartOutcome::Started,
            Err(error) if win32(&error) == Some(ERROR_SERVICE_ALREADY_RUNNING) => {
                StartOutcome::AlreadyRunning
            }
            Err(error) if win32(&error) == Some(ERROR_ACCESS_DENIED) => StartOutcome::AccessDenied,
            Err(_) => StartOutcome::Failed,
        }
    }

    fn request_elevated_start(&self) -> bool {
        // `runas` on sc.exe directly: exactly one UAC prompt, visibly tied
        // to a deliberate action, and no console window afterwards. The
        // call returns once the prompt is answered; declining is fine —
        // the offline panel handles a service that never comes up.
        let operation = wide("runas");
        let file = wide(&system32_tool("sc.exe").to_string_lossy());
        let parameters = wide(&format!("start {SERVICE_NAME}"));
        let instance = unsafe {
            ShellExecuteW(
                None,
                PCWSTR(operation.as_ptr()),
                PCWSTR(file.as_ptr()),
                PCWSTR(parameters.as_ptr()),
                PCWSTR::null(),
                SW_HIDE,
            )
        };
        // ShellExecuteW's documented contract: values above 32 mean the
        // process launched.
        instance.0 as isize > 32
    }
}

/// A service in these states needs a start; pending states are already in
/// motion and stop-pending cannot legally be started, so both are left to
/// the pipe retry and the offline panel.
fn needs_start(state: SERVICE_STATUS_CURRENT_STATE) -> bool {
    state == SERVICE_STOPPED || state == SERVICE_PAUSED
}

fn open_manager() -> windows::core::Result<ScmGuard> {
    unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT) }.map(ScmGuard)
}

fn open_service(manager: &ScmGuard, access: u32) -> windows::core::Result<ScmGuard> {
    let name = wide(SERVICE_NAME);
    unsafe { OpenServiceW(manager.0, PCWSTR(name.as_ptr()), access) }.map(ScmGuard)
}

fn query_state(service: &ScmGuard) -> Option<SERVICE_STATUS_CURRENT_STATE> {
    let mut status = SERVICE_STATUS::default();
    unsafe { QueryServiceStatus(service.0, &raw mut status) }
        .ok()
        .map(|()| status.dwCurrentState)
}

/// The Win32 error inside a `windows` crate error, when there is one.
fn win32(error: &windows::core::Error) -> Option<WIN32_ERROR> {
    WIN32_ERROR::from_error(error)
}

struct ScmGuard(SC_HANDLE);

impl Drop for ScmGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseServiceHandle(self.0);
        }
    }
}

/// The real tray layer: a Toolhelp process-name check and a detached spawn
/// from the TUI's own directory.
pub struct SystemTray;

impl TrayHelper for SystemTray {
    fn is_running(&self) -> bool {
        process_running(TRAY_EXE_NAME)
    }

    fn spawn(&self) -> TraySpawn {
        let Some(directory) = std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().map(PathBuf::from))
        else {
            return TraySpawn::Failed;
        };
        let binary = directory.join(TRAY_EXE_NAME);
        if !binary.is_file() {
            return TraySpawn::MissingBinary;
        }
        // DETACHED_PROCESS and null stdio: the helper owns its own
        // lifetime from the first instruction — the TUI closing, or even
        // crashing, never reaps it.
        match Command::new(&binary)
            .current_dir(&directory)
            .creation_flags(DETACHED_PROCESS)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(_) => TraySpawn::Spawned,
            Err(_) => TraySpawn::Failed,
        }
    }
}

/// True when any process in this session's snapshot carries `exe_name`.
/// A same-name check suffices: the helper enforces its own single-instance
/// behavior, and a false positive merely skips a courtesy respawn.
fn process_running(exe_name: &str) -> bool {
    let Ok(snapshot) = (unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }) else {
        return false;
    };
    let _guard = SnapshotGuard(snapshot);
    let mut entry = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    if unsafe { Process32FirstW(snapshot, &raw mut entry) }.is_err() {
        return false;
    }
    loop {
        let length = entry
            .szExeFile
            .iter()
            .position(|&unit| unit == 0)
            .unwrap_or(entry.szExeFile.len());
        let name = String::from_utf16_lossy(&entry.szExeFile[..length]);
        if name.eq_ignore_ascii_case(exe_name) {
            return true;
        }
        if unsafe { Process32NextW(snapshot, &raw mut entry) }.is_err() {
            return false;
        }
    }
}

struct SnapshotGuard(HANDLE);

impl Drop for SnapshotGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

/// `%SystemRoot%\System32\<name>` — the same exact-path rule `update.rs`
/// applies to curl/certutil, so PATH aliases never intercept sc.exe.
fn system32_tool(name: &str) -> PathBuf {
    std::env::var_os("SystemRoot")
        .map_or_else(|| PathBuf::from(r"C:\Windows"), PathBuf::from)
        .join("System32")
        .join(name)
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    /// A scripted SCM that records exactly which calls the heal made.
    struct StubScm {
        probe: ServiceProbe,
        start_outcome: StartOutcome,
        elevation_accepted: bool,
        starts: Cell<u32>,
        elevations: Cell<u32>,
    }

    impl StubScm {
        fn new(probe: ServiceProbe, start_outcome: StartOutcome) -> Self {
            Self {
                probe,
                start_outcome,
                elevation_accepted: true,
                starts: Cell::new(0),
                elevations: Cell::new(0),
            }
        }
    }

    impl CollectorScm for StubScm {
        fn probe(&self) -> ServiceProbe {
            self.probe
        }

        fn start(&self) -> StartOutcome {
            self.starts.set(self.starts.get() + 1);
            self.start_outcome
        }

        fn request_elevated_start(&self) -> bool {
            self.elevations.set(self.elevations.get() + 1);
            self.elevation_accepted
        }
    }

    /// A scripted tray layer recording spawn attempts.
    struct StubTray {
        running: bool,
        spawn_outcome: TraySpawn,
        spawns: RefCell<Vec<()>>,
    }

    impl StubTray {
        fn new(running: bool, spawn_outcome: TraySpawn) -> Self {
            Self {
                running,
                spawn_outcome,
                spawns: RefCell::new(Vec::new()),
            }
        }
    }

    impl TrayHelper for StubTray {
        fn is_running(&self) -> bool {
            self.running
        }

        fn spawn(&self) -> TraySpawn {
            self.spawns.borrow_mut().push(());
            self.spawn_outcome
        }
    }

    fn idle_tray() -> StubTray {
        StubTray::new(true, TraySpawn::Spawned)
    }

    #[test]
    fn a_running_service_is_left_alone() {
        let scm = StubScm::new(ServiceProbe::Healthy, StartOutcome::Started);
        let summary = heal(&scm, &idle_tray());
        assert_eq!(summary.service, None);
        assert_eq!(scm.starts.get(), 0, "no start call on a healthy service");
        assert_eq!(scm.elevations.get(), 0);
        assert_eq!(summary.message(), None, "the common case stays silent");
    }

    #[test]
    fn an_absent_service_is_a_silent_noop() {
        let scm = StubScm::new(ServiceProbe::Absent, StartOutcome::Started);
        let summary = heal(&scm, &idle_tray());
        assert_eq!(summary, HealSummary::default());
        assert_eq!(scm.starts.get(), 0);
        assert_eq!(scm.elevations.get(), 0);
    }

    #[test]
    fn a_stopped_service_gets_started() {
        let scm = StubScm::new(ServiceProbe::Stopped, StartOutcome::Started);
        let summary = heal(&scm, &idle_tray());
        assert_eq!(summary.service, Some(ServiceHeal::Started));
        assert_eq!(scm.starts.get(), 1);
        assert_eq!(scm.elevations.get(), 0, "no UAC when the grant works");
        assert_eq!(summary.message().as_deref(), Some("Collector service started"));
    }

    #[test]
    fn a_denied_start_falls_back_to_one_elevation_request() {
        let scm = StubScm::new(ServiceProbe::Stopped, StartOutcome::AccessDenied);
        let summary = heal(&scm, &idle_tray());
        assert_eq!(summary.service, Some(ServiceHeal::ElevationRequested));
        assert_eq!(scm.starts.get(), 1);
        assert_eq!(scm.elevations.get(), 1);
    }

    #[test]
    fn a_query_only_handle_skips_start_and_asks_for_elevation() {
        let scm = StubScm::new(ServiceProbe::StoppedDenied, StartOutcome::Failed);
        let summary = heal(&scm, &idle_tray());
        assert_eq!(summary.service, Some(ServiceHeal::ElevationRequested));
        assert_eq!(scm.starts.get(), 0, "an unstartable handle is never used");
        assert_eq!(scm.elevations.get(), 1);
        assert_eq!(
            summary.message().as_deref(),
            Some("Collector service start requested — approve the elevation prompt")
        );
    }

    #[test]
    fn a_declined_elevation_prompt_degrades_silently() {
        let mut scm = StubScm::new(ServiceProbe::StoppedDenied, StartOutcome::Failed);
        scm.elevation_accepted = false;
        let summary = heal(&scm, &idle_tray());
        assert_eq!(summary.service, None, "a declined prompt is not a heal");
        assert_eq!(summary.message(), None);
    }

    #[test]
    fn losing_the_start_race_or_failing_stays_silent() {
        for outcome in [StartOutcome::AlreadyRunning, StartOutcome::Failed] {
            let scm = StubScm::new(ServiceProbe::Stopped, outcome);
            let summary = heal(&scm, &idle_tray());
            assert_eq!(summary.service, None);
            assert_eq!(scm.elevations.get(), 0, "{outcome:?} never elevates");
        }
    }

    #[test]
    fn a_running_tray_helper_is_never_respawned() {
        let tray = StubTray::new(true, TraySpawn::Spawned);
        let summary = heal(&StubScm::new(ServiceProbe::Healthy, StartOutcome::Started), &tray);
        assert!(!summary.tray_started);
        assert!(tray.spawns.borrow().is_empty(), "no spawn while running");
    }

    #[test]
    fn an_absent_tray_helper_is_spawned() {
        let tray = StubTray::new(false, TraySpawn::Spawned);
        let summary = heal(&StubScm::new(ServiceProbe::Healthy, StartOutcome::Started), &tray);
        assert!(summary.tray_started);
        assert_eq!(tray.spawns.borrow().len(), 1);
        assert_eq!(summary.message().as_deref(), Some("Tray helper started"));
    }

    #[test]
    fn a_missing_tray_binary_is_a_silent_noop() {
        for outcome in [TraySpawn::MissingBinary, TraySpawn::Failed] {
            let tray = StubTray::new(false, outcome);
            let summary =
                heal(&StubScm::new(ServiceProbe::Healthy, StartOutcome::Started), &tray);
            assert!(!summary.tray_started, "{outcome:?} is not a heal");
            assert_eq!(summary.message(), None);
        }
    }

    #[test]
    fn healing_both_companions_reads_as_one_line() {
        let scm = StubScm::new(ServiceProbe::Stopped, StartOutcome::Started);
        let tray = StubTray::new(false, TraySpawn::Spawned);
        assert_eq!(
            heal(&scm, &tray).message().as_deref(),
            Some("Collector service started · Tray helper started")
        );
    }

    #[test]
    fn the_real_tray_spawn_reports_missing_binary_from_a_dev_directory() {
        // Dev builds sit next to `pcpulse-notify.exe`, not the installed
        // `PcPulse.Notify.exe`, so the real spawn path must be a no-op
        // unless someone staged the installed name beside the test binary.
        let staged = std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().map(|dir| dir.join(TRAY_EXE_NAME)))
            .is_some_and(|path| path.is_file());
        if !staged {
            assert_eq!(SystemTray.spawn(), TraySpawn::MissingBinary);
        }
    }

    #[test]
    #[ignore = "dev harness: reports the real PcPulseCollector state and whether this token may start it (never starts anything)"]
    fn dev_probe_service_state() {
        let manager = match open_manager() {
            Ok(manager) => manager,
            Err(error) => {
                println!("SCM unreachable: {error}");
                return;
            }
        };
        match open_service(&manager, SERVICE_QUERY_STATUS) {
            Ok(service) => match query_state(&service) {
                Some(state) => println!(
                    "service state: {} (needs_start: {})",
                    describe_state(state),
                    needs_start(state)
                ),
                None => println!("service state: query failed"),
            },
            Err(error) => {
                println!("query-open failed: {error}");
                return;
            }
        }
        match open_service(&manager, SERVICE_QUERY_STATUS | SERVICE_START) {
            Ok(_) => println!("start right: GRANTED unelevated (no start attempted)"),
            Err(error) if win32(&error) == Some(ERROR_ACCESS_DENIED) => {
                println!("start right: DENIED unelevated — the heal would raise one UAC prompt");
            }
            Err(error) => println!("start right: open failed: {error}"),
        }
        println!("probe: {:?}", SystemScm.probe());
        println!("tray helper running: {}", SystemTray.is_running());
    }

    fn describe_state(state: SERVICE_STATUS_CURRENT_STATE) -> String {
        use windows::Win32::System::Services::{
            SERVICE_CONTINUE_PENDING, SERVICE_PAUSE_PENDING, SERVICE_RUNNING,
            SERVICE_START_PENDING, SERVICE_STOP_PENDING,
        };
        match state {
            SERVICE_STOPPED => "stopped".into(),
            SERVICE_START_PENDING => "start-pending".into(),
            SERVICE_STOP_PENDING => "stop-pending".into(),
            SERVICE_RUNNING => "running".into(),
            SERVICE_CONTINUE_PENDING => "continue-pending".into(),
            SERVICE_PAUSE_PENDING => "pause-pending".into(),
            SERVICE_PAUSED => "paused".into(),
            other => format!("unknown ({})", other.0),
        }
    }
}
