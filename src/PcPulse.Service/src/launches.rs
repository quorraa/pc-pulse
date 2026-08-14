//! Pure helpers for launch-history tracking: kernel image-path normalization
//! and console-host classification, plus the stateful `LaunchTracker` that
//! turns ETW start/stop events into `LaunchEvent` rows -- capture-time
//! lineage resolution, stop matching (PID-reuse safe), window-visibility
//! state, and the 60s "still running" flush.

use std::collections::{HashMap, VecDeque};

use windows::Win32::Storage::FileSystem::QueryDosDeviceW;
use windows::core::PCWSTR;

use crate::etw_props::{ProcessStartProps, ProcessStopProps};
use crate::models::{LaunchCaptureStatus, LaunchEvent, LineageEntry, WindowState};

/// Cap on the recent-launch ring used to resolve lineage for ancestors the
/// live process table no longer has (already exited) but that this tracker
/// itself observed starting recently.
const RECENT_CAP: usize = 4096;
/// Max ancestors walked when resolving a launch's lineage.
const LINEAGE_MAX_DEPTH: usize = 5;
/// A still-pending (no stop event yet) launch this old is flushed as a
/// `Running` snapshot rather than held back indefinitely.
const RUNNING_FLUSH_THRESHOLD_MS: i64 = 60_000;
/// A still-pending (no stop event ever arrived) launch this old is evicted
/// from `pending` outright rather than held forever: its previously-emitted
/// `Running` snapshot (if any) remains the honest last-known state in
/// storage, and a stop event that arrives afterward is counted as an
/// orphan rather than resurrecting the row.
const STALE_PENDING_THRESHOLD_MS: i64 = 24 * 60 * 60 * 1000;
/// Minimum spacing between device-map rebuilds triggered by a mapping
/// failure, so a storm of unmappable paths (e.g. `\Device\Mup\...` network
/// shares) can't hammer `QueryDosDeviceW` once per start event.
const DEVICE_MAP_REBUILD_COOLDOWN_MS: i64 = 60_000;

/// A device-map builder function: `build_device_map` in production, a
/// counting stand-in in tests that exercise the rebuild-cooldown path.
type DeviceMapBuilder = fn() -> Vec<(String, String)>;

/// Console host executable names (lowercase, exact match only -- no
/// substring matching, so e.g. "mycmd.exe" does not match "cmd.exe").
const CONSOLE_HOSTS: &[&str] = &[
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "conhost.exe",
    "wt.exe",
    "windowsterminal.exe",
    "openconsole.exe",
];

/// Maps `\Device\HarddiskVolumeN\...` to `c:\...` using a supplied device
/// map, and lowercases the result either way. `device_map` entries are
/// `(device_path, drive)` pairs, both already lowercase (see
/// `build_device_map`). Matching uses the longest device-path prefix so that
/// a device map is never ambiguous even if entries share a common prefix.
///
/// Returns `(normalized_or_original_lowercased, mapped)`, where `mapped` is
/// `true` only if a device prefix was substituted.
pub fn normalize_image_path(raw: &str, device_map: &[(String, String)]) -> (String, bool) {
    let lower = raw.to_lowercase();

    let best = device_map
        .iter()
        .filter(|(device, _)| device_prefix_matches(&lower, device))
        .max_by_key(|(device, _)| device.len());

    match best {
        Some((device, drive)) => {
            let rest = &lower[device.len()..];
            (format!("{drive}{rest}"), true)
        }
        None => (lower, false),
    }
}

/// Whether `lower` (already lowercased) begins with `device` at a
/// path-component boundary: the prefix must be followed by a path separator
/// (`\` or `/`) or nothing at all. A plain `starts_with` would let
/// `\device\harddiskvolume1` wrongly match `\device\harddiskvolume10\...`
/// since one device path can be a numeric prefix of another.
fn device_prefix_matches(lower: &str, device: &str) -> bool {
    lower
        .strip_prefix(device)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with(['\\', '/']))
}

/// Builds a live `\Device\HarddiskVolumeN` -> drive-letter map by calling
/// `QueryDosDeviceW` for each drive letter A:..Z:. Only existing mappings
/// are returned. Callers should cache the result rather than rebuilding it
/// per lookup -- drive mappings rarely change during a service's lifetime.
pub fn build_device_map() -> Vec<(String, String)> {
    let mut map = Vec::new();

    for letter in b'A'..=b'Z' {
        let drive = format!("{}:", letter as char);
        let wide_drive: Vec<u16> = drive.encode_utf16().chain(std::iter::once(0)).collect();

        let mut buf = [0u16; 260];
        // SAFETY: `wide_drive` is a valid NUL-terminated wide string and
        // `buf` is a valid, appropriately-sized output buffer for the
        // duration of the call.
        let len = unsafe { QueryDosDeviceW(PCWSTR(wide_drive.as_ptr()), Some(&mut buf)) };
        if len == 0 {
            continue;
        }

        let device = String::from_utf16_lossy(&buf[..(len as usize).saturating_sub(1)]);
        if device.is_empty() {
            continue;
        }

        map.push((device.to_lowercase(), drive.to_lowercase()));
    }

    map
}

/// Returns the last path component (the executable file name), unchanged
/// otherwise -- callers are expected to lowercase separately if needed.
pub fn exe_name_from_path(path: &str) -> String {
    path.rsplit(['\\', '/']).next().unwrap_or(path).to_string()
}

/// Whether `exe_name` names a known console host, matched case-insensitively
/// and by exact full name (no substring matching).
pub fn is_console_host(exe_name: &str) -> bool {
    let lower = exe_name.to_lowercase();
    CONSOLE_HOSTS.contains(&lower.as_str())
}

/// Minimal live-process info a caller's process-table lookup returns for a
/// pid. Carries the pid's own `parent_pid` (unlike a bare name/path pair) so
/// `LaunchTracker::build_lineage` can keep walking up the chain through
/// consecutive live-table hits instead of stopping after just one.
#[derive(Debug, Clone)]
pub struct LiveProcessInfo {
    pub name: String,
    pub path: Option<String>,
    pub parent_pid: u32,
}

/// One ancestor launch remembered purely so a later descendant's lineage
/// walk can resolve it even after it has exited. Distinct from
/// `LineageEntry` (the public, serialized shape) because it also carries
/// `parent_pid`, needed to keep walking further up the chain, and
/// `start_ms`, needed to pick the reuse-correct entry when a pid recurs.
struct RecentLaunch {
    pid: u32,
    parent_pid: u32,
    start_ms: i64,
    name: String,
    path: String,
}

/// A launch that has started but not yet been drained-and-removed: either
/// still running (no stop event) or stopped but not yet drained.
struct PendingLaunch {
    start_time_ms: i64,
    stop_time_ms: Option<i64>,
    exit_code: Option<u32>,
    exe_name: String,
    exe_path: String,
    raw_image_path: Option<String>,
    session_id: u32,
    parent_pid: u32,
    lineage: Vec<LineageEntry>,
    console_host: bool,
    /// Set true the first time `observe_window` samples this pid, whatever
    /// the visibility result -- distinguishes "never sampled" from "sampled,
    /// never visible".
    sampled: bool,
    /// Sticky once-true: whether the process was ever observed with a
    /// visible top-level window.
    visible: bool,
    /// Final window state, resolved once the matching stop event lands.
    /// Meaningless (left at its default) while `stop_time_ms` is `None`;
    /// `drain_flushable` uses `WindowState::Running` for still-pending rows
    /// instead of reading this field.
    window_state: WindowState,
    /// Whether a `Running` snapshot has already been emitted for this row.
    /// A still-pending row is only ever emitted once as `Running`; it is
    /// only re-emitted once a stop event finalizes it (the upsert then
    /// replaces the earlier `Running` row).
    emitted_running: bool,
}

impl PendingLaunch {
    fn to_event(&self, pid: u32) -> LaunchEvent {
        LaunchEvent {
            pid,
            start_time_ms: self.start_time_ms,
            stop_time_ms: self.stop_time_ms,
            exit_code: self.exit_code,
            exe_name: self.exe_name.clone(),
            exe_path: self.exe_path.clone(),
            raw_image_path: self.raw_image_path.clone(),
            session_id: self.session_id,
            parent_pid: self.parent_pid,
            lineage: self.lineage.clone(),
            window_state: self.window_state,
            console_host: self.console_host,
            command_line: None,
        }
    }

    /// A still-open snapshot: always `Running`, never a fabricated stop.
    fn to_running_event(&self, pid: u32) -> LaunchEvent {
        LaunchEvent {
            pid,
            start_time_ms: self.start_time_ms,
            stop_time_ms: None,
            exit_code: None,
            exe_name: self.exe_name.clone(),
            exe_path: self.exe_path.clone(),
            raw_image_path: self.raw_image_path.clone(),
            session_id: self.session_id,
            parent_pid: self.parent_pid,
            lineage: self.lineage.clone(),
            window_state: WindowState::Running,
            console_host: self.console_host,
            command_line: None,
        }
    }
}

/// Stateful capture-time builder of `LaunchEvent` rows from ETW start/stop
/// events. Never fabricates a row: stops with no matching start are counted
/// (`orphan_stops`) and dropped, not synthesized.
pub struct LaunchTracker {
    /// Keyed by `(pid, start_time_ms)` so PID reuse produces distinct rows.
    pending: HashMap<(u32, i64), PendingLaunch>,
    /// pid -> the start_time_ms of that pid's *latest* observed launch, used
    /// to route stop events and window-visibility samples to the right
    /// pending row. On PID reuse this is overwritten by the newer launch;
    /// the older `pending` row is not touched by it and is only ever closed
    /// by its own stop event (or flushed `Running` once stale).
    pid_index: HashMap<u32, i64>,
    /// Bounded ring of recently-started launches, used to resolve lineage
    /// for ancestors that have already exited (so are no longer in the live
    /// process table) but that this tracker itself observed starting.
    recent: VecDeque<RecentLaunch>,
    device_map: Vec<(String, String)>,
    /// How `on_start` rebuilds `device_map` on a mapping failure: `None`
    /// disables rebuilding entirely (the `#[cfg(test)]` default, so unit
    /// tests never touch Win32); `Some(f)` calls `f()` to rebuild, subject
    /// to `last_rebuild_ms`'s cooldown.
    device_map_builder: Option<DeviceMapBuilder>,
    /// Event-clock (`create_time_ms`) timestamp of the last device-map
    /// rebuild, so a storm of unmappable paths can't rebuild more than once
    /// per `DEVICE_MAP_REBUILD_COOLDOWN_MS`. Deliberately driven by the
    /// event's own timestamp rather than a wall clock, so this stays
    /// deterministic and testable.
    last_rebuild_ms: Option<i64>,
    starts_seen: u64,
    stops_seen: u64,
    persisted: u64,
    orphan_stops: u64,
    stale_pending_evicted: u64,
}

impl LaunchTracker {
    pub fn new() -> Self {
        Self {
            pending: HashMap::new(),
            pid_index: HashMap::new(),
            recent: VecDeque::new(),
            device_map: build_device_map(),
            device_map_builder: Some(build_device_map),
            last_rebuild_ms: None,
            starts_seen: 0,
            stops_seen: 0,
            persisted: 0,
            orphan_stops: 0,
            stale_pending_evicted: 0,
        }
    }

    /// Test-only constructor: takes a fixed device map and never rebuilds
    /// it, so tests never call into Win32 (`QueryDosDeviceW`).
    #[cfg(test)]
    fn new_for_test(device_map: Vec<(String, String)>) -> Self {
        Self {
            pending: HashMap::new(),
            pid_index: HashMap::new(),
            recent: VecDeque::new(),
            device_map,
            device_map_builder: None,
            last_rebuild_ms: None,
            starts_seen: 0,
            stops_seen: 0,
            persisted: 0,
            orphan_stops: 0,
            stale_pending_evicted: 0,
        }
    }

    /// Test-only constructor for exercising the rebuild-cooldown path
    /// without touching Win32: `builder` stands in for `build_device_map`.
    #[cfg(test)]
    fn new_for_test_with_rebuild(
        device_map: Vec<(String, String)>,
        builder: DeviceMapBuilder,
    ) -> Self {
        let mut tracker = Self::new_for_test(device_map);
        tracker.device_map_builder = Some(builder);
        tracker
    }

    /// live_lookup: pid -> the live process table's info for that pid, if any.
    pub fn on_start(
        &mut self,
        p: ProcessStartProps,
        live_lookup: &dyn Fn(u32) -> Option<LiveProcessInfo>,
    ) {
        self.starts_seen += 1;

        let key = (p.pid, p.create_time_ms);
        if self.pending.contains_key(&key) {
            // Duplicate start for an already-tracked (pid, start) row (e.g. a
            // retransmitted ETW event): ignore rather than reset accumulated
            // window-sample state or resurrect an already-finalized row.
            return;
        }

        let (mut exe_path, mut mapped) = normalize_image_path(&p.image_name, &self.device_map);
        if !mapped {
            let should_rebuild = self.device_map_builder.is_some()
                && match self.last_rebuild_ms {
                    None => true,
                    Some(last) => p.create_time_ms - last >= DEVICE_MAP_REBUILD_COOLDOWN_MS,
                };
            if should_rebuild {
                // `device_map_builder` is `Some` per `should_rebuild` above.
                if let Some(builder) = self.device_map_builder {
                    self.device_map = builder();
                    self.last_rebuild_ms = Some(p.create_time_ms);
                    (exe_path, mapped) = normalize_image_path(&p.image_name, &self.device_map);
                }
            }
        }
        let raw_image_path = if mapped {
            None
        } else {
            Some(p.image_name.clone())
        };
        let exe_name = exe_name_from_path(&exe_path);
        let console_host = is_console_host(&exe_name);
        let lineage = self.build_lineage(p.parent_pid, p.create_time_ms, live_lookup);

        self.recent.push_back(RecentLaunch {
            pid: p.pid,
            parent_pid: p.parent_pid,
            start_ms: p.create_time_ms,
            name: exe_name.clone(),
            path: exe_path.clone(),
        });
        if self.recent.len() > RECENT_CAP {
            self.recent.pop_front();
        }

        self.pending.insert(
            key,
            PendingLaunch {
                start_time_ms: p.create_time_ms,
                stop_time_ms: None,
                exit_code: None,
                exe_name,
                exe_path,
                raw_image_path,
                session_id: p.session_id,
                parent_pid: p.parent_pid,
                lineage,
                console_host,
                sampled: false,
                visible: false,
                window_state: WindowState::Unobserved,
                emitted_running: false,
            },
        );
        // PID reuse: overwrites unconditionally. The prior pending row (if
        // any) keeps its own `(pid, old_start)` key untouched -- it simply
        // stops receiving stop/window-sample routing.
        self.pid_index.insert(p.pid, p.create_time_ms);
    }

    /// Walks the parent chain from `start_pid` up to `LINEAGE_MAX_DEPTH`
    /// ancestors, preferring `live_lookup`, then this tracker's own
    /// recently-observed launches, and finally giving up with `"unknown"`
    /// (which also stops the walk -- an unresolvable ancestor's own parent
    /// is not guessable). A `live_lookup` hit carries its own `parent_pid`,
    /// so the walk keeps going through consecutive live hits instead of
    /// stopping after the first one.
    fn build_lineage(
        &self,
        start_pid: u32,
        at_start_ms: i64,
        live_lookup: &dyn Fn(u32) -> Option<LiveProcessInfo>,
    ) -> Vec<LineageEntry> {
        let mut lineage = Vec::new();
        let mut current_pid = start_pid;
        for _ in 0..LINEAGE_MAX_DEPTH {
            if let Some(info) = live_lookup(current_pid) {
                lineage.push(LineageEntry {
                    pid: current_pid,
                    name: info.name,
                    path: info.path,
                });
                current_pid = info.parent_pid;
                continue;
            }
            if let Some(entry) = self.recent_lookup(current_pid, at_start_ms) {
                lineage.push(LineageEntry {
                    pid: current_pid,
                    name: entry.name.clone(),
                    path: Some(entry.path.clone()),
                });
                current_pid = entry.parent_pid;
                continue;
            }
            lineage.push(LineageEntry {
                pid: current_pid,
                name: "unknown".to_string(),
                path: None,
            });
            break;
        }
        lineage
    }

    /// Finds the recent-ring entry for `pid` that is reuse-proof at capture
    /// time: the entry with the largest `start_ms` that is still `<=
    /// at_ms` (i.e. the launch of `pid` that was actually alive when the
    /// event being resolved happened), falling back to the newest entry for
    /// that pid if none started early enough (a clock-skew/ordering
    /// edge case, not the common path).
    fn recent_lookup(&self, pid: u32, at_ms: i64) -> Option<&RecentLaunch> {
        self.recent
            .iter()
            .filter(|e| e.pid == pid && e.start_ms <= at_ms)
            .max_by_key(|e| e.start_ms)
            .or_else(|| {
                self.recent
                    .iter()
                    .filter(|e| e.pid == pid)
                    .max_by_key(|e| e.start_ms)
            })
    }

    pub fn on_stop(&mut self, p: ProcessStopProps, now_ms: i64) {
        self.stops_seen += 1;

        let matched = self.pid_index.get(&p.pid).copied().and_then(|start_ms| {
            self.pending
                .get_mut(&(p.pid, start_ms))
                .map(|launch| (start_ms, launch))
        });

        let Some((start_ms, launch)) = matched else {
            self.orphan_stops += 1;
            return;
        };

        launch.stop_time_ms = Some(now_ms);
        launch.exit_code = Some(p.exit_code);
        launch.window_state = if launch.visible {
            WindowState::Windowed
        } else if launch.sampled {
            WindowState::NeverWindowed
        } else {
            WindowState::Unobserved
        };

        // Only this exact (pid, start) launch is closing; if a newer launch
        // for the same reused pid has already overwritten pid_index, leave
        // it alone.
        if self.pid_index.get(&p.pid) == Some(&start_ms) {
            self.pid_index.remove(&p.pid);
        }
    }

    /// Called from the 2s visibility sweep for every sampled pid.
    pub fn observe_window(&mut self, pid: u32, visible: bool) {
        if let Some(&start_ms) = self.pid_index.get(&pid)
            && let Some(launch) = self.pending.get_mut(&(pid, start_ms))
        {
            launch.sampled = true;
            launch.visible |= visible;
        }
    }

    /// Completed launches (drained and removed) + still-open ones >= 60s old
    /// (emitted exactly once as `Running`, and kept pending -- finalized
    /// later by upsert when the stop event lands). Pending rows with no
    /// stop event 24h past their start are evicted outright rather than
    /// held or re-emitted; see `STALE_PENDING_THRESHOLD_MS`.
    pub fn drain_flushable(&mut self, now_ms: i64) -> Vec<LaunchEvent> {
        let mut out = Vec::new();
        let mut finished_keys = Vec::new();
        let mut stale_keys = Vec::new();

        for (&(pid, start_ms), launch) in self.pending.iter_mut() {
            if launch.stop_time_ms.is_some() {
                out.push(launch.to_event(pid));
                finished_keys.push((pid, start_ms));
            } else if now_ms - launch.start_time_ms >= STALE_PENDING_THRESHOLD_MS {
                stale_keys.push((pid, start_ms));
            } else if !launch.emitted_running
                && now_ms - launch.start_time_ms >= RUNNING_FLUSH_THRESHOLD_MS
            {
                out.push(launch.to_running_event(pid));
                launch.emitted_running = true;
            }
        }

        for key in finished_keys {
            self.pending.remove(&key);
            self.persisted += 1;
        }
        for (pid, start_ms) in stale_keys {
            self.pending.remove(&(pid, start_ms));
            // Only clear pid_index if it still points at this exact stale
            // row; a newer (reused-pid) launch must not be clobbered.
            if self.pid_index.get(&pid) == Some(&start_ms) {
                self.pid_index.remove(&pid);
            }
            self.stale_pending_evicted += 1;
        }

        out
    }

    /// etw fields (dropped_channel, etw_events_lost, malformed_events,
    /// events_lost_query_failures) are merged in by the runtime from
    /// `EtwHealth`; left at 0 here.
    pub fn status(&self) -> LaunchCaptureStatus {
        LaunchCaptureStatus {
            starts_seen: self.starts_seen,
            stops_seen: self.stops_seen,
            persisted: self.persisted,
            orphan_stops: self.orphan_stops,
            stale_pending_evicted: self.stale_pending_evicted,
            ..LaunchCaptureStatus::default()
        }
    }
}

impl Default for LaunchTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_device_path_and_flags_mapping() {
        let map = vec![(r"\device\harddiskvolume4".to_string(), "c:".to_string())];
        let (p, mapped) =
            normalize_image_path(r"\Device\HarddiskVolume4\Windows\System32\CMD.EXE", &map);
        assert_eq!(p, r"c:\windows\system32\cmd.exe");
        assert!(mapped);
    }

    #[test]
    fn numeric_prefix_volume_is_not_falsely_matched() {
        let map = vec![(r"\device\harddiskvolume1".to_string(), "c:".to_string())];
        let (p, mapped) = normalize_image_path(r"\Device\HarddiskVolume10\x.exe", &map);
        assert_eq!(p, r"\device\harddiskvolume10\x.exe");
        assert!(!mapped);
    }

    #[test]
    fn exact_equality_prefix_still_maps() {
        let map = vec![(r"\device\harddiskvolume1".to_string(), "c:".to_string())];
        let (p, mapped) = normalize_image_path(r"\Device\HarddiskVolume1", &map);
        assert_eq!(p, "c:");
        assert!(mapped);
    }

    #[test]
    fn volume_and_its_numeric_extension_each_map_to_own_drive() {
        let map = vec![
            (r"\device\harddiskvolume1".to_string(), "c:".to_string()),
            (r"\device\harddiskvolume10".to_string(), "d:".to_string()),
        ];
        let (p1, mapped1) = normalize_image_path(r"\Device\HarddiskVolume1\a.exe", &map);
        assert_eq!(p1, r"c:\a.exe");
        assert!(mapped1);

        let (p10, mapped10) = normalize_image_path(r"\Device\HarddiskVolume10\b.exe", &map);
        assert_eq!(p10, r"d:\b.exe");
        assert!(mapped10);
    }

    #[test]
    fn unmapped_device_path_preserved_lowercased_and_flagged() {
        let (p, mapped) = normalize_image_path(r"\Device\Mup\share\x.exe", &[]);
        assert_eq!(p, r"\device\mup\share\x.exe");
        assert!(!mapped);
    }

    #[test]
    fn console_hosts_recognized_case_insensitively() {
        for n in [
            "cmd.exe",
            "PowerShell.exe",
            "pwsh.exe",
            "conhost.exe",
            "wt.exe",
            "WindowsTerminal.exe",
            "OpenConsole.exe",
        ] {
            assert!(is_console_host(n), "{n}");
        }
        assert!(!is_console_host("notepad.exe"));
        assert!(!is_console_host("mycmd.exe")); // exact-name match only, no substring matching
    }

    #[test]
    fn exe_name_is_last_component() {
        assert_eq!(
            exe_name_from_path(r"c:\windows\system32\cmd.exe"),
            "cmd.exe"
        );
        assert_eq!(exe_name_from_path("cmd.exe"), "cmd.exe");
    }

    fn start(pid: u32, ppid: u32, t: i64, img: &str) -> ProcessStartProps {
        ProcessStartProps {
            pid,
            parent_pid: ppid,
            session_id: 1,
            create_time_ms: t,
            image_name: img.to_string(),
        }
    }
    fn no_live(_: u32) -> Option<LiveProcessInfo> {
        None
    }

    #[test]
    fn sub_two_second_lifecycle_recorded_as_unobserved() {
        let mut tr = LaunchTracker::new_for_test(Vec::new());
        tr.on_start(
            start(500, 4, 1_000, r"\Device\HarddiskVolume4\x\popup.exe"),
            &no_live,
        );
        tr.on_stop(
            ProcessStopProps {
                pid: 500,
                exit_code: 1,
            },
            1_300,
        );
        let ev = &tr.drain_flushable(2_000)[0];
        assert_eq!(ev.stop_time_ms, Some(1_300));
        assert_eq!(ev.exit_code, Some(1));
        assert_eq!(ev.window_state, WindowState::Unobserved);
    }
    #[test]
    fn pid_reuse_produces_distinct_rows_with_correct_stop_matching() {
        let mut tr = LaunchTracker::new_for_test(Vec::new());
        tr.on_start(start(500, 4, 1_000, r"c:\a.exe"), &no_live);
        tr.on_stop(
            ProcessStopProps {
                pid: 500,
                exit_code: 0,
            },
            2_000,
        );
        tr.on_start(start(500, 4, 3_000, r"c:\b.exe"), &no_live);
        tr.on_stop(
            ProcessStopProps {
                pid: 500,
                exit_code: 7,
            },
            4_000,
        );
        let evs = tr.drain_flushable(5_000);
        assert_eq!(evs.len(), 2);
        assert!(
            evs.iter()
                .any(|e| e.start_time_ms == 1_000 && e.exit_code == Some(0))
        );
        assert!(
            evs.iter()
                .any(|e| e.start_time_ms == 3_000 && e.exit_code == Some(7))
        );
    }
    #[test]
    fn lineage_prefers_live_then_recent_then_unknown() {
        let mut tr = LaunchTracker::new_for_test(Vec::new());
        tr.on_start(start(100, 1, 500, r"c:\parent.exe"), &no_live); // parent known via recent ring
        tr.on_start(start(200, 100, 1_000, r"c:\child.exe"), &no_live);
        let evs = tr.drain_flushable(120_000);
        let child = evs.iter().find(|e| e.pid == 200).unwrap();
        assert_eq!(child.lineage[0].name, "parent.exe");
        // grandparent pid 1 unresolvable anywhere:
        assert_eq!(child.lineage[1].name, "unknown");
        assert_eq!(child.lineage.len(), 2); // walk stops at unknown
    }
    #[test]
    fn orphan_stop_counts_and_creates_no_row() {
        let mut tr = LaunchTracker::new_for_test(Vec::new());
        tr.on_stop(
            ProcessStopProps {
                pid: 999,
                exit_code: 0,
            },
            1_000,
        );
        assert!(tr.drain_flushable(2_000).is_empty());
        assert_eq!(tr.status().orphan_stops, 1);
    }
    #[test]
    fn window_states_windowed_and_never_windowed() {
        let mut tr = LaunchTracker::new_for_test(Vec::new());
        tr.on_start(start(1, 4, 0, r"c:\w.exe"), &no_live);
        tr.on_start(start(2, 4, 0, r"c:\bg.exe"), &no_live);
        tr.observe_window(1, true);
        tr.observe_window(2, false);
        tr.on_stop(
            ProcessStopProps {
                pid: 1,
                exit_code: 0,
            },
            5_000,
        );
        tr.on_stop(
            ProcessStopProps {
                pid: 2,
                exit_code: 0,
            },
            5_000,
        );
        let evs = tr.drain_flushable(6_000);
        assert_eq!(
            evs.iter().find(|e| e.pid == 1).unwrap().window_state,
            WindowState::Windowed
        );
        assert_eq!(
            evs.iter().find(|e| e.pid == 2).unwrap().window_state,
            WindowState::NeverWindowed
        );
    }
    #[test]
    fn long_running_launch_flushes_as_running_and_stays_pending() {
        let mut tr = LaunchTracker::new_for_test(Vec::new());
        tr.on_start(start(1, 4, 0, r"c:\long.exe"), &no_live);
        let first = tr.drain_flushable(61_000);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].window_state, WindowState::Running);
        tr.on_stop(
            ProcessStopProps {
                pid: 1,
                exit_code: 0,
            },
            90_000,
        );
        let second = tr.drain_flushable(91_000);
        assert_eq!(second[0].stop_time_ms, Some(90_000)); // same (pid,start) key → upsert finalizes
    }
    #[test]
    fn rapid_repeated_launches_all_recorded() {
        let mut tr = LaunchTracker::new_for_test(Vec::new());
        for i in 0..50 {
            tr.on_start(start(1000 + i, 4, i as i64 * 10, r"c:\spam.exe"), &no_live);
            tr.on_stop(
                ProcessStopProps {
                    pid: 1000 + i,
                    exit_code: 0,
                },
                i as i64 * 10 + 5,
            );
        }
        assert_eq!(tr.drain_flushable(10_000).len(), 50);
        assert_eq!(tr.status().starts_seen, 50);
    }

    // -- Fix round 1 --------------------------------------------------

    #[test]
    fn lineage_walks_through_multiple_live_ancestors() {
        // live table: pid 100 -> parent 50, pid 50 -> parent 4; pid 4 itself
        // is unresolvable anywhere. Depth must reach >= 2 through
        // consecutive live hits, not collapse to 1 after the first.
        fn live(pid: u32) -> Option<LiveProcessInfo> {
            match pid {
                100 => Some(LiveProcessInfo {
                    name: "explorer.exe".to_string(),
                    path: Some(r"c:\windows\explorer.exe".to_string()),
                    parent_pid: 50,
                }),
                50 => Some(LiveProcessInfo {
                    name: "services.exe".to_string(),
                    path: Some(r"c:\windows\system32\services.exe".to_string()),
                    parent_pid: 4,
                }),
                _ => None,
            }
        }
        let mut tr = LaunchTracker::new_for_test(Vec::new());
        tr.on_start(start(200, 100, 1_000, r"c:\child.exe"), &live);
        let evs = tr.drain_flushable(65_000); // past the 60s Running-flush threshold
        let child = evs.iter().find(|e| e.pid == 200).unwrap();
        assert_eq!(child.lineage.len(), 3);
        assert_eq!(child.lineage[0].pid, 100);
        assert_eq!(child.lineage[0].name, "explorer.exe");
        assert_eq!(child.lineage[1].pid, 50);
        assert_eq!(child.lineage[1].name, "services.exe");
        assert_eq!(child.lineage[2].pid, 4);
        assert_eq!(child.lineage[2].name, "unknown");
    }

    #[test]
    fn running_snapshot_emitted_exactly_once_while_pending() {
        let mut tr = LaunchTracker::new_for_test(Vec::new());
        tr.on_start(start(1, 4, 0, r"c:\long.exe"), &no_live);
        let d1 = tr.drain_flushable(61_000);
        assert_eq!(d1.len(), 1);
        assert_eq!(d1[0].window_state, WindowState::Running);
        let d2 = tr.drain_flushable(62_000);
        assert!(d2.is_empty(), "must not re-emit Running on every drain");
        let d3 = tr.drain_flushable(600_000);
        assert!(d3.is_empty());
    }

    #[test]
    fn stop_after_running_emission_re_emits_as_finalized() {
        let mut tr = LaunchTracker::new_for_test(Vec::new());
        tr.on_start(start(1, 4, 0, r"c:\long.exe"), &no_live);
        let d1 = tr.drain_flushable(61_000);
        assert_eq!(d1[0].window_state, WindowState::Running);
        tr.on_stop(
            ProcessStopProps {
                pid: 1,
                exit_code: 0,
            },
            70_000,
        );
        let d2 = tr.drain_flushable(71_000);
        assert_eq!(d2.len(), 1);
        assert_eq!(d2[0].stop_time_ms, Some(70_000));
        assert_eq!(d2[0].exit_code, Some(0));
    }

    #[test]
    fn stale_pending_row_evicted_after_24h_and_later_stop_is_orphan() {
        let mut tr = LaunchTracker::new_for_test(Vec::new());
        tr.on_start(start(1, 4, 0, r"c:\ghost.exe"), &no_live);
        // Jump straight past the 24h staleness threshold.
        let evs = tr.drain_flushable(STALE_PENDING_THRESHOLD_MS + 1);
        assert!(evs.is_empty());
        assert_eq!(tr.status().stale_pending_evicted, 1);

        tr.on_stop(
            ProcessStopProps {
                pid: 1,
                exit_code: 0,
            },
            STALE_PENDING_THRESHOLD_MS + 2,
        );
        assert_eq!(tr.status().orphan_stops, 1);
        assert!(
            tr.drain_flushable(STALE_PENDING_THRESHOLD_MS + 3)
                .is_empty()
        );
    }

    #[test]
    fn duplicate_start_after_observe_window_keeps_windowed_state() {
        let mut tr = LaunchTracker::new_for_test(Vec::new());
        tr.on_start(start(1, 4, 0, r"c:\a.exe"), &no_live);
        tr.observe_window(1, true);
        // Duplicate start for the exact same (pid, start) key: must not
        // reset the accumulated `visible` state back to false.
        tr.on_start(start(1, 4, 0, r"c:\a.exe"), &no_live);
        tr.on_stop(
            ProcessStopProps {
                pid: 1,
                exit_code: 0,
            },
            5_000,
        );
        let evs = tr.drain_flushable(6_000);
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].window_state, WindowState::Windowed);
    }

    #[test]
    fn duplicate_start_after_stop_does_not_resurrect_the_row() {
        let mut tr = LaunchTracker::new_for_test(Vec::new());
        tr.on_start(start(1, 4, 0, r"c:\a.exe"), &no_live);
        tr.on_stop(
            ProcessStopProps {
                pid: 1,
                exit_code: 0,
            },
            1_000,
        );
        // Duplicate start after the row already finalized: must not revert
        // it back to a pending/no-stop phantom.
        tr.on_start(start(1, 4, 0, r"c:\a.exe"), &no_live);
        let evs = tr.drain_flushable(2_000);
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].stop_time_ms, Some(1_000));
    }

    #[test]
    fn recent_ring_lineage_lookup_is_reuse_proof_at_capture_time() {
        // pid 100 is reused: an earlier launch starting at t=0, then a
        // later one starting at t=2_000. A child that started at t=1_000
        // (between the two) must resolve its parent to the *earlier*
        // launch, the one actually alive at that time.
        let mut tr = LaunchTracker::new_for_test(Vec::new());
        tr.on_start(start(100, 1, 0, r"c:\first.exe"), &no_live);
        tr.on_start(start(200, 100, 1_000, r"c:\child.exe"), &no_live);
        tr.on_start(start(100, 1, 2_000, r"c:\second.exe"), &no_live);
        let evs = tr.drain_flushable(65_000); // past the 60s Running-flush threshold
        let child = evs.iter().find(|e| e.pid == 200).unwrap();
        assert_eq!(child.lineage[0].name, "first.exe");
    }

    #[test]
    fn device_map_rebuild_respects_cooldown_using_event_clock() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static REBUILD_CALLS: AtomicU64 = AtomicU64::new(0);
        fn counting_builder() -> Vec<(String, String)> {
            REBUILD_CALLS.fetch_add(1, Ordering::SeqCst);
            Vec::new()
        }
        REBUILD_CALLS.store(0, Ordering::SeqCst);

        let mut tr = LaunchTracker::new_for_test_with_rebuild(Vec::new(), counting_builder);
        tr.on_start(start(1, 4, 0, r"\Device\Mup\a.exe"), &no_live);
        assert_eq!(REBUILD_CALLS.load(Ordering::SeqCst), 1);
        // Still within the 60s cooldown window: no second rebuild.
        tr.on_start(start(2, 4, 10_000, r"\Device\Mup\b.exe"), &no_live);
        assert_eq!(REBUILD_CALLS.load(Ordering::SeqCst), 1);
        // Past the cooldown: rebuilds again.
        tr.on_start(start(3, 4, 61_000, r"\Device\Mup\c.exe"), &no_live);
        assert_eq!(REBUILD_CALLS.load(Ordering::SeqCst), 2);
    }
}
