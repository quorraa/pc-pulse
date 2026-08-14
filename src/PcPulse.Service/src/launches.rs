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

/// One ancestor launch remembered purely so a later descendant's lineage
/// walk can resolve it even after it has exited. Distinct from
/// `LineageEntry` (the public, serialized shape) because it also carries
/// `parent_pid`, needed to keep walking further up the chain.
struct RecentLaunch {
    pid: u32,
    parent_pid: u32,
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
    /// Whether `on_start` may call the real `build_device_map` (Win32) when
    /// normalization fails to map a device path. Disabled by the
    /// `#[cfg(test)]` constructor so unit tests never touch Win32.
    rebuild_device_map: bool,
    starts_seen: u64,
    stops_seen: u64,
    persisted: u64,
    orphan_stops: u64,
}

impl LaunchTracker {
    pub fn new() -> Self {
        Self {
            pending: HashMap::new(),
            pid_index: HashMap::new(),
            recent: VecDeque::new(),
            device_map: build_device_map(),
            rebuild_device_map: true,
            starts_seen: 0,
            stops_seen: 0,
            persisted: 0,
            orphan_stops: 0,
        }
    }

    /// Test-only constructor: takes a fixed device map so tests never call
    /// into Win32 (`QueryDosDeviceW`), including via the mapping-failure
    /// rebuild path.
    #[cfg(test)]
    fn new_for_test(device_map: Vec<(String, String)>) -> Self {
        Self {
            pending: HashMap::new(),
            pid_index: HashMap::new(),
            recent: VecDeque::new(),
            device_map,
            rebuild_device_map: false,
            starts_seen: 0,
            stops_seen: 0,
            persisted: 0,
            orphan_stops: 0,
        }
    }

    /// live_lookup: pid -> Some((name, Some(path))) from the live process table.
    pub fn on_start(
        &mut self,
        p: ProcessStartProps,
        live_lookup: &dyn Fn(u32) -> Option<(String, Option<String>)>,
    ) {
        self.starts_seen += 1;

        let (mut exe_path, mut mapped) = normalize_image_path(&p.image_name, &self.device_map);
        if !mapped && self.rebuild_device_map {
            self.device_map = build_device_map();
            (exe_path, mapped) = normalize_image_path(&p.image_name, &self.device_map);
        }
        let raw_image_path = if mapped {
            None
        } else {
            Some(p.image_name.clone())
        };
        let exe_name = exe_name_from_path(&exe_path);
        let console_host = is_console_host(&exe_name);
        let lineage = self.build_lineage(p.parent_pid, live_lookup);

        self.recent.push_back(RecentLaunch {
            pid: p.pid,
            parent_pid: p.parent_pid,
            name: exe_name.clone(),
            path: exe_path.clone(),
        });
        if self.recent.len() > RECENT_CAP {
            self.recent.pop_front();
        }

        self.pending.insert(
            (p.pid, p.create_time_ms),
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
    /// is not guessable).
    fn build_lineage(
        &self,
        start_pid: u32,
        live_lookup: &dyn Fn(u32) -> Option<(String, Option<String>)>,
    ) -> Vec<LineageEntry> {
        let mut lineage = Vec::new();
        let mut current_pid = start_pid;
        for _ in 0..LINEAGE_MAX_DEPTH {
            if let Some((name, path)) = live_lookup(current_pid) {
                lineage.push(LineageEntry {
                    pid: current_pid,
                    name,
                    path,
                });
                break; // live table gives no further parent pid to continue with
            }
            if let Some(entry) = self.recent.iter().rev().find(|e| e.pid == current_pid) {
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

    /// Completed launches + still-open ones >= 60s old (emitted once as
    /// Running; finalized later by upsert).
    pub fn drain_flushable(&mut self, now_ms: i64) -> Vec<LaunchEvent> {
        let mut out = Vec::new();
        let mut finished_keys = Vec::new();

        for (&(pid, start_ms), launch) in self.pending.iter() {
            if launch.stop_time_ms.is_some() {
                out.push(launch.to_event(pid));
                finished_keys.push((pid, start_ms));
            } else if now_ms - launch.start_time_ms >= RUNNING_FLUSH_THRESHOLD_MS {
                out.push(launch.to_running_event(pid));
            }
        }

        for key in finished_keys {
            self.pending.remove(&key);
            self.persisted += 1;
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
    fn no_live(_: u32) -> Option<(String, Option<String>)> {
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
}
