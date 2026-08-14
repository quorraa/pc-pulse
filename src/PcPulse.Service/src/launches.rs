//! Pure helpers for launch-history tracking: kernel image-path normalization
//! and console-host classification, plus the stateful `LaunchTracker` that
//! turns ETW start/stop events into `LaunchEvent` rows -- capture-time
//! lineage resolution, stop matching (PID-reuse safe), window-visibility
//! state, and the 60s "still running" flush.

use std::collections::{HashMap, VecDeque};

use serde::{Deserialize, Serialize};
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

/// Decodes the first target string out of a `QueryDosDeviceW` result buffer.
///
/// `QueryDosDeviceW` fills `buf` with a `MULTI_SZ`: one or more
/// NUL-terminated strings followed by an extra terminating NUL, and `len`
/// (the value it returns) counts every character written, including all of
/// those NULs. Naively decoding `buf[..len - 1]` therefore leaves an
/// embedded NUL at the end of a single-target result (only the final,
/// list-terminating NUL is stripped), which then never matches as a path
/// prefix downstream. Splitting on the first NUL both fixes that and picks
/// just the first target when a drive letter unusually has more than one
/// (a symbolic-link chain), matching what production code has always
/// wanted here.
///
/// Returns `None` if `len` is `0` or the first target is empty.
pub(crate) fn first_multi_sz_target(buf: &[u16], len: usize) -> Option<String> {
    if len == 0 {
        return None;
    }

    let bytes = &buf[..len.min(buf.len())];
    let first = bytes.split(|&c| c == 0).next().unwrap_or(&[]);
    if first.is_empty() {
        return None;
    }

    Some(String::from_utf16_lossy(first))
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

        let Some(device) = first_multi_sz_target(&buf, len as usize) else {
            continue;
        };

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

    /// Closes the pending launch matching `p.pid`, stamping it with the stop
    /// *event's* own time (`p.stop_time_ms`).
    ///
    /// Deliberately takes no wall clock: it used to be handed the sampling
    /// tick's `Utc::now()`, which stamped every exit with when we happened
    /// to drain the ETW queue rather than when the process died. The kernel
    /// session flushes on a 1s timer and the loop drains on its own
    /// interval, so a 300ms popup was recorded as living for seconds --
    /// durations measured our delivery latency, not the process. Sourcing
    /// the stamp from the event alone makes that regression unrepresentable
    /// rather than merely fixed at the one call site.
    ///
    /// Note this is only the *recorded* clock domain: `drain_flushable` and
    /// the staleness eviction still run on wall-clock time, since those are
    /// decisions about our own bookkeeping, not about the process.
    pub fn on_stop(&mut self, p: ProcessStopProps) {
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

        launch.stop_time_ms = Some(p.stop_time_ms);
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

/// Cap on the pending command-line ring. Entries only live here between the
/// MOF session observing a process start and the launch row for that same
/// start being drained (a tick or two), so this is generous slack; it exists
/// so an unmatched flood costs bounded memory rather than unbounded growth.
const CMDLINE_JOIN_CAP: usize = 4096;
/// How far apart the MOF session's create time and the manifest session's
/// `CreateTime` may be and still describe the same launch. The two sessions
/// timestamp the same kernel event from different clocks (manifest
/// `CreateTime` FILETIME vs. the MOF event's header timestamp), so an exact
/// match is not available; 2s is the spec's join window.
const CMDLINE_JOIN_WINDOW_MS: i64 = 2_000;
/// How long an unclaimed capture is kept. A launch row can wait up to the
/// 60s `Running` flush before it asks for its command line, so this is
/// generous slack past that; beyond it the capture belongs to a process the
/// tracker never recorded (the MOF session sees every process on the
/// machine, not just tracked launches) and is evicted. Age eviction matters
/// as much as the cap: on a machine churning starts, cap-only eviction would
/// silently discard *recent* captures while stale ones sat at the front.
const CMDLINE_JOIN_MAX_AGE_MS: i64 = 5 * 60_000;

/// One redacted command line waiting to be joined to its launch row.
///
/// There is deliberately no field holding the original text: `offer`
/// redacts before constructing this, so the raw line exists only as the
/// caller's borrowed `&str` and is never owned by the joiner.
struct PendingCmdline {
    pid: u32,
    start_ms: i64,
    redacted: String,
    redacted_fields: u32,
}

/// Joins command lines captured by the opt-in MOF session to the launch rows
/// produced from the manifest session, by `(pid, |start delta| <= 2s)`.
///
/// Privacy invariant: this type never stores an un-redacted command line.
/// [`redact_command_line`](crate::redact::redact_command_line) runs inside
/// [`CmdlineJoiner::offer`], before the entry is created, so the raw line is
/// dropped at the door rather than at persist time.
#[derive(Default)]
pub struct CmdlineJoiner {
    entries: VecDeque<PendingCmdline>,
    unmatched_evicted: u64,
}

impl CmdlineJoiner {
    pub fn new() -> Self {
        Self {
            entries: VecDeque::new(),
            unmatched_evicted: 0,
        }
    }

    /// Redacts `raw_line` and remembers the result against
    /// `(pid, event_start_ms)`. The raw text is never stored.
    pub fn offer(&mut self, pid: u32, event_start_ms: i64, raw_line: &str) {
        let (redacted, redacted_fields) = crate::redact::redact_command_line(raw_line);
        self.entries.push_back(PendingCmdline {
            pid,
            start_ms: event_start_ms,
            redacted,
            redacted_fields,
        });
        while self.entries.len() > CMDLINE_JOIN_CAP {
            self.entries.pop_front();
            self.unmatched_evicted += 1;
        }
    }

    /// Drops captures older than [`CMDLINE_JOIN_MAX_AGE_MS`]. Called once per
    /// tick so eviction happens on the clock rather than only under pressure
    /// from new captures.
    ///
    /// Entries are kept in offer order, which is the MOF session's event
    /// order, so this scans from the front and stops at the first entry young
    /// enough to keep -- an out-of-order straggler costs at most one extra
    /// entry's lifetime, never a full scan per tick.
    pub fn evict_older_than(&mut self, now_ms: i64) {
        while let Some(entry) = self.entries.front() {
            if now_ms.saturating_sub(entry.start_ms) <= CMDLINE_JOIN_MAX_AGE_MS {
                break;
            }
            self.entries.pop_front();
            self.unmatched_evicted += 1;
        }
    }

    /// Captures dropped without ever being claimed by a launch row, by age or
    /// by the cap. Absolute total for the joiner's lifetime.
    pub fn unmatched_evicted(&self) -> u64 {
        self.unmatched_evicted
    }

    /// Attaches the closest matching capture to `ev` (same pid, start times
    /// within [`CMDLINE_JOIN_WINDOW_MS`]), removing it from the ring so one
    /// capture can never be attached to two launches. Returns the redacted
    /// line and its redaction count for the caller to persist encrypted.
    pub fn attach(&mut self, ev: &mut LaunchEvent) -> Option<(String, u32)> {
        let index = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| {
                entry.pid == ev.pid
                    && delta_ms(entry.start_ms, ev.start_time_ms) <= CMDLINE_JOIN_WINDOW_MS
            })
            .min_by_key(|(_, entry)| delta_ms(entry.start_ms, ev.start_time_ms))
            .map(|(index, _)| index)?;
        let entry = self.entries.remove(index)?;
        ev.command_line = Some(entry.redacted.clone());
        Some((entry.redacted, entry.redacted_fields))
    }

    /// Drops every pending capture. Called when the opt-in setting is turned
    /// off, so nothing captured before the flip can still be persisted after
    /// it.
    ///
    /// Deliberately *not* counted as unmatched eviction: this is the user
    /// withdrawing consent, not the join losing data, and mixing the two
    /// would make the counter useless for spotting a broken join.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }
}

/// Absolute distance between two epoch-millisecond timestamps, saturating
/// rather than overflowing/panicking on extreme values (`i64::MIN.abs()`
/// panics).
fn delta_ms(a: i64, b: i64) -> i64 {
    a.saturating_sub(b).saturating_abs()
}

// ---------------------------------------------------------------------
// Launch grouping (Task 8)
// ---------------------------------------------------------------------

const TRAILING_24H_MS: i64 = 24 * 60 * 60 * 1000;

/// Ancestor-chain signature used as half of a launch group's key: the
/// lowercase launcher names, nearest first, joined by `<` (e.g.
/// `"cmd.exe<explorer.exe"`). Lowercasing means two launches through the
/// same chain of launchers group together even if capture-time casing
/// differed; an empty lineage signs as the empty string.
pub fn lineage_sig(lineage: &[LineageEntry]) -> String {
    lineage
        .iter()
        .map(|entry| entry.name.to_lowercase())
        .collect::<Vec<_>>()
        .join("<")
}

/// Human-facing summary of what launched this: the nearest ancestor's own
/// name, or `"unknown"` when the launch has no resolved lineage at all.
fn launcher_summary(lineage: &[LineageEntry]) -> String {
    lineage
        .first()
        .map(|entry| entry.name.clone())
        .unwrap_or_else(|| "unknown".to_string())
}

/// One `(exe_path, lineage_sig)` bucket of recorded launches, with
/// aggregate stats a client can chart without re-deriving them from raw
/// rows. Produced by [`group_launches`]; the underlying occurrences
/// themselves are fetched separately (`getLaunchOccurrences`) by this
/// group's `(exe_path, lineage_sig)` key.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LaunchGroup {
    pub exe_name: String,
    pub exe_path: String,
    /// `"<"`-joined lowercase lineage names, e.g. `"cmd.exe<explorer.exe"`.
    pub lineage_sig: String,
    /// First lineage entry's name, or `"unknown"`.
    pub launcher_summary: String,
    pub count: usize,
    pub first_ms: i64,
    pub last_ms: i64,
    /// Median gap between successive `start_time_ms` values in the group,
    /// ascending. `None` when `count < 2` -- there is no interval to
    /// measure.
    pub median_interval_ms: Option<i64>,
    /// Mean/max duration (`stop_time_ms - start_time_ms`) over completed
    /// occurrences only. `None` when none of the group's occurrences have
    /// finished (all still `Running`).
    pub mean_duration_ms: Option<i64>,
    pub max_duration_ms: Option<i64>,
    pub windowed: usize,
    pub never_windowed: usize,
    pub unobserved: usize,
    pub running: usize,
    pub console_host: bool,
}

/// Median of the successive gaps between ascending `start_time_ms`
/// values. `starts.len() < 2` has nothing to measure -- `None`, not zero.
fn median_interval_ms(mut starts: Vec<i64>) -> Option<i64> {
    if starts.len() < 2 {
        return None;
    }
    starts.sort_unstable();
    let mut diffs: Vec<i64> = starts
        .windows(2)
        .map(|pair| pair[1].saturating_sub(pair[0]))
        .collect();
    diffs.sort_unstable();
    Some(median_of_sorted(&diffs))
}

/// Median of an already-sorted, non-empty slice: the middle element for an
/// odd length, the round-half-away-from-zero average of the two middle
/// elements for an even one (e.g. diffs `[1, 2]` -> `2`, not `1`).
///
/// `sorted` here is always a list of `start_time_ms` gaps computed from an
/// ascending-sorted list of starts, so every element is `>= 0`; the integer
/// rounding below (`sum / 2 + sum % 2`) relies on that non-negativity and
/// uses `saturating_add` rather than plain `+` so an extreme (near-`i64::MAX`)
/// gap cannot overflow into a nonsense negative median.
fn median_of_sorted(sorted: &[i64]) -> i64 {
    let n = sorted.len();
    if n % 2 == 1 {
        sorted[n / 2]
    } else {
        let a = sorted[n / 2 - 1];
        let b = sorted[n / 2];
        let sum = a.saturating_add(b);
        sum / 2 + sum % 2
    }
}

/// Builds one [`LaunchGroup`] from every occurrence sharing an
/// `(exe_path, lineage_sig)` key. `occurrences` must be non-empty.
fn build_group(occurrences: &[&LaunchEvent]) -> LaunchGroup {
    let representative = occurrences[0];
    let starts: Vec<i64> = occurrences
        .iter()
        .map(|event| event.start_time_ms)
        .collect();
    // `occurrences` is always non-empty (callers only ever build a group
    // from a bucket that has at least one member), so folding from the
    // identity extremes is equivalent to `.min()`/`.max()` without an
    // `unwrap`/`expect` this crate denies outside tests.
    let first_ms = starts.iter().copied().fold(i64::MAX, i64::min);
    let last_ms = starts.iter().copied().fold(i64::MIN, i64::max);

    let durations: Vec<i64> = occurrences
        .iter()
        .filter_map(|event| {
            event
                .stop_time_ms
                .map(|stop| stop.saturating_sub(event.start_time_ms))
        })
        .collect();
    let (mean_duration_ms, max_duration_ms) = if durations.is_empty() {
        (None, None)
    } else {
        let sum: i64 = durations.iter().copied().fold(0, i64::saturating_add);
        let mean = sum / durations.len() as i64;
        let max = durations.iter().copied().fold(i64::MIN, i64::max);
        (Some(mean), Some(max))
    };

    let (mut windowed, mut never_windowed, mut unobserved, mut running) =
        (0usize, 0usize, 0usize, 0usize);
    for event in occurrences {
        match event.window_state {
            WindowState::Windowed => windowed += 1,
            WindowState::NeverWindowed => never_windowed += 1,
            WindowState::Unobserved => unobserved += 1,
            WindowState::Running => running += 1,
        }
    }

    LaunchGroup {
        exe_name: representative.exe_name.clone(),
        exe_path: representative.exe_path.clone(),
        lineage_sig: lineage_sig(&representative.lineage),
        launcher_summary: launcher_summary(&representative.lineage),
        count: occurrences.len(),
        first_ms,
        last_ms,
        median_interval_ms: median_interval_ms(starts),
        mean_duration_ms,
        max_duration_ms,
        windowed,
        never_windowed,
        unobserved,
        running,
        console_host: representative.console_host,
    }
}

/// Groups launch events by `(exe_path, lineage_sig)` -- never by
/// `session_id`: the same launcher chain across different sessions is one
/// group, and its individual occurrences (fetched separately via
/// `getLaunchOccurrences`) keep their own distinct `session_id`s.
///
/// Sorted by each group's occurrence count within the trailing 24h of the
/// newest `start_time_ms` across all of `events` (desc), ties broken by
/// the group's own `last_ms` (desc), then truncated to `limit`. This
/// deliberately favors recent activity over raw lifetime count: a group
/// that launched heavily weeks ago but is quiet now sorts below a group
/// that is active right now, however small its total.
pub fn group_launches(
    events: &[LaunchEvent],
    console_hosts_only: bool,
    limit: usize,
) -> Vec<LaunchGroup> {
    let mut buckets: HashMap<(String, String), Vec<&LaunchEvent>> = HashMap::new();
    for event in events {
        let sig = lineage_sig(&event.lineage);
        buckets
            .entry((event.exe_path.clone(), sig))
            .or_default()
            .push(event);
    }

    let newest = events
        .iter()
        .map(|event| event.start_time_ms)
        .max()
        .unwrap_or(0);
    let window_start = newest.saturating_sub(TRAILING_24H_MS);

    let mut scored: Vec<(usize, LaunchGroup)> = buckets
        .into_values()
        .map(|occurrences| {
            let count_24h = occurrences
                .iter()
                .filter(|event| {
                    event.start_time_ms >= window_start && event.start_time_ms <= newest
                })
                .count();
            (count_24h, build_group(&occurrences))
        })
        .collect();

    if console_hosts_only {
        scored.retain(|(_, group)| group.console_host);
    }

    // Final two tie-breakers make the order fully deterministic even when
    // two groups share both the 24h count and `last_ms` exactly (e.g. two
    // executables that both last launched in the same millisecond): without
    // them, `HashMap`'s iteration order would leak into the response and a
    // client polling `getLaunchGroups` could see two equally-ranked groups
    // swap positions between otherwise-identical requests.
    scored.sort_by(|a, b| {
        b.0.cmp(&a.0)
            .then_with(|| b.1.last_ms.cmp(&a.1.last_ms))
            .then_with(|| a.1.exe_path.cmp(&b.1.exe_path))
            .then_with(|| a.1.lineage_sig.cmp(&b.1.lineage_sig))
    });

    scored
        .into_iter()
        .take(limit)
        .map(|(_, group)| group)
        .collect()
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

    /// Builds a `QueryDosDeviceW`-shaped buffer: `target` encoded as UTF-16,
    /// NUL-terminated, followed by the list-terminating extra NUL -- exactly
    /// what a single-target `MULTI_SZ` result looks like, with `len` set the
    /// way the real API reports it (counting every char written, both NULs
    /// included).
    fn multi_sz_buf(target: &str) -> (Vec<u16>, usize) {
        let mut buf: Vec<u16> = target.encode_utf16().collect();
        buf.push(0); // terminates this target
        buf.push(0); // terminates the MULTI_SZ list
        let len = buf.len();
        (buf, len)
    }

    #[test]
    fn first_multi_sz_target_decodes_single_target_past_its_nul() {
        let (buf, len) = multi_sz_buf(r"\Device\HarddiskVolume5");
        let decoded = first_multi_sz_target(&buf, len);
        assert_eq!(decoded.as_deref(), Some(r"\Device\HarddiskVolume5"));
    }

    #[test]
    fn first_multi_sz_target_picks_first_of_multiple_targets() {
        let mut buf: Vec<u16> = r"\Device\HarddiskVolume5".encode_utf16().collect();
        buf.push(0);
        buf.extend(r"\Device\HarddiskVolumeShadowCopy1".encode_utf16());
        buf.push(0);
        buf.push(0); // list-terminating NUL
        let len = buf.len();

        let decoded = first_multi_sz_target(&buf, len);
        assert_eq!(decoded.as_deref(), Some(r"\Device\HarddiskVolume5"));
    }

    #[test]
    fn first_multi_sz_target_none_when_target_empty() {
        // An immediate NUL (empty first target) decodes to `None` rather
        // than an empty string.
        let buf: Vec<u16> = vec![0, 0];
        let len = buf.len();
        assert_eq!(first_multi_sz_target(&buf, len), None);
    }

    #[test]
    fn first_multi_sz_target_none_when_len_zero() {
        let buf: Vec<u16> = vec![0u16; 260];
        assert_eq!(first_multi_sz_target(&buf, 0), None);
    }

    #[test]
    fn device_path_with_trailing_embedded_nul_does_not_match_normalize() {
        // Documents the pre-fix bug shape: if the device string in the map
        // still carries a trailing embedded NUL (as `build_device_map` used
        // to produce before decoding via `first_multi_sz_target`), the
        // stored prefix never matches a real (NUL-free) image path, so every
        // launch silently falls through to "unmapped".
        let device_with_trailing_nul = format!("{}{}", r"\device\harddiskvolume5", '\0');
        let map = vec![(device_with_trailing_nul, "c:".to_string())];

        let (p, mapped) =
            normalize_image_path(r"\Device\HarddiskVolume5\Windows\System32\cmd.exe", &map);

        assert!(!mapped, "a NUL-contaminated device prefix must not match");
        assert_eq!(p, r"\device\harddiskvolume5\windows\system32\cmd.exe");
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
    /// `at_ms` is the stop *event's* own timestamp -- what the ETW record
    /// header carried -- which is exactly what lands on the row. The tracker
    /// has no other clock for it, by design.
    fn stop(pid: u32, exit_code: u32, at_ms: i64) -> ProcessStopProps {
        ProcessStopProps {
            pid,
            exit_code,
            stop_time_ms: at_ms,
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
        tr.on_stop(stop(500, 1, 1_300));
        let ev = &tr.drain_flushable(2_000)[0];
        assert_eq!(ev.stop_time_ms, Some(1_300));
        assert_eq!(ev.exit_code, Some(1));
        assert_eq!(ev.window_state, WindowState::Unobserved);
    }

    #[test]
    fn sub_second_lifetime_survives_seconds_of_delivery_latency() {
        // The marquee case: a 300ms popup whose stop event only reaches us
        // seconds after the fact (kernel FlushTimer + the sampling
        // interval). The delivery is late in every way the tracker could
        // possibly notice -- `on_stop` is called long after the exit and the
        // drain happens later still -- yet the recorded lifetime must be the
        // process's 300ms, not the multi-second round trip. Before the stop
        // stamp moved to the event's own header timestamp this recorded
        // ~4_700ms of pure delivery latency.
        let mut tr = LaunchTracker::new_for_test(Vec::new());
        tr.on_start(
            start(500, 4, 1_000, r"\Device\HarddiskVolume4\x\popup.exe"),
            &no_live,
        );
        // Event time 1_300 (300ms after start); everything downstream of it
        // is seconds later.
        tr.on_stop(stop(500, 0, 1_300));
        let ev = &tr.drain_flushable(6_000)[0];
        let duration_ms = ev.stop_time_ms.unwrap() - ev.start_time_ms;
        assert_eq!(duration_ms, 300);
        assert!(
            duration_ms < 1_000,
            "sub-second lifetime reported as {duration_ms}ms -- that is delivery latency, \
             not a process lifetime"
        );
    }

    #[test]
    fn pid_reuse_produces_distinct_rows_with_correct_stop_matching() {
        let mut tr = LaunchTracker::new_for_test(Vec::new());
        tr.on_start(start(500, 4, 1_000, r"c:\a.exe"), &no_live);
        tr.on_stop(stop(500, 0, 2_000));
        tr.on_start(start(500, 4, 3_000, r"c:\b.exe"), &no_live);
        tr.on_stop(stop(500, 7, 4_000));
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
        tr.on_stop(stop(999, 0, 1_000));
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
        tr.on_stop(stop(1, 0, 5_000));
        tr.on_stop(stop(2, 0, 5_000));
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
        tr.on_stop(stop(1, 0, 90_000));
        let second = tr.drain_flushable(91_000);
        assert_eq!(second[0].stop_time_ms, Some(90_000)); // same (pid,start) key → upsert finalizes
    }
    #[test]
    fn rapid_repeated_launches_all_recorded() {
        let mut tr = LaunchTracker::new_for_test(Vec::new());
        for i in 0..50 {
            tr.on_start(start(1000 + i, 4, i as i64 * 10, r"c:\spam.exe"), &no_live);
            tr.on_stop(stop(1000 + i, 0, i as i64 * 10 + 5));
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
        tr.on_stop(stop(1, 0, 70_000));
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

        tr.on_stop(stop(1, 0, STALE_PENDING_THRESHOLD_MS + 2));
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
        tr.on_stop(stop(1, 0, 5_000));
        let evs = tr.drain_flushable(6_000);
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].window_state, WindowState::Windowed);
    }

    #[test]
    fn duplicate_start_after_stop_does_not_resurrect_the_row() {
        let mut tr = LaunchTracker::new_for_test(Vec::new());
        tr.on_start(start(1, 4, 0, r"c:\a.exe"), &no_live);
        tr.on_stop(stop(1, 0, 1_000));
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

    // -- CmdlineJoiner (Task 7) ---------------------------------------

    fn launch_event(pid: u32, start_time_ms: i64) -> LaunchEvent {
        LaunchEvent {
            pid,
            start_time_ms,
            stop_time_ms: None,
            exit_code: None,
            exe_name: "x.exe".into(),
            exe_path: r"c:\x.exe".into(),
            raw_image_path: None,
            session_id: 1,
            parent_pid: 4,
            lineage: Vec::new(),
            window_state: WindowState::Running,
            console_host: false,
            command_line: None,
        }
    }

    #[test]
    fn joiner_attaches_within_the_two_second_window_and_removes_the_entry() {
        let mut joiner = CmdlineJoiner::new();
        joiner.offer(500, 10_000, r"c:\x.exe --flag");
        let mut ev = launch_event(500, 11_500); // 1.5s apart
        let (line, fields) = joiner.attach(&mut ev).expect("within window");
        assert_eq!(line, r"c:\x.exe --flag");
        assert_eq!(fields, 0);
        assert_eq!(ev.command_line.as_deref(), Some(r"c:\x.exe --flag"));
        // Consumed: a second launch must not inherit the same capture.
        let mut again = launch_event(500, 11_500);
        assert!(joiner.attach(&mut again).is_none());
        assert_eq!(joiner.len(), 0);
    }

    #[test]
    fn launch_event_debug_never_prints_the_command_line() {
        // Redaction strips secrets, not identity: what survives is still the
        // user's own paths and document names. A derived `Debug` -- which is
        // what this guards against being reintroduced -- would put that
        // straight into any log line or panic message that formats a
        // `LaunchEvent`.
        let mut ev = launch_event(500, 11_500);
        ev.command_line = Some(r"c:\x.exe --open c:\users\someone\taxes-2025.pdf".into());
        let rendered = format!("{ev:?}");
        assert!(
            !rendered.contains("taxes-2025"),
            "command line leaked into Debug: {rendered}"
        );
        assert!(
            !rendered.contains("someone"),
            "command line leaked into Debug: {rendered}"
        );
        // Presence stays visible -- "was a line attached?" is legitimate
        // diagnostic signal, and eliding it would hide join failures.
        assert!(rendered.contains("‹elided›"), "{rendered}");
        let mut absent = launch_event(500, 11_500);
        absent.command_line = None;
        assert!(format!("{absent:?}").contains("command_line: None"));
    }

    #[test]
    fn joiner_exact_window_boundary_matches_and_beyond_it_does_not() {
        let mut joiner = CmdlineJoiner::new();
        joiner.offer(500, 10_000, "a");
        let mut on_edge = launch_event(500, 12_000); // exactly 2 000 ms
        assert!(joiner.attach(&mut on_edge).is_some());

        joiner.offer(500, 10_000, "b");
        let mut too_far = launch_event(500, 12_500); // 2.5s apart
        assert!(joiner.attach(&mut too_far).is_none());
        assert!(too_far.command_line.is_none());
        assert_eq!(joiner.len(), 1, "a non-match must not consume the entry");
    }

    #[test]
    fn joiner_matches_only_the_same_pid_and_prefers_the_closest_start() {
        let mut joiner = CmdlineJoiner::new();
        joiner.offer(500, 10_000, "far");
        joiner.offer(500, 11_000, "near");
        joiner.offer(999, 11_100, "other pid");
        let mut ev = launch_event(500, 11_200);
        let (line, _) = joiner.attach(&mut ev).unwrap();
        assert_eq!(line, "near");
        assert_eq!(joiner.len(), 2);
    }

    #[test]
    fn joiner_redacts_on_entry_so_the_secret_is_never_stored() {
        let mut joiner = CmdlineJoiner::new();
        joiner.offer(1, 0, "tool.exe --password hunter2 --user bob");
        let mut ev = launch_event(1, 0);
        let (line, fields) = joiner.attach(&mut ev).unwrap();
        assert!(
            !line.contains("hunter2"),
            "stored line still has it: {line}"
        );
        assert!(fields >= 1, "redaction count must reflect the hit");
        assert_eq!(ev.command_line.as_deref(), Some(line.as_str()));
    }

    #[test]
    fn joiner_attach_on_empty_ring_is_none() {
        let mut joiner = CmdlineJoiner::new();
        let mut ev = launch_event(1, 0);
        assert!(joiner.attach(&mut ev).is_none());
        assert!(ev.command_line.is_none());
    }

    #[test]
    fn joiner_evicts_by_age_and_counts_what_was_never_claimed() {
        let mut joiner = CmdlineJoiner::new();
        joiner.offer(1, 0, "old");
        joiner.offer(2, CMDLINE_JOIN_MAX_AGE_MS, "young");

        // Exactly at the age limit the oldest still stays: eviction is for
        // captures that are *past* the window, not at its edge.
        joiner.evict_older_than(CMDLINE_JOIN_MAX_AGE_MS);
        assert_eq!(joiner.len(), 2);
        assert_eq!(joiner.unmatched_evicted(), 0);

        joiner.evict_older_than(CMDLINE_JOIN_MAX_AGE_MS + 1);
        assert_eq!(joiner.len(), 1);
        assert_eq!(joiner.unmatched_evicted(), 1);
        // The survivor is the young one, still joinable.
        let mut ev = launch_event(2, CMDLINE_JOIN_MAX_AGE_MS);
        assert_eq!(joiner.attach(&mut ev).unwrap().0, "young");
        // An attached capture is not an eviction.
        assert_eq!(joiner.unmatched_evicted(), 1);
    }

    #[test]
    fn joiner_clear_is_consent_withdrawal_not_counted_loss() {
        let mut joiner = CmdlineJoiner::new();
        joiner.offer(1, 0, "x");
        joiner.clear();
        assert_eq!(
            joiner.unmatched_evicted(),
            0,
            "turning the setting off is not a join failure"
        );
    }

    #[test]
    fn joiner_evicts_oldest_past_the_cap() {
        let mut joiner = CmdlineJoiner::new();
        for index in 0..(CMDLINE_JOIN_CAP + 10) {
            joiner.offer(index as u32, index as i64, "x");
        }
        assert_eq!(joiner.len(), CMDLINE_JOIN_CAP);
        assert_eq!(
            joiner.unmatched_evicted(),
            10,
            "cap eviction is silent loss unless it is counted"
        );
        // The ten oldest are gone; the newest are still joinable.
        let mut oldest = launch_event(0, 0);
        assert!(joiner.attach(&mut oldest).is_none());
        let newest_pid = (CMDLINE_JOIN_CAP + 9) as u32;
        let mut newest = launch_event(newest_pid, i64::from(newest_pid));
        assert!(joiner.attach(&mut newest).is_some());
    }

    #[test]
    fn joiner_clear_drops_everything_captured_before_the_toggle_flipped_off() {
        let mut joiner = CmdlineJoiner::new();
        joiner.offer(1, 0, "x");
        joiner.clear();
        let mut ev = launch_event(1, 0);
        assert!(joiner.attach(&mut ev).is_none());
        assert_eq!(joiner.len(), 0);
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

    // -- group_launches (Task 8) ---------------------------------------

    fn group_test_event(
        pid: u32,
        start_ms: i64,
        exe_path: &str,
        lineage_names: &[&str],
    ) -> LaunchEvent {
        let exe_name = exe_name_from_path(exe_path);
        LaunchEvent {
            pid,
            start_time_ms: start_ms,
            stop_time_ms: None,
            exit_code: None,
            console_host: is_console_host(&exe_name),
            exe_name,
            exe_path: exe_path.to_string(),
            raw_image_path: None,
            session_id: 1,
            parent_pid: 4,
            lineage: lineage_names
                .iter()
                .enumerate()
                .map(|(index, name)| LineageEntry {
                    pid: 100 + index as u32,
                    name: name.to_string(),
                    path: None,
                })
                .collect(),
            window_state: WindowState::Unobserved,
            command_line: None,
        }
    }

    #[test]
    fn grouping_key_separates_same_exe_under_different_launchers() {
        let events = vec![
            group_test_event(1, 0, r"c:\a.exe", &["explorer.exe"]),
            group_test_event(2, 1_000, r"c:\a.exe", &["cmd.exe"]),
        ];
        let groups = group_launches(&events, false, 500);
        assert_eq!(
            groups.len(),
            2,
            "same exe under different launchers must not merge"
        );
        assert!(groups.iter().any(|g| g.lineage_sig == "explorer.exe"));
        assert!(groups.iter().any(|g| g.lineage_sig == "cmd.exe"));
    }

    #[test]
    fn median_interval_over_three_starts_is_the_average_of_the_two_middle_gaps() {
        let events = vec![
            group_test_event(1, 0, r"c:\a.exe", &[]),
            group_test_event(2, 10_000, r"c:\a.exe", &[]),
            group_test_event(3, 25_000, r"c:\a.exe", &[]),
        ];
        let groups = group_launches(&events, false, 500);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].median_interval_ms, Some(12_500));
    }

    #[test]
    fn median_interval_over_two_occurrences_is_their_single_gap() {
        let events = vec![
            group_test_event(1, 0, r"c:\a.exe", &[]),
            group_test_event(2, 7_000, r"c:\a.exe", &[]),
        ];
        let groups = group_launches(&events, false, 500);
        assert_eq!(groups[0].median_interval_ms, Some(7_000));
    }

    #[test]
    fn median_interval_rounds_half_gaps_away_from_zero() {
        // Three starts (0, 1, 3) produce gap diffs [1, 2]; their average,
        // 1.5, must round to 2 -- not down to 1 (banker's/truncating
        // rounding) and not to -2 (away from zero in the wrong direction).
        let events = vec![
            group_test_event(1, 0, r"c:\a.exe", &[]),
            group_test_event(2, 1, r"c:\a.exe", &[]),
            group_test_event(3, 3, r"c:\a.exe", &[]),
        ];
        let groups = group_launches(&events, false, 500);
        assert_eq!(groups[0].median_interval_ms, Some(2));
    }

    #[test]
    fn a_single_occurrence_has_no_median_interval() {
        let events = vec![group_test_event(1, 0, r"c:\a.exe", &[])];
        let groups = group_launches(&events, false, 500);
        assert_eq!(groups[0].count, 1);
        assert_eq!(groups[0].median_interval_ms, None);
    }

    #[test]
    fn duration_stats_ignore_still_running_occurrences() {
        let mut finished = group_test_event(1, 0, r"c:\a.exe", &[]);
        finished.stop_time_ms = Some(1_000);
        let mut running = group_test_event(2, 2_000, r"c:\a.exe", &[]);
        running.window_state = WindowState::Running;
        let groups = group_launches(&[finished, running], false, 500);
        assert_eq!(groups[0].mean_duration_ms, Some(1_000));
        assert_eq!(groups[0].max_duration_ms, Some(1_000));
        assert_eq!(
            groups[0].running, 1,
            "the running row must still count in the histogram"
        );
    }

    #[test]
    fn duration_stats_are_none_when_nothing_has_completed() {
        let mut running = group_test_event(1, 0, r"c:\a.exe", &[]);
        running.window_state = WindowState::Running;
        let groups = group_launches(&[running], false, 500);
        assert_eq!(groups[0].mean_duration_ms, None);
        assert_eq!(groups[0].max_duration_ms, None);
    }

    #[test]
    fn window_state_histogram_sums_to_the_group_count() {
        let mut windowed = group_test_event(1, 0, r"c:\a.exe", &[]);
        windowed.window_state = WindowState::Windowed;
        let mut never_windowed = group_test_event(2, 1, r"c:\a.exe", &[]);
        never_windowed.window_state = WindowState::NeverWindowed;
        let mut unobserved = group_test_event(3, 2, r"c:\a.exe", &[]);
        unobserved.window_state = WindowState::Unobserved;
        let mut running = group_test_event(4, 3, r"c:\a.exe", &[]);
        running.window_state = WindowState::Running;
        let groups = group_launches(&[windowed, never_windowed, unobserved, running], false, 500);
        let group = &groups[0];
        assert_eq!(group.count, 4);
        assert_eq!(
            group.windowed + group.never_windowed + group.unobserved + group.running,
            group.count
        );
        assert_eq!(
            (
                group.windowed,
                group.never_windowed,
                group.unobserved,
                group.running
            ),
            (1, 1, 1, 1)
        );
    }

    #[test]
    fn console_filter_keeps_only_console_host_groups() {
        let console = group_test_event(1, 0, r"c:\windows\system32\cmd.exe", &[]);
        let non_console = group_test_event(2, 0, r"c:\a.exe", &[]);
        let groups = group_launches(&[console, non_console], true, 500);
        assert_eq!(groups.len(), 1);
        assert!(groups[0].console_host);
        assert_eq!(groups[0].exe_name.to_lowercase(), "cmd.exe");
    }

    #[test]
    fn limit_truncates_after_sorting_not_before() {
        let events: Vec<LaunchEvent> = (0..5)
            .map(|i| group_test_event(i, i as i64 * 1_000, &format!(r"c:\p{i}.exe"), &[]))
            .collect();
        let groups = group_launches(&events, false, 2);
        assert_eq!(
            groups.len(),
            2,
            "limit must apply after the full set is scored and sorted"
        );
    }

    #[test]
    fn sort_favors_trailing_24h_activity_over_raw_lifetime_count() {
        let day_ms = 24 * 60 * 60 * 1000;
        let newest = 100 * day_ms;

        // Old-heavy: ten launches, every one of them more than 24h before
        // the newest event in the whole set.
        let old_heavy: Vec<LaunchEvent> = (0..10)
            .map(|i| group_test_event(i, newest - 2 * day_ms - i as i64, r"c:\old.exe", &[]))
            .collect();
        // Recent-active: only three launches, but all inside the trailing
        // 24h window, including the set's overall newest event.
        let recent_active: Vec<LaunchEvent> = (0..3)
            .map(|i| group_test_event(100 + i, newest - i as i64 * 1_000, r"c:\recent.exe", &[]))
            .collect();

        let mut events = old_heavy;
        events.extend(recent_active);

        let groups = group_launches(&events, false, 500);
        assert_eq!(
            groups[0].exe_path, r"c:\recent.exe",
            "a smaller but currently-active group must outrank a bigger but stale one"
        );
        assert_eq!(groups[1].exe_path, r"c:\old.exe");
    }

    #[test]
    fn sort_is_deterministic_when_count_and_last_ms_both_tie() {
        // Two distinct groups (different exe_path) that launched exactly
        // once each, at the exact same millisecond: count and last_ms tie
        // completely, so only the exe_path/lineage_sig tie-breakers decide
        // the order -- and they must decide it the same way every time,
        // not however `HashMap` happened to iterate this run.
        let events = vec![
            group_test_event(1, 1_000, r"c:\zeta.exe", &[]),
            group_test_event(2, 1_000, r"c:\alpha.exe", &[]),
        ];
        let groups = group_launches(&events, false, 500);
        assert_eq!(groups.len(), 2);
        assert_eq!(
            groups[0].exe_path, r"c:\alpha.exe",
            "lexicographically-first exe_path must sort first once every other key ties"
        );
        assert_eq!(groups[1].exe_path, r"c:\zeta.exe");
    }

    #[test]
    fn grouping_does_not_key_on_session_id() {
        let mut first = group_test_event(1, 0, r"c:\a.exe", &[]);
        first.session_id = 1;
        let mut second = group_test_event(2, 1_000, r"c:\a.exe", &[]);
        second.session_id = 2;

        let groups = group_launches(&[first.clone(), second.clone()], false, 500);
        assert_eq!(
            groups.len(),
            1,
            "distinct session_ids must not split a group -- only exe_path/lineage_sig do"
        );
        assert_eq!(groups[0].count, 2);
        // The occurrences themselves (fetched separately, by this task's
        // getLaunchOccurrences handler) are untouched and keep their own
        // distinct session ids -- grouping never overwrites or collapses
        // that field.
        assert_ne!(first.session_id, second.session_id);
    }
}
