# Launch History & Recurring Popups Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Record every process start/stop via ETW so recurring short-lived console popups become identifiable, grouped, and drillable in a new Launch History TUI page — with command-line capture as a default-off, redacted, encrypted, short-retention opt-in.

**Architecture:** Extend the existing `Microsoft-Windows-Kernel-Process` ETW session in `etw.rs` with a TDH property parser and ProcessStop consumption; a `LaunchTracker` in the runtime loop resolves lineage at capture time and window state from the existing 2 s visibility sampler; events persist to a doubly-bounded `launch_events` table; command lines (opt-in only) flow through a separate MOF system-logger session → redaction → DPAPI → their own retention clock. Spec: `docs/superpowers/specs/2026-08-14-launch-history-design.md` — read it before starting any task.

**Tech Stack:** Rust, `windows` crate (ETW/TDH/DPAPI), rusqlite, serde, Ratatui TUI.

## Global Constraints

- Never terminate, suspend, or disable a process from anything built here. The Launch History page is read-only.
- Never collect file contents, keystrokes, environment variables, browser data, or Security event-log records — regardless of any setting.
- `captureCommandLines` defaults to **false**; absent field in an existing settings file must deserialize to false. With it off, no command-line data may enter the process in any form.
- Bounds (exact values): `LAUNCH_RETENTION_MS = 7 * 24 * 3600 * 1000`; `LAUNCH_ROW_CAP = 100_000`; ETW channel capacity 4096; lineage depth 5; recent-launch ring 4096; `commandLineRetentionHours` default 24, validated range 1–168; getLaunchGroups limit clamp 500; getLaunchOccurrences limit clamp 1000; cmdline join proximity ≤ 2000 ms.
- Verbatim UI copy (pin in tests, byte-exact):
  - Off-state sentence: `Command-line capture is off — PC Pulse can identify the executable and launcher, but not the exact command or script.`
  - Unobserved window: `window state unobserved — lived less than one sampling interval`
  - Dead-process drill-down note: `process has exited — showing recorded lineage`
- Malformed/dropped events are counted in health metrics, never panic, never stall the collector.
- Protocol JSON is camelCase, additive-only; follow existing `docs/protocol.md` naming.
- House rules: scope `cargo fmt` to your own hunks and `git restore` unrelated formatting churn; if the sandbox blocks `git restore`/`git checkout --`, revert hunks manually or report BLOCKED — never tunnel via `git show HEAD:file > file`. Commits have no co-author trailer.

---

### Task 1: TDH property decode core (`etw_props.rs`)

**Files:**
- Create: `src/PcPulse.Service/src/etw_props.rs`
- Modify: `src/PcPulse.Service/src/main.rs` (add `mod etw_props;`)
- Modify: `src/PcPulse.Service/Cargo.toml` (no new features needed here; TDH lives in the already-enabled `Win32_System_Diagnostics_Etw`)

**Interfaces:**
- Produces (used by Tasks 2, 4):

```rust
pub struct ProcessStartProps {
    pub pid: u32,
    pub parent_pid: u32,
    pub session_id: u32,
    pub create_time_ms: i64,   // ms since epoch, converted from FILETIME
    pub image_name: String,    // raw, usually a \Device\... path
}
pub struct ProcessStopProps { pub pid: u32, pub exit_code: u32 }
pub enum ParsedProcessEvent { Start(ProcessStartProps), Stop(ProcessStopProps) }
#[derive(Debug, PartialEq)]
pub enum ParseError { MissingProperty(&'static str), BadType(&'static str), Tdh(u32), UnknownEventId(u16) }

/// Pure, testable core: decode from an already-extracted property bag.
pub(crate) enum PropValue { U32(u32), U64(u64), FileTime(i64), Unicode(String) }
pub(crate) fn decode_event(event_id: u16, props: &[(String, PropValue)]) -> Result<ParsedProcessEvent, ParseError>;

/// Unsafe shell: EVENT_RECORD -> property bag via TdhGetEventInformation, then decode_event.
/// Called only from the ETW callback (Task 2).
pub unsafe fn parse_process_event(record: *const EVENT_RECORD) -> Result<ParsedProcessEvent, ParseError>;
```

Design rule: all logic lives in `decode_event` (pure, fixture-testable). The unsafe shell only walks `TRACE_EVENT_INFO` (`TdhGetEventInformation` with a grow-on-`ERROR_INSUFFICIENT_BUFFER` retry, buffer reused via a thread-local `Vec<u8>` since the callback runs on the dedicated `pcpulse-etw` thread), reads each top-level property's offset/length from `EVENT_PROPERTY_INFO` (`GetPropertyDataOffset` via `TdhGetPropertySize`/`TdhGetProperty` per property — use `TdhGetProperty` with a single `PROPERTY_DATA_DESCRIPTOR` per named property; simpler and length-safe), and maps `InType` → `PropValue`: `TDH_INTYPE_UINT32`→U32, `TDH_INTYPE_UINT64`→U64, `TDH_INTYPE_FILETIME`→FileTime (convert to epoch ms: `(ft - 116444736000000000) / 10_000`), `TDH_INTYPE_UNICODESTRING`→Unicode (NUL-trimmed). Unknown in-types for properties we don't need are skipped, not errors.

- [ ] **Step 1: Write failing tests for `decode_event`**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    fn start_bag() -> Vec<(String, PropValue)> {
        vec![
            ("ProcessID".into(), PropValue::U32(4242)),
            ("ParentProcessID".into(), PropValue::U32(1000)),
            ("SessionID".into(), PropValue::U32(1)),
            ("CreateTime".into(), PropValue::FileTime(1_786_600_000_000)),
            ("ImageName".into(), PropValue::Unicode(r"\Device\HarddiskVolume4\Windows\System32\cmd.exe".into())),
        ]
    }
    #[test]
    fn decodes_process_start() {
        let ParsedProcessEvent::Start(s) = decode_event(1, &start_bag()).unwrap() else { panic!("expected Start") };
        assert_eq!(s.pid, 4242);
        assert_eq!(s.parent_pid, 1000);
        assert_eq!(s.session_id, 1);
        assert_eq!(s.create_time_ms, 1_786_600_000_000);
        assert!(s.image_name.ends_with("cmd.exe"));
    }
    #[test]
    fn decodes_process_stop() {
        let bag = vec![("ProcessID".into(), PropValue::U32(4242)), ("ExitCode".into(), PropValue::U32(0))];
        let ParsedProcessEvent::Stop(s) = decode_event(2, &bag).unwrap() else { panic!("expected Stop") };
        assert_eq!(s.pid, 4242);
        assert_eq!(s.exit_code, 0);
    }
    #[test]
    fn missing_property_is_error_not_panic() {
        let mut bag = start_bag();
        bag.retain(|(k, _)| k != "ParentProcessID");
        assert_eq!(decode_event(1, &bag).unwrap_err(), ParseError::MissingProperty("ParentProcessID"));
    }
    #[test]
    fn wrong_type_is_error() {
        let mut bag = start_bag();
        bag.iter_mut().find(|(k, _)| k == "ProcessID").unwrap().1 = PropValue::Unicode("42".into());
        assert_eq!(decode_event(1, &bag).unwrap_err(), ParseError::BadType("ProcessID"));
    }
    #[test]
    fn unknown_event_id_is_error() {
        assert_eq!(decode_event(15, &start_bag()).unwrap_err(), ParseError::UnknownEventId(15));
    }
    #[test]
    fn sessionid_u64_widening_accepted() {
        // Some manifest versions emit UInt64 for SessionID; accept lossless widening.
        let mut bag = start_bag();
        bag.iter_mut().find(|(k, _)| k == "SessionID").unwrap().1 = PropValue::U64(1);
        assert!(decode_event(1, &bag).is_ok());
    }
}
```

- [ ] **Step 2: Run to verify failure** — `cargo test -p pcpulse-service etw_props` → FAIL (module/functions missing).
- [ ] **Step 3: Implement `decode_event` + the unsafe TDH shell** as specified in Interfaces. `decode_event` looks up properties by name with helper `fn get<'a>(props, name) -> Result<&'a PropValue, ParseError>`; U64→u32 conversions must be checked (`try_into` → `BadType` on overflow).
- [ ] **Step 4: Run tests** — `cargo test -p pcpulse-service etw_props` → PASS. `cargo build -p pcpulse-service` must compile the unsafe shell.
- [ ] **Step 5: Commit** — `git add -A src/PcPulse.Service && git commit -m "Add TDH property decode core for kernel process events"`

---

### Task 2: ETW session extension — stop events, channel, loss counters

**Files:**
- Modify: `src/PcPulse.Service/src/etw.rs`
- Test: inline `#[cfg(test)]` in `etw.rs`

**Interfaces:**
- Consumes: `etw_props::{parse_process_event, ParsedProcessEvent}` (Task 1).
- Produces (used by Tasks 4, 8):

```rust
pub struct EtwHealth {
    pub dropped_channel: AtomicU64,    // channel-full drops (wires the existing dead dropped_events hook)
    pub etw_events_lost: AtomicU64,    // from EVENT_TRACE_CONTROL_QUERY EventsLost
    pub malformed_events: AtomicU64,   // parse_process_event errors
}
/// Returned alongside the existing session handle plumbing:
pub fn take_process_events(&self) -> Vec<ParsedProcessEvent>;  // drains the bounded channel, called once per runtime tick
```

Implementation notes:
- The session already enables `PROCESS_KEYWORD 0x10`; ProcessStop (EventId 2) arrives on it today and is ignored — extend the existing callback's EventId match to feed both ids 1 and 2 through `parse_process_event`. Keep the existing 4-byte-PID fast path for the pressure `process_starts` map exactly as-is (it runs before/independent of the new parse).
- Bounded queue: `crossbeam_channel::bounded(4096)` if crossbeam is already a dependency; otherwise `std::sync::mpsc::sync_channel(4096)` with `try_send` — on `Full`, increment `dropped_channel` and drop the **new** event (simplest correct bound; spec's "drop oldest" is amended here to drop-newest because sync_channel cannot pop — record this as a deviation note for the reviewer, health counter semantics unchanged).
- Events-lost query: once per existing 1 s flush cycle, call `ControlTraceW(session, EVENT_TRACE_CONTROL_QUERY)` on a properly sized `EVENT_TRACE_PROPERTIES` buffer and store `EventsLost` into `etw_events_lost` (store the absolute value; consumers diff it).

- [ ] **Step 1: Write failing test for channel bounding**

```rust
#[test]
fn channel_full_increments_dropped_and_keeps_collector_alive() {
    let (h, tx) = EtwProcessQueue::new_for_test(4); // capacity-4 test constructor
    for i in 0..10 {
        tx.offer(ParsedProcessEvent::Stop(ProcessStopProps { pid: i, exit_code: 0 }));
    }
    assert_eq!(h.health().dropped_channel.load(Ordering::Relaxed), 6);
    assert_eq!(h.take_process_events().len(), 4);
    assert_eq!(h.take_process_events().len(), 0); // drained
}
```

(Structure the queue as a small `EtwProcessQueue { tx, rx, health }` type so the test never needs a real ETW session; the callback holds a clone of `tx` + `Arc<EtwHealth>`.)

- [ ] **Step 2: Run to verify failure** — `cargo test -p pcpulse-service etw::` → FAIL.
- [ ] **Step 3: Implement** `EtwProcessQueue`, wire `offer()` into the callback after `parse_process_event` (parse errors → `malformed_events += 1`, return), add the `EVENT_TRACE_CONTROL_QUERY` poll into the existing flush-timer path, and expose `EtwHealth` + `take_process_events` from the session struct that `runtime.rs` already holds.
- [ ] **Step 4: Run** — `cargo test -p pcpulse-service` → PASS; `cargo build` clean.
- [ ] **Step 5: Commit** — `git commit -am "Consume process stop events and bound the ETW launch queue with loss counters"`

---

### Task 3: Path normalization + console-host classification (`launches.rs`, pure half)

**Files:**
- Create: `src/PcPulse.Service/src/launches.rs` (this task adds only the pure helpers; Task 4 adds the tracker)
- Modify: `src/PcPulse.Service/src/main.rs` (add `mod launches;`)

**Interfaces:**
- Produces (used by Tasks 4, 8, 9):

```rust
/// Maps \Device\HarddiskVolumeN\... to c:\... using a supplied device map; lowercases.
/// Returns (normalized_or_original_lowercased, mapped: bool).
pub fn normalize_image_path(raw: &str, device_map: &[(String, String)]) -> (String, bool);
/// Live device map via QueryDosDeviceW over drive letters A:..Z:; cached by caller.
pub fn build_device_map() -> Vec<(String, String)>;  // e.g. ("\\device\\harddiskvolume4", "c:")
pub fn exe_name_from_path(path: &str) -> String;      // last component
pub fn is_console_host(exe_name: &str) -> bool;       // cmd/powershell/pwsh/conhost/wt/windowsterminal/openconsole (.exe, case-insensitive)
```

- [ ] **Step 1: Write failing tests**

```rust
#[test]
fn normalizes_device_path_and_flags_mapping() {
    let map = vec![(r"\device\harddiskvolume4".to_string(), "c:".to_string())];
    let (p, mapped) = normalize_image_path(r"\Device\HarddiskVolume4\Windows\System32\CMD.EXE", &map);
    assert_eq!(p, r"c:\windows\system32\cmd.exe");
    assert!(mapped);
}
#[test]
fn unmapped_device_path_preserved_lowercased_and_flagged() {
    let (p, mapped) = normalize_image_path(r"\Device\Mup\share\x.exe", &[]);
    assert_eq!(p, r"\device\mup\share\x.exe");
    assert!(!mapped);
}
#[test]
fn console_hosts_recognized_case_insensitively() {
    for n in ["cmd.exe", "PowerShell.exe", "pwsh.exe", "conhost.exe", "wt.exe", "WindowsTerminal.exe", "OpenConsole.exe"] {
        assert!(is_console_host(n), "{n}");
    }
    assert!(!is_console_host("notepad.exe"));
    assert!(!is_console_host("mycmd.exe")); // exact-name match only, no substring matching
}
#[test]
fn exe_name_is_last_component() {
    assert_eq!(exe_name_from_path(r"c:\windows\system32\cmd.exe"), "cmd.exe");
    assert_eq!(exe_name_from_path("cmd.exe"), "cmd.exe");
}
```

- [ ] **Step 2: Run to verify failure**, **Step 3: Implement** (longest-prefix match against the device map; `is_console_host` compares the full exe name against a `const` lowercase list), **Step 4: Run → PASS**, **Step 5: Commit** — `git commit -am "Add launch path normalization and console-host classification"`

---

### Task 4: LaunchTracker — lineage, stop matching, window state, flush

**Files:**
- Modify: `src/PcPulse.Service/src/launches.rs`
- Modify: `src/PcPulse.Service/src/models.rs` (add `LaunchEvent`, `WindowState`, `LineageEntry`, `LaunchCaptureStatus` — serde camelCase like the neighbors)

**Interfaces:**
- Consumes: `ParsedProcessEvent` (Task 1), pure helpers (Task 3).
- Produces (used by Tasks 5, 7, 8):

```rust
#[derive(Clone, Serialize, Deserialize)] #[serde(rename_all = "camelCase")]
pub struct LineageEntry { pub pid: u32, pub name: String, #[serde(skip_serializing_if = "Option::is_none")] pub path: Option<String> }

#[derive(Clone, Copy, PartialEq, Serialize, Deserialize)] #[serde(rename_all = "camelCase")]
pub enum WindowState { Windowed, NeverWindowed, Unobserved, Running }

#[derive(Clone, Serialize, Deserialize)] #[serde(rename_all = "camelCase")]
pub struct LaunchEvent {
    pub pid: u32, pub start_time_ms: i64,
    #[serde(skip_serializing_if = "Option::is_none")] pub stop_time_ms: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")] pub exit_code: Option<u32>,
    pub exe_name: String, pub exe_path: String,
    #[serde(skip_serializing_if = "Option::is_none")] pub raw_image_path: Option<String>, // only when !mapped
    pub session_id: u32, pub parent_pid: u32,
    pub lineage: Vec<LineageEntry>,      // depth ≤ 5; name "unknown" when unresolvable
    pub window_state: WindowState, pub console_host: bool,
    #[serde(skip_serializing_if = "Option::is_none")] pub command_line: Option<String>, // set only by Task 7 join
}

#[derive(Clone, Default, Serialize)] #[serde(rename_all = "camelCase")]
pub struct LaunchCaptureStatus {
    pub starts_seen: u64, pub stops_seen: u64, pub persisted: u64,
    pub dropped_channel: u64, pub etw_events_lost: u64, pub malformed_events: u64,
    pub orphan_stops: u64, pub cmdline_session_active: bool,
    pub cmdlines_captured: u64, pub cmdlines_redacted_fields: u64,
}

pub struct LaunchTracker { /* pending: HashMap<(u32, i64), PendingLaunch>, pid_index: HashMap<u32, i64>, recent: VecDeque<(u32, i64, String, String)>, device_map, status counters */ }
impl LaunchTracker {
    pub fn new() -> Self;
    /// live_lookup: pid -> Some((name, Some(path))) from the live process table.
    pub fn on_start(&mut self, p: ProcessStartProps, live_lookup: &dyn Fn(u32) -> Option<(String, Option<String>)>);
    pub fn on_stop(&mut self, p: ProcessStopProps, now_ms: i64);
    pub fn observe_window(&mut self, pid: u32, visible: bool);   // called from the 2 s visibility sweep for every sampled pid
    /// Completed launches + still-open ones ≥ 60 s old (emitted once as Running; finalized later by upsert).
    pub fn drain_flushable(&mut self, now_ms: i64) -> Vec<LaunchEvent>;
    pub fn status(&self) -> LaunchCaptureStatus;                  // etw fields merged in by runtime from EtwHealth
}
```

Semantics to implement exactly:
- `on_start`: normalize path (cached device map, rebuilt on a mapping failure once per call at most); lineage = walk parent chain up to depth 5 using, in order, `live_lookup(pid)`, then the tracker's `recent` ring (last 4096 `(pid, start_ms, name, path)`), else `LineageEntry { pid, name: "unknown".into(), path: None }` and stop the walk. Push self into `recent`. `pid_index` maps pid → latest start_time_ms (PID reuse: a new start for a live pid overwrites the index but the old pending row keeps its own `(pid, old_start)` key and is closed as `stop unmatched` → flushed as Running/no-stop).
- `on_stop`: match via `pid_index`; found → set stop/exit/duration, resolve `WindowState` (`Windowed` if ever visible, `NeverWindowed` if sampled-but-never-visible, `Unobserved` if never sampled), move to the completed buffer, clear index entry. Not found → `orphan_stops += 1`, no fabricated row.
- `observe_window(pid, visible)`: mark `sampled = true` and `visible |= visible` on the pending launch for that pid (via `pid_index`), if any.
- `drain_flushable`: completed rows drain fully; pending rows older than 60 s emit a snapshot with `window_state: Running`, `stop_time_ms: None`, and stay pending (idempotent upsert finalizes them on stop).

- [ ] **Step 1: Write failing tests** — the spec's marquee cases:

```rust
fn start(pid: u32, ppid: u32, t: i64, img: &str) -> ProcessStartProps { /* helper */ }
fn no_live(_: u32) -> Option<(String, Option<String>)> { None }

#[test]
fn sub_two_second_lifecycle_recorded_as_unobserved() {
    let mut tr = LaunchTracker::new();
    tr.on_start(start(500, 4, 1_000, r"\Device\HarddiskVolume4\x\popup.exe"), &no_live);
    tr.on_stop(ProcessStopProps { pid: 500, exit_code: 1 }, 1_300);
    let ev = &tr.drain_flushable(2_000)[0];
    assert_eq!(ev.stop_time_ms, Some(1_300));
    assert_eq!(ev.exit_code, Some(1));
    assert_eq!(ev.window_state, WindowState::Unobserved);
}
#[test]
fn pid_reuse_produces_distinct_rows_with_correct_stop_matching() {
    let mut tr = LaunchTracker::new();
    tr.on_start(start(500, 4, 1_000, r"c:\a.exe"), &no_live);
    tr.on_stop(ProcessStopProps { pid: 500, exit_code: 0 }, 2_000);
    tr.on_start(start(500, 4, 3_000, r"c:\b.exe"), &no_live);
    tr.on_stop(ProcessStopProps { pid: 500, exit_code: 7 }, 4_000);
    let evs = tr.drain_flushable(5_000);
    assert_eq!(evs.len(), 2);
    assert!(evs.iter().any(|e| e.start_time_ms == 1_000 && e.exit_code == Some(0)));
    assert!(evs.iter().any(|e| e.start_time_ms == 3_000 && e.exit_code == Some(7)));
}
#[test]
fn lineage_prefers_live_then_recent_then_unknown() {
    let mut tr = LaunchTracker::new();
    tr.on_start(start(100, 1, 500, r"c:\parent.exe"), &no_live);       // parent known via recent ring
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
    let mut tr = LaunchTracker::new();
    tr.on_stop(ProcessStopProps { pid: 999, exit_code: 0 }, 1_000);
    assert!(tr.drain_flushable(2_000).is_empty());
    assert_eq!(tr.status().orphan_stops, 1);
}
#[test]
fn window_states_windowed_and_never_windowed() {
    let mut tr = LaunchTracker::new();
    tr.on_start(start(1, 4, 0, r"c:\w.exe"), &no_live);
    tr.on_start(start(2, 4, 0, r"c:\bg.exe"), &no_live);
    tr.observe_window(1, true);
    tr.observe_window(2, false);
    tr.on_stop(ProcessStopProps { pid: 1, exit_code: 0 }, 5_000);
    tr.on_stop(ProcessStopProps { pid: 2, exit_code: 0 }, 5_000);
    let evs = tr.drain_flushable(6_000);
    assert_eq!(evs.iter().find(|e| e.pid == 1).unwrap().window_state, WindowState::Windowed);
    assert_eq!(evs.iter().find(|e| e.pid == 2).unwrap().window_state, WindowState::NeverWindowed);
}
#[test]
fn long_running_launch_flushes_as_running_and_stays_pending() {
    let mut tr = LaunchTracker::new();
    tr.on_start(start(1, 4, 0, r"c:\long.exe"), &no_live);
    let first = tr.drain_flushable(61_000);
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].window_state, WindowState::Running);
    tr.on_stop(ProcessStopProps { pid: 1, exit_code: 0 }, 90_000);
    let second = tr.drain_flushable(91_000);
    assert_eq!(second[0].stop_time_ms, Some(90_000)); // same (pid,start) key → upsert finalizes
}
#[test]
fn rapid_repeated_launches_all_recorded() {
    let mut tr = LaunchTracker::new();
    for i in 0..50 {
        tr.on_start(start(1000 + i, 4, i as i64 * 10, r"c:\spam.exe"), &no_live);
        tr.on_stop(ProcessStopProps { pid: 1000 + i, exit_code: 0 }, i as i64 * 10 + 5);
    }
    assert_eq!(tr.drain_flushable(10_000).len(), 50);
    assert_eq!(tr.status().starts_seen, 50);
}
```

- [ ] **Step 2: Run to verify failure** — `cargo test -p pcpulse-service launches::` → FAIL.
- [ ] **Step 3: Implement `LaunchTracker`** per Semantics above.
- [ ] **Step 4: Run → PASS** (`cargo test -p pcpulse-service`).
- [ ] **Step 5: Commit** — `git commit -am "Add LaunchTracker with capture-time lineage and honest window states"`

---

### Task 5: Storage — launch_events + launch_cmdlines, retention, caps

**Files:**
- Modify: `src/PcPulse.Service/src/storage.rs`
- Test: inline `#[cfg(test)]` (in-memory rusqlite, house pattern)

**Interfaces:**
- Consumes: `LaunchEvent` (Task 4).
- Produces (used by Tasks 7, 8):

```rust
pub const LAUNCH_RETENTION_MS: i64 = 7 * 24 * 3600 * 1000;
pub const LAUNCH_ROW_CAP: usize = 100_000;
pub fn save_launch_events(conn: &Connection, events: &[LaunchEvent]) -> Result<()>;   // INSERT OR REPLACE, then cap-evict oldest
pub fn load_launch_events(conn: &Connection, from_ms: i64) -> Result<Vec<LaunchEvent>>;
pub fn prune_launch_events(conn: &Connection, now_ms: i64) -> Result<usize>;          // retention window
pub fn save_cmdline(conn: &Connection, pid: u32, start_time_ms: i64, captured_at_ms: i64, blob: &[u8]) -> Result<()>;
pub fn load_cmdline(conn: &Connection, pid: u32, start_time_ms: i64) -> Result<Option<Vec<u8>>>;
pub fn prune_cmdlines(conn: &Connection, cutoff_ms: i64) -> Result<usize>;            // captured_at_ms < cutoff
pub fn delete_all_cmdlines(conn: &Connection) -> Result<usize>;
```

Schema exactly as in the spec (`WITHOUT ROWID`, PK `(pid, start_time_ms)`, `idx_launch_events_start` on `start_time_ms DESC`; `launch_cmdlines` likewise plus `captured_at_ms`). Add `CREATE TABLE IF NOT EXISTS` to the existing schema-init function; wire `prune_launch_events` into the existing daily prune job and `prune_cmdlines` into the hourly path Task 7 adds (for now export it; Task 7 calls it).

- [ ] **Step 1: Write failing tests** — round-trip; upsert finalization (save Running row, save again with stop → one row, stop set); retention prune (rows older than 7 d gone, newer stay); row-cap eviction (insert `LAUNCH_ROW_CAP + 10` synthetic rows via a small-cap test hook `save_launch_events_with_cap(conn, evs, cap)` so the test doesn't need 100k inserts — assert oldest evicted, newest kept, count == cap); cmdline save/load/prune/delete-all (delete returns count). Follow the ratings tests as the template.
- [ ] **Step 2: Run to verify failure.**
- [ ] **Step 3: Implement** (payload JSON via serde like every neighbor table; cap eviction: `DELETE FROM launch_events WHERE (pid, start_time_ms) IN (SELECT pid, start_time_ms FROM launch_events ORDER BY start_time_ms ASC LIMIT excess)`).
- [ ] **Step 4: Run → PASS.**
- [ ] **Step 5: Commit** — `git commit -am "Persist launch events with retention, row cap, and cmdline table"`

---

### Task 6: Redaction + DPAPI (`redact.rs`, `dpapi.rs`)

**Files:**
- Create: `src/PcPulse.Service/src/redact.rs`, `src/PcPulse.Service/src/dpapi.rs`
- Modify: `src/PcPulse.Service/src/main.rs` (mods), `src/PcPulse.Service/Cargo.toml` (add `Win32_Security_Cryptography` to the windows-crate features)

**Interfaces:**
- Produces (used by Task 7):

```rust
/// Returns (redacted string, number of fields redacted). Irreversible.
pub fn redact_command_line(input: &str) -> (String, u32);
pub fn protect(data: &[u8]) -> Result<Vec<u8>, u32>;    // CryptProtectData, CRYPTPROTECT_LOCAL_MACHINE
pub fn unprotect(blob: &[u8]) -> Result<Vec<u8>, u32>;  // CryptUnprotectData
```

Redaction rules (each its own pass, all case-insensitive, replacement token `‹redacted›`):
1. Credential vocabulary `password|passwd|pwd|secret|token|apikey|api-key|auth|credential|bearer|cookie|session` as: `key=value`, `key:value`, `--key value`, `--key=value`, `/key:value` → value replaced.
2. Long opaque runs: base64-ish `[A-Za-z0-9+/=_-]{20,}` or hex `[0-9a-fA-F]{20,}` **only when** the token is not a path (contains no `\` or `/`) — replaced whole.
3. URL userinfo `scheme://user:pass@` → `scheme://‹redacted›@`; URL query values whose key matches the vocabulary.
4. Connection-string fragments `(Password|Pwd|User Id|Uid)\s*=\s*[^;]+` → value replaced.

- [ ] **Step 1: Write failing tests**

```rust
#[test] fn redacts_password_flag_forms() {
    for s in ["app --password hunter2", "app --password=hunter2", "app /password:hunter2", "app password=hunter2"] {
        let (r, n) = redact_command_line(s);
        assert!(!r.contains("hunter2"), "{s} -> {r}");
        assert_eq!(n, 1);
    }
}
#[test] fn redacts_long_opaque_tokens_but_not_paths() {
    let (r, n) = redact_command_line(r"tool eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 c:\some\deadbeefdeadbeefdeadbeef\file.txt");
    assert!(!r.contains("eyJhbGci"));
    assert!(r.contains(r"c:\some\deadbeefdeadbeefdeadbeef\file.txt")); // path exempt
    assert_eq!(n, 1);
}
#[test] fn redacts_url_userinfo_and_secret_query_values() {
    let (r, _) = redact_command_line("curl https://bob:pw@x.io/a?token=abc123def456abc123def456&page=2");
    assert!(!r.contains("bob:pw") && !r.contains("abc123def456"));
    assert!(r.contains("page=2"));
}
#[test] fn redacts_connection_strings() {
    let (r, _) = redact_command_line(r#"app "Server=x;User Id=sa;Password=s3cret;""#);
    assert!(!r.contains("s3cret"));
    assert!(r.contains("Server=x"));
}
#[test] fn non_secrets_untouched() {
    let s = r"cmd.exe /c echo hello & ping -n 4 localhost";
    assert_eq!(redact_command_line(s), (s.to_string(), 0));
}
#[test] fn dpapi_round_trip() {
    let blob = protect(b"redacted line").unwrap();
    assert_ne!(blob.as_slice(), b"redacted line");
    assert_eq!(unprotect(&blob).unwrap(), b"redacted line");
}
```

- [ ] **Step 2: Run to verify failure**, **Step 3: Implement** (redaction via the `regex` crate if already a dependency, else hand-rolled scanners — check `Cargo.toml` first and follow what exists), **Step 4: Run → PASS**, **Step 5: Commit** — `git commit -am "Add command-line redaction and DPAPI at-rest encryption"`

---

### Task 7: Settings, opt-in MOF cmdline session, runtime wiring

**Files:**
- Modify: `src/PcPulse.Service/src/config.rs` (settings + validation)
- Modify: `src/PcPulse.Service/src/etw.rs` (MOF system-logger session, start/stop on toggle)
- Modify: `src/PcPulse.Service/src/runtime.rs` (tick wiring: drain queue → tracker → join cmdlines → save; hourly cmdline prune; snapshot fields)
- Modify: `src/PcPulse.Service/src/launches.rs` (`CmdlineJoiner`)

**Interfaces:**
- Consumes: everything above.
- Produces (used by Tasks 8, 9):

```rust
// config.rs (serde camelCase, defaults via #[serde(default)]):
pub capture_command_lines: bool,          // default false
pub command_line_retention_hours: u32,    // default 24; validate 1..=168 (bail! style)

// launches.rs:
pub struct CmdlineJoiner { /* VecDeque<(pid, start_ms, redacted_line, redacted_fields)> cap 4096 */ }
impl CmdlineJoiner {
    pub fn offer(&mut self, pid: u32, event_start_ms: i64, raw_line: &str);  // redacts on entry; raw dropped immediately
    pub fn attach(&mut self, ev: &mut LaunchEvent) -> Option<(String, u32)>; // |start_ms delta| <= 2000, removes entry
}
```

Runtime tick order (insert after the existing baseline-publish step): drain `take_process_events` → `tracker.on_start/on_stop` (live_lookup = existing process table) → visibility sweep already calls `tracker.observe_window` (add the call where windows are enumerated) → `drain_flushable(now)` → for each event `joiner.attach` (only when opt-in active) → `save_launch_events` → on attach also `save_cmdline(protect(line))`. Hourly: `prune_cmdlines(now - hours*3600_000)`. Toggle handling: when `capture_command_lines` flips on → start the MOF session (`EVENT_TRACE_FLAG_PROCESS` system-logger, fail-soft: log + `cmdline_session_active = false` if the 8-slot pool is exhausted); flips off → stop session and clear the joiner. Snapshot gains `launchCapture: LaunchCaptureStatus` (merge `EtwHealth` counters in).

- [ ] **Step 1: Write failing tests** — settings: absent fields deserialize to `(false, 24)` (opt-in migration test: deserialize a pre-1.20 settings JSON fixture without the fields); `command_line_retention_hours: 0` and `169` fail validation, `1` and `168` pass. Joiner: offer+attach within 2 s matches and removes; 2.5 s apart does not; raw secrets never stored (offer `--password x`, assert stored line lacks `x`); attach when empty → None; cap eviction at 4096.
- [ ] **Step 2: Run to verify failure.**
- [ ] **Step 3: Implement.** The MOF session start/stop is thin ETW plumbing following the existing session-creation code in `etw.rs`; its callback extracts `CommandLine` + `ProcessId` + parsed create-time from the classic `Process_TypeGroup1` MOF layout (MOF events have fixed offsets per pointer size — parse defensively, malformed → counter) and calls `joiner.offer` through the same bounded-channel pattern as Task 2.
- [ ] **Step 4: Run → PASS** (`cargo test -p pcpulse-service`).
- [ ] **Step 5: Commit** — `git commit -am "Wire launch capture into the runtime with opt-in command-line session"`

---

### Task 8: Grouping + pipe protocol + protocol docs

**Files:**
- Modify: `src/PcPulse.Service/src/launches.rs` (grouping, pure)
- Modify: `src/PcPulse.Service/src/runtime.rs` (command handlers), `src/PcPulse.Service/src/models.rs` (request/response types)
- Modify: `docs/protocol.md`

**Interfaces:**
- Consumes: `load_launch_events`, `load_cmdline`+`unprotect`, `delete_all_cmdlines`, `LaunchEvent`.
- Produces (used by Task 9):

```rust
#[derive(Clone, Serialize)] #[serde(rename_all = "camelCase")]
pub struct LaunchGroup {
    pub exe_name: String, pub exe_path: String,
    pub lineage_sig: String,          // "<" -joined lowercase lineage names, e.g. "cmd.exe<explorer.exe"
    pub launcher_summary: String,     // first lineage entry name or "unknown"
    pub count: usize, pub first_ms: i64, pub last_ms: i64,
    pub median_interval_ms: Option<i64>,   // None when count < 2
    pub mean_duration_ms: Option<i64>, pub max_duration_ms: Option<i64>, // None when no completed occurrence
    pub windowed: usize, pub never_windowed: usize, pub unobserved: usize, pub running: usize,
    pub console_host: bool,
}
pub fn group_launches(events: &[LaunchEvent], console_hosts_only: bool, limit: usize) -> Vec<LaunchGroup>;
// Sort: count within trailing 24 h of the newest event desc, then last_ms desc. Key: (exe_path, lineage_sig).
```

Pipe commands (camelCase, existing dispatch pattern in `runtime.rs`):
- `getLaunchGroups { fromMs?: i64, consoleHostsOnly?: bool, limit?: usize }` → `{ groups: [LaunchGroup] }`, limit clamped to 500, fromMs default now−7 d.
- `getLaunchOccurrences { exePath: String, lineageSig: String, fromMs?: i64, limit?: usize }` → `{ events: [LaunchEvent] }` newest-first, limit clamped to 1000; `command_line` populated by `load_cmdline`+`unprotect` per event when present (decrypt per-request, never cached).
- `deleteCommandLines {}` → `{ deleted: usize }`.

- [ ] **Step 1: Write failing tests for `group_launches`** — grouping key separates same exe under different launchers; median interval over starts `[0, 10_000, 25_000]` == 12_500; count<2 → `median_interval_ms: None`; duration stats ignore running rows; window-state histogram sums to count; console filter keeps only console-host groups; limit truncates after sort; 24 h-count sort ordering (an old-heavy group sorts below a recent-active one). Session separation: two occurrences with different `session_id` stay in one group but both appear in occurrences (assert grouping does not key on session).
- [ ] **Step 2: Run to verify failure**, **Step 3: Implement grouping + the three handlers** (byte-check protocol names against `docs/protocol.md` additions you write in this task — document all three commands with example JSON marked illustrative, plus the `launchCapture` snapshot block), **Step 4: Run → PASS**, **Step 5: Commit** — `git commit -am "Add launch grouping, pipe commands, and protocol docs"`

---

### Task 9: TUI — Launch History page

**Files:**
- Modify: `src/PcPulse.Tui/src/app.rs` (Page variant, key routing, state, data fetch)
- Modify: `src/PcPulse.Tui/src/ui.rs` (masthead, render arm, tables)
- Modify: `src/PcPulse.Tui/src/client.rs` (three new requests)
- Modify: `src/PcPulse.Tui/src/prefs.rs` (persist page + filter if pages are persisted today — follow the existing pattern)

**Interfaces:**
- Consumes: `LaunchGroup`, `LaunchEvent`, `LaunchCaptureStatus` (mirror the serde structs client-side per house pattern).
- Produces: `Page::Launches` (digit `'9'`, masthead label `LAUNCHES`).

Follow the existing ~7-site new-page checklist (find every `match` over `Page` — key routing, page cycle order, masthead labels, render dispatch, mouse map, help text, prefs). Behavior:
- Groups table columns: exe name, launcher summary, count, last seen (relative), median interval, mean duration, window glyph (`▣` any windowed / `▢` never-windowed majority / `?` unobserved majority), `[console]` tag.
- `c` toggles console-hosts-only (re-fetch with `consoleHostsOnly: true`); footer shows `filter: console hosts` when active.
- Selection + detail pane: per-occurrence rows (start, stop or `running`, duration, exit code, session, lineage chain). Command line shown when present; when capture is off show the verbatim off-state sentence from Global Constraints. Unobserved occurrences render the verbatim unobserved sentence.
- `Enter`/`h` → if the selected occurrence's `(pid, start_time_ms)` matches a live process in the current snapshot, switch to the Processes page with that pid selected; `l` → same for the Tree page. Otherwise stay and show the verbatim dead-process note above the inline lineage.
- Footer: `LaunchCaptureStatus` summary; any nonzero `dropped_channel + etw_events_lost + malformed_events` renders `capture incomplete (N lost)`.
- No action on this page may kill/suspend/modify anything.

- [ ] **Step 1: Write failing tests** (existing TUI test harness style): page registration sweep (cycling pages hits `Launches`; digit `9` routes; masthead renders `LAUNCHES`); render of a fixture group list shows counts and the `[console]` tag; `c` toggle flips the fetch flag; verbatim strings pinned byte-exact (off-state sentence, unobserved sentence, dead-process note); jump-when-alive selects the pid on Processes; jump-when-dead does not switch pages.
- [ ] **Step 2: Run to verify failure** — `cargo test -p pcpulse-tui` → FAIL.
- [ ] **Step 3: Implement** across the checklist sites; use `format!("v{}", env!("CARGO_PKG_VERSION"))`-style dynamic strings where version appears (house rule from the 1.18.1 breakage).
- [ ] **Step 4: Run → PASS** (`cargo test -p pcpulse-tui`).
- [ ] **Step 5: Commit** — `git commit -am "Add Launch History page with recurrence groups and drill-down"`

---

### Task 10: TUNE opt-in surface, docs, version bump, verification

**Files:**
- Modify: `src/PcPulse.Tui/src/app.rs` + `ui.rs` (TUNE rows: capture toggle, retention hours, delete-now action)
- Modify: `docs/protocol.md` (settings fields), `README.md`/feature docs (follow where ratings were documented)
- Modify: both `Cargo.toml` versions → `1.20.0`

**Interfaces:**
- Consumes: settings fields (Task 7), `deleteCommandLines` (Task 8).

Behavior:
- TUNE gains: `Command-line capture` (on/off; description carries the disclosure verbatim from the spec: `Command lines can contain credentials, tokens, and personal paths. Captured lines are redacted, encrypted at rest, kept N hours, and deletable at any time. Off: PC Pulse identifies the executable and launcher, but not the exact command or script.`), `Cmdline retention (hours)` (1–168 stepper), `Delete captured command lines` (action row → `deleteCommandLines`, result count shown in status line).
- Docs: Launch History section (what is captured always, what only under opt-in, both retention clocks, the limitations section from the spec verbatim or summarized faithfully).

- [ ] **Step 1: Write failing tests** — TUNE rows render with the verbatim disclosure; retention stepper clamps at 1 and 168; delete action issues the command (harness-mock) and surfaces the count.
- [ ] **Step 2: Run to verify failure**, **Step 3: Implement + write docs + bump versions**, **Step 4: Full verification** — `cargo test --workspace` all green, `cargo build --release` clean.
- [ ] **Step 5: Commit** — `git commit -am "Add command-line capture controls, docs, and bump to 1.20.0"`
