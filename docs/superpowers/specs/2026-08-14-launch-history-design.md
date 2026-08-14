# Launch History & Recurring Popups — Design

Date: 2026-08-14
Status: Approved design, pre-implementation
Target release: v1.20.0

## Problem

Short-lived processes are invisible to PC Pulse today because they must survive a
triple filter: the 2-second toolhelp snapshot cadence, the top-64 pressure ranking,
and the 30-second persistence write cadence. A console window that flashes for 300 ms
— the classic "what keeps popping up?" complaint — never appears in any view or table.
Meanwhile the existing ETW session (`Microsoft-Windows-Kernel-Process`, start events
only) already receives the launch events and discards everything except the first
4 bytes of the payload (the PID).

## Goals

- Record **every** process start and stop continuously — no pressure ranking, no
  sampling cadence — with executable name, normalized path, PID, parent PID, start
  time, stop time, session ID, window classification, and captured lineage.
- A **Launch History** page that groups repeated launches by executable path and
  launcher lineage: frequency, timestamps, durations, recurrence intervals.
- Console-host filters (cmd, powershell, pwsh, conhost, Windows Terminal/OpenConsole)
  without treating console processes as suspicious.
- HUNT/LINEAGE drill-down per occurrence.
- Command-line capture as a **separate, explicit, default-off opt-in** with
  disclosure, redaction, encryption at rest, short retention, and immediate deletion.
- Bounded collection: dedup, storage limits, retention cleanup, health metrics.
- The UI states uncertainty explicitly and never terminates or disables anything.

## Non-goals

- No file contents, keystrokes, environment variables, browser data, or Security
  event-log records — never, regardless of opt-in state.
- No process termination, suspension, or "block this launcher" actions.
- No kernel driver, no image-load/DLL telemetry, no network attribution.

## Architecture

### 1. Capture layer (`etw.rs` + new `etw_props.rs`)

The existing manifest session is extended in place:

- **TDH property parsing** (new module `etw_props.rs`): a schema-driven parser using
  `TdhGetEventInformation` extracts named properties instead of raw offsets. From
  **ProcessStart (EventId 1)**: `ProcessID`, `ParentProcessID`, `SessionID`,
  `CreateTime`, `ImageName`. From **ProcessStop (EventId 2)** (same
  `PROCESS_KEYWORD 0x10`, currently ignored): `ProcessID`, `ExitCode`. Any event
  whose properties fail to parse increments a `malformed_events` counter and is
  dropped — never a panic, never a collector stall. The existing 4-byte PID fast
  path for the pressure-tracking `process_starts` map is preserved unchanged.
- **Event routing**: parsed starts/stops are pushed to a bounded crossbeam channel
  (capacity 4096) drained by the runtime loop each tick. Channel overflow increments
  `dropped_events` (finally wiring the existing dead `AtomicU64` hook) and drops the
  oldest — capture degrades measurably, never unboundedly.
- **Real ETW loss**: `ControlTraceW(EVENT_TRACE_CONTROL_QUERY)` per flush interval
  reads `EventsLost` from the session properties and folds it into health metrics.

`ImageName` arrives as a device path (`\Device\HarddiskVolume4\...`). Normalization
maps device prefixes to drive letters via `QueryDosDeviceW` (cached, refreshed on
failure) and lowercases for grouping; the original device path is preserved in the
payload for honesty when mapping fails.

### 2. Launch-event assembly (new `launches.rs`)

The runtime loop owns a `LaunchTracker`:

- **Start event** → a `PendingLaunch` keyed `(pid, start_time_ms)` — the PID-reuse-proof
  identity used everywhere downstream.
- **Lineage resolved at capture time**, before the parent can exit: parent name/path
  from (a) the live process table if the parent is running, (b) the tracker's own
  recent launches (ring of the last 4096), (c) otherwise `unknown`. The chain walks
  up to 5 ancestors and stores `[{pid, name, path?}]`. Because ETW buffers flush on
  a ~1 s timer, a parent can die inside that window; lineage is then whatever the
  event itself carried (parent PID) plus `unknown` names — recorded as-is, never
  guessed.
- **Session ID** from the event property (no per-launch `ProcessIdToSessionId` race).
- **Stop event** → closes the pending launch (stop time, exit code, duration). A stop
  with no matching start (collector started mid-life) is counted, not fabricated into
  a row.
- **Window classification**, three honest states fed by the existing 2 s visibility
  sampler: `windowed` (observed with a visible window in ≥1 sample),
  `never_windowed` (present in ≥1 sample, never visible), `unobserved` (lived and
  died between samples — the popups themselves). Console-host tagging by normalized
  exe name: `cmd.exe`, `powershell.exe`, `pwsh.exe`, `conhost.exe`,
  `wt.exe`/`windowsterminal.exe`, `openconsole.exe`.
- **Flush**: completed launches (and still-open launches older than 60 s, marked
  `running`) are written to storage every tick batch — not on shutdown, so a collector
  crash loses at most the in-flight batch (restart-recovery guarantee).

### 3. Storage (`storage.rs`)

New table in the house style:

```sql
CREATE TABLE IF NOT EXISTS launch_events (
    pid INTEGER NOT NULL,
    start_time_ms INTEGER NOT NULL,
    payload TEXT NOT NULL,          -- JSON LaunchEvent
    PRIMARY KEY (pid, start_time_ms)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_launch_events_start
    ON launch_events (start_time_ms DESC);
```

Writes are `INSERT OR REPLACE` (a `running` row is later finalized with its stop
time; the `(pid, start_time_ms)` key makes the update idempotent and PID-reuse-safe).
Bounded twice, never rank-filtered:

- **Retention**: 7 days (`LAUNCH_RETENTION_MS`), pruned by the existing daily job.
- **Hard cap**: 100 000 rows (`LAUNCH_ROW_CAP`), oldest-first eviction on insert
  batch, ratings-style.

Payload (`LaunchEvent`, camelCase): `pid`, `startTimeMs`, `stopTimeMs?`, `exitCode?`,
`exeName`, `exePath` (normalized), `rawImagePath?` (only when normalization failed),
`sessionId`, `parentPid`, `lineage: [{pid, name, path?}]`, `windowState`
(`windowed|neverWindowed|unobserved|running`), `consoleHost: bool`.

### 4. Command-line capture (opt-in) — privacy design

**Off means the data never enters the process.** The manifest Kernel-Process provider
carries no command line, so with the setting off there is nothing to redact, encrypt,
or delete — command lines are never received in any form.

Opting in starts a **second, dedicated system-logger session** with
`EVENT_TRACE_FLAG_PROCESS`: classic MOF process events carry `CommandLine` in the
event payload itself, so even sub-second processes get their command line without a
post-hoc `OpenProcess` race. Events are joined to launch events by
`(pid, start-time proximity ≤ 2 s)`. The session is started/stopped live when the
setting flips (no service restart).

Pipeline, strictly in order, before anything persists:

1. **Redaction** (`redact.rs`): replace with `‹redacted›` — long base64/hex runs
   (≥20 chars), `key=value` and `--flag value` pairs whose key matches a credential
   vocabulary (`password|passwd|pwd|secret|token|apikey|api-key|auth|credential|
   bearer|cookie|session`), URL userinfo and query values for the same vocabulary,
   and connection-string credential fields. Case-insensitive. Redaction is
   irreversible — the original is dropped.
2. **Encryption at rest**: `CryptProtectData` (DPAPI, machine scope — the service
   runs as LocalSystem), new `Win32_Security_Cryptography` cargo feature. Ciphertext
   stored in a separate table:

```sql
CREATE TABLE IF NOT EXISTS launch_cmdlines (
    pid INTEGER NOT NULL,
    start_time_ms INTEGER NOT NULL,
    captured_at_ms INTEGER NOT NULL,
    blob BLOB NOT NULL,             -- DPAPI(redacted UTF-8 command line)
    PRIMARY KEY (pid, start_time_ms)
) WITHOUT ROWID;
```

3. **Retention**: its own clock — `commandLineRetentionHours`, default 24,
   validated 1–168 — pruned hourly, independent of the 7-day launch-event window.
4. **Deletion**: `DeleteCommandLines` pipe command wipes the table immediately and
   returns the deleted count. Exposed in the TUI next to the toggle.
5. **Access**: the database lives under the existing service-owned ProgramData ACL;
   decryption happens only in the service, per-request, never cached.

Settings (`config.rs`, `Settings::validate` bail-style):
`captureCommandLines: bool` (default **false**; absent-field migration = false) and
`commandLineRetentionHours: u32` (default 24, range 1–168). The TUNE row description
carries the disclosure verbatim: *"Command lines can contain credentials, tokens,
and personal paths. Captured lines are redacted, encrypted at rest, kept N hours,
and deletable at any time. Off: PC Pulse identifies the executable and launcher,
but not the exact command or script."*

Never collected regardless of this setting: file contents, keystrokes, environment
variables, browser data, Security event-log records.

### 5. Health metrics

`LaunchCaptureStatus` (DiagnosticLogStatus template), in the snapshot and on the
Launch History page footer: `startsSeen`, `stopsSeen`, `persisted`,
`droppedChannel`, `etwEventsLost`, `malformedEvents`, `orphanStops`,
`cmdlineSessionActive`, `cmdlinesCaptured`, `cmdlinesRedactedFields`. Nonzero loss
counters render as an explicit "capture incomplete" note — dropped events are
visible, not silent.

### 6. Pipe protocol (`docs/protocol.md`)

- `getLaunchGroups { fromMs?, consoleHostsOnly?, limit? }` → server-side grouping by
  `(exePath, lineage-path signature)`: count, firstMs, lastMs, medianIntervalMs,
  meanDurationMs, maxDurationMs, windowStates histogram, consoleHost, exeName,
  launcher summary. Limit clamped to 500 groups.
- `getLaunchOccurrences { exePath, lineageSig, fromMs?, limit? }` → individual
  events, newest first, limit clamped to 1000; includes decrypted command line only
  when captured and present.
- `deleteCommandLines {}` → `{ deleted: n }`.

### 7. TUI — Launch History page

Tenth `Page` variant, digit `9`, masthead label **LAUNCHES**, following the existing
~7-site new-page checklist (key routing, help, page cycle, masthead, render arm,
mouse map, prefs persistence).

- **Groups table** (default sort: launch count within the last 24 h descending,
  ties by last-seen descending — so frequently recurring launches float up while
  stale groups sink): exe name, launcher (compact lineage
  tail), count, last seen, median interval, duration, window-state glyph
  (`▣ windowed · ▢ background · ? unobserved`), console tag.
- **`c` filter**: console hosts only — labeled "filter: console hosts", explicitly a
  filter, not a verdict.
- **Detail pane** (selected group): per-occurrence list — start/stop timestamps,
  duration, exit code, session ID, full recorded lineage, command line (when
  captured; otherwise the exact sentence *"Command-line capture is off — PC Pulse
  can identify the executable and launcher, but not the exact command or script."*).
- **Uncertainty wording**: unobserved windows render as *"window state unobserved —
  lived less than one sampling interval"*; unknown lineage as *"parent exited before
  capture (pid N)"*.
- **HUNT/LINEAGE jumps**: `Enter`/`h` selects the live process on the Processes
  (HUNT) page and `l` on the Tree (LINEAGE) page **when the pid+start-time identity
  is still alive**; otherwise the recorded lineage renders inline (the normal case
  for popups) with a "process has exited — showing recorded lineage" note.
- The page is read-only: no kill, no disable, no suspend.

## Testing

Unit: TDH parse of captured fixture buffers + malformed-payload fuzz (health counters
asserted); device-path normalization incl. mapping failure; sub-2-second lifecycle
(start+stop same batch); PID reuse (two launches, same PID, distinct start times —
distinct rows, correct stop matching); missing/exited parents (lineage `unknown`,
never guessed); rapid repeated launches (dedup key + grouping intervals); session
separation (grouping keeps sessions distinct in occurrences); redaction vocabulary
(each class, plus non-secrets untouched); opt-in migration (absent field → false;
retention bounds validated); both retention clocks + row-cap eviction; restart
recovery (rows persisted per batch, `running` finalization, orphan stops counted);
DPAPI round-trip; delete-command-lines wipes and counts.

TUI: page registration sweep (all ~7 sites), group table rendering with each
window-state, filter toggle, uncertainty strings pinned verbatim, jump-when-alive vs
inline-lineage-when-dead.

## Limitations (stated, not hidden)

- ETW flush batching (~1 s) means the fastest parent chains may outlive their
  recorder; lineage is then partial and says so.
- Window state for sub-cadence processes is fundamentally unobservable with the 2 s
  sampler; `unobserved` is the honest answer, not a defect.
- Command-line capture, when off, cannot be reconstructed retroactively — enabling
  it applies only to future launches.
- System-logger sessions come from a shared pool of 8 per machine; the opt-in
  session fails soft (health metric + UI note) if the pool is exhausted.
