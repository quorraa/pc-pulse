# Named-pipe protocol

PC Pulse protocol version 1 uses one UTF-8 JSON object per message on `\\.\pipe\PcPulse.v1`. The pipe is local-only, message-mode, duplex, and capped at 1 MiB in both directions. The dashboard opens a fresh connection for each request so service shutdown cannot be held open by an idle client.

Every request has a camel-case `command`; request parameter fields are snake_case (`alert_id`, `from_ms`) while response payload fields are camelCase — the two directions deliberately differ, and the tables below show the exact wire spellings. Successful responses are:

```json
{"status":"ok","data":{}}
```

Errors do not disclose stack traces:

```json
{"status":"error","code":"requestFailed","message":"human-readable message"}
```

## Commands

| Command | Additional fields | Result |
|---|---|---|
| `ping` | — | Protocol and service versions |
| `getSnapshot` | — | Latest system sample, all live processes, active alerts |
| `live` | — | Most recent high-rate system-only sample; also marks live-channel liveness (see below) |
| `getHistory` | `from_ms`, `to_ms`, `limit` | System and process samples; transport-safe limit is clamped to 750 |
| `getSystemHistory` | `from_ms`, `to_ms`, `limit` | System-only history downsampled evenly across the requested window; limit is clamped to 800 |
| `getAlerts` | `from_ms`, `limit` | Active/resolved alert history; transport-safe limit is clamped to 300 |
| `getDiagnosticLogs` | `from_ms`, `limit` | Redacted high-signal Application/System event records plus collector health; transport-safe limit is clamped to 200 |
| `getAgentContext` | `window_hours` | Bounded, redacted system/process/log rollups and exact evidence references; 1–24 hours |
| `getOptimizationPlans` | `limit` | Previously validated systems-analyzer plans; transport-safe limit is clamped to 5 |
| `saveOptimizationPlan` | `plan` | Validate and persist a schema-v1 display-only optimization plan |
| `getSettings` | — | Validated detector settings |
| `updateSettings` | `settings` | Saved settings or a validation error |
| `getProcessTree` | — | Current processes nested by parent PID |
| `acknowledgeAlert` | `alert_id` | Acknowledgment result |
| `archiveAlert` | `alert_id`, `archived` | Archive-flag result; `archived: false` recovers a finding |
| `terminateProcess` | `pid`, `confirmed` | Termination result |
| `addRating` | `verdict` | Stores and returns a server-assembled performance rating |
| `getRatings` | `limit` | Rating history, newest first; transport-safe limit is clamped to 200 (`POLICY_OFFSET_RATINGS`, the same history bound the notification policy is derived from) |
| `getLaunchGroups` | `from_ms`, `console_hosts_only`, `limit` (all optional) | Recorded launches bucketed by `(exe_path, lineage_sig)` with aggregate stats; transport-safe limit is clamped to 500 |
| `getLaunchOccurrences` | `exe_path`, `lineage_sig`, `from_ms`, `limit` (the latter two optional) | Individual launch rows for one group's exact key, newest first, with `commandLine` decrypted per request when captured; transport-safe limit is clamped to 1000 |
| `deleteCommandLines` | — | Deletes every captured command-line blob; never touches launch-history rows |

## The `live` channel

`live` (service 1.11+) serves the smooth-refresh dashboard fresh system numbers at up to 8 Hz without touching the 2-second snapshot pipeline. The payload is one JSON object:

```json
{"available":true,"timestampMs":0,"cpuPercent":0,"memoryUsedBytes":0,"memoryTotalBytes":0,"diskReadBytesPerSec":0,"diskWriteBytesPerSec":0,"diskLatencyMs":0,"networkBytesPerSec":0,"dpcRate":0,"interruptRate":0}
```

Gating semantics — the channel is strictly activity-gated so its idle cost is zero syscalls, zero threads, zero handles:

- The first `live` request starts a dedicated sampling loop that collects every 125 ms on its **own** PDH query, so high-rate collection can never skew the main 2-second query's rate windows. There is no process enumeration on this path.
- Every request marks liveness; the loop stops (closing its PDH handles) after 10 seconds without a request.
- Rate counters need a prior collection, so requests during the loop's warm-up (~125 ms after start, including the request that started it) return `available: false` with zeroed fields rather than fabricated rates. Clients must ignore unavailable samples.
- Responses always return the most recent completed sample; the service keeps no ring and no history for this channel.

Budget: while subscribed, the loop costs one `PdhCollectQueryData` over a seven-counter query plus one `GlobalMemoryStatusEx` every 125 ms (well under 0.01 % normalized CPU against the 0.2 % collector budget) and one extra PDH query handle set that exists only while a subscriber is active. Collections are never closer than 100 ms — PDH rate counters get noisy below that window.

`protocolVersion` is unchanged (still 1): `live` is additive. A pre-1.11 service answers it with the ordinary unknown-command `invalidRequest` error, and the dashboard degrades cleanly — it notes the fact once, stops sending `live` for the session, and smooth mode continues on 2-second snapshots.

`archiveAlert` (service 1.14+) sets or clears the `archived` flag alerts now carry. Archiving is presentation-only: detector semantics are untouched, so an archived active finding keeps updating, counting, and resolving normally — clients simply hide it from their default surfaces, and `getAgentContext` excludes archived findings from `recentAlerts` and the embedded snapshot's active list. Validation mirrors `acknowledgeAlert` (an unknown id answers ok with `archived: false`). `protocolVersion` is unchanged (still 1): the command and the field are additive — alerts without the field deserialize as unarchived, old clients ignore it, and a pre-archive service answers the command with the ordinary unknown-command `invalidRequest` error.

## Alert lifecycle and calibration

`Alert` gained five additive camelCase fields for incident lifecycle and notification calibration. All are `#[serde(default)]`; alerts persisted by older services deserialize with the defaults noted below, which reproduce their old, ungated behavior exactly. `protocolVersion` is unchanged (still 1).

| Field | Type | Default (pre-upgrade records) | Meaning |
|---|---|---|---|
| `fingerprint` | string | `""` | The engine's internal dedup key (e.g. `dpcInterrupt`, or a per-process key), now persisted and visible. Shared by every alert that belongs to the same underlying incident across its open/resolve/reopen cycle. |
| `state` | `"open" \| "reopened" \| "resolved"` | `"open"` | Lifecycle state of the incident, independent of `resolvedAtMs`. |
| `quality` | `AlertQuality` object | all scores `1.0` | The calibration signals behind the `notify` decision (see below). Trusting old records fully matches how they behaved before quality gating existed. |
| `notify` | bool | `true` | Whether this alert should surface a tray balloon. |
| `notifyGeneration` | u32 | `0` | Monotonic counter bumped whenever the incident's notification eligibility is recomputed (e.g. a confident renotify-worthy change). |

`quality` is an object of five 0–1 scores, each recomputed on every evaluation of a live incident:

| Score | Meaning |
|---|---|
| `confidence` | Attribution stability, baseline maturity, and sample depth behind the breach. |
| `persistence` | Breach duration relative to the detector's sustained window. |
| `corroboration` | Correlated co-signals (e.g. DPC rate against disk-latency, GPU, or network activity; growth against unresponsive windows). |
| `userImpact` | Co-occurring user-facing evidence — hung windows, slow launches, foreground-process involvement. |
| `novelty` | `1.0` for a fingerprint's first occurrence, decaying with occurrence count and recency of the last notification. |

### Reopen

An incident resolves when its detector stops reporting a breach (after hysteresis and any minimum hold time). If the same `fingerprint` breaches again within a **6-hour quiet period** of that resolution, the engine *reopens* the existing incident rather than minting a new one: the alert keeps its original `id`, `state` becomes `"reopened"`, `occurrenceCount` continues incrementing (it never resets to 1), and `firstSeenMs` is preserved from the original incident — only `lastSeenMs` and the evidence advance. A breach after the quiet period elapses is a genuinely new incident with a new `id` and `firstSeenMs`. Reopening does not by itself flip `notify` to `true` or bump `notifyGeneration` — see below.

A service restart force-resolves any alerts still open at shutdown (marked resolved with a restart note), but their fingerprints remain reopen-eligible, so a condition that is still present when the service comes back reattaches to the same incident instead of spawning a sibling.

### Notification contract

The tray helper's balloon filter is: an alert pops when `notify == true`, it is not `acknowledged`, not `archived`, and its `(id, notifyGeneration)` pair has not already been shown. Concretely, a client should track a set of seen `(id, notifyGeneration)` pairs and pop only unseen ones from the active-alert list, exactly mirroring the compatibility default (`notify = true, notifyGeneration = 0`) that makes an old alert behave like it always did.

`notify == false` does **not** mean the incident is hidden or discarded — it means only that this particular sample never earns a tray popup. Every suppressed incident is still a fully recorded finding: it persists to SQLite, appears in `getAlerts` history and the Findings page, and carries its real `quality` scores and evidence like any other alert. Nothing about suppression drops telemetry; it only gates the interruption.

## Performance ratings

`addRating` (service 1.19+) submits a quick in-app performance rating. The client sends only the verdict; the service owns everything else because the data it needs (recent samples, learned baselines, active incidents) already lives there:

```json
{"command":"addRating","verdict":"good"}
```

`verdict` is one of `"good"`, `"acceptable"`, `"sluggish"`. The response is the full, server-assembled `Rating` record, also persisted:

```json
{
  "id": "...",
  "atMs": 0,
  "verdict": "good",
  "demand": "light",
  "demandDetail": {
    "cpuPercent": 0, "cpuPercentile": null,
    "memoryOccupancyPct": 0, "memoryPercentile": null,
    "diskLatencyMs": 0, "diskPercentile": null,
    "ioBytesPerSec": 0, "ioPercentile": null
  },
  "digest": {},
  "openIncidents": [{"fingerprint": "...", "kind": "...", "severity": "warning", "notify": true, "acknowledged": false}],
  "duringLearning": false,
  "unexplained": false
}
```

- `demand` (`"light" | "moderate" | "heavy"`) is the trailing-10-minute workload bucket the rating was given under, derived from the machine's own learned baselines. A rating is evidence about its own bucket only.
- `digest` is a compact, redacted (`%USERPROFILE%`-style) snapshot of system/process rollups, active incidents, and learning state at rating time — capped at 32 KB — for a future optimization agent's labeled corpus.
- `openIncidents` lists what was active (unarchived) when the rating was given.
- `unexplained` is `true` exactly when `verdict` is `"sluggish"` and nothing was actively notifying — the user felt something no detector named.

`getRatings` returns rating history, newest first:

```json
{"command":"getRatings","limit":50}
```

`getSnapshot`'s top-level payload gained two additive fields so a client can decide *when to ask* and *what the policy currently says* without deriving either itself: `demand: "light" | "moderate" | "heavy" | null` — the bucket the machine is in right now, the same classification a rating would be filed under — and `heavyMinutesTrailingHour: number | null`, how many distinct minutes of the last hour were heavy. Both are `null` from services that predate ratings, and `null` means *not reported*, never "light"/"zero": a client must not nudge, or display a policy offset, on an unknown bucket. Heaviness is counted in wall-clock minutes rather than in samples, so the figure does not move when `sampleIntervalMs` changes.

**Ratings never modify baselines, detector thresholds, or severities.** They only ever adjust the notification policy's floors, per alert kind and demand bucket, bounded to ±0.15 and decaying with a 30-day half-life — the same guarantee `getAgentContext`'s `ratingOffsets`/`limitations` fields already document. `protocolVersion` is unchanged (still 1): both commands are additive, and a pre-1.19 service answers them with the ordinary unknown-command `invalidRequest` error.

## Launch history

`getLaunchGroups`, `getLaunchOccurrences`, and `deleteCommandLines` (service 1.20+) surface the ETW-captured process launch history. A `LaunchEvent` never carries a command line at rest -- the capture pipeline clears it before the row is saved, and any captured line lives only in a separate, DPAPI-encrypted table keyed by `(pid, startTimeMs)`. `getLaunchOccurrences` is the only path that ever populates `commandLine`, decrypting per request and never caching the plaintext.

```json
{"command":"getLaunchGroups","from_ms":0,"console_hosts_only":false,"limit":500}
```

All three fields are optional: `from_ms` defaults to 7 days back, `console_hosts_only` defaults to `false`, and `limit` is clamped to 500 either way. The response groups every matching `LaunchEvent` by `(exePath, lineageSig)` -- never by `sessionId`, so the same launcher chain across sessions is one group:

```json
{
  "groups": [
    {
      "exeName": "notepad.exe",
      "exePath": "c:\\windows\\system32\\notepad.exe",
      "lineageSig": "explorer.exe",
      "launcherSummary": "explorer.exe",
      "count": 12,
      "firstMs": 0,
      "lastMs": 0,
      "medianIntervalMs": 0,
      "meanDurationMs": 0,
      "maxDurationMs": 0,
      "windowed": 10,
      "neverWindowed": 1,
      "unobserved": 1,
      "running": 0,
      "consoleHost": false
    }
  ]
}
```

`lineageSig` is the launch's ancestor names, nearest first, lowercased and joined by `"<"` (e.g. `"cmd.exe<explorer.exe"`; the empty string for a launch with no resolved lineage). `launcherSummary` is the nearest ancestor's own name, or `"unknown"`. Groups are sorted by their occurrence count within the trailing 24 hours of the newest launch in the whole result set (descending), ties broken by `lastMs` (descending) -- a group that was busy weeks ago but is quiet now sorts below one that is active right now, however small its lifetime total. `medianIntervalMs` is `null` when the group has fewer than two occurrences; `meanDurationMs`/`maxDurationMs` are `null` when none of the group's occurrences have finished (still `"running"`).

`getLaunchOccurrences` fetches one group's individual rows by its exact key:

```json
{"command":"getLaunchOccurrences","exe_path":"c:\\windows\\system32\\notepad.exe","lineage_sig":"explorer.exe","from_ms":0,"limit":1000}
```

`exe_path` and `lineage_sig` are required (copy them from a `getLaunchGroups` row); `from_ms` defaults to 7 days back and `limit` is clamped to 1000. The response is newest-first `LaunchEvent` rows:

```json
{
  "events": [
    {
      "pid": 0,
      "startTimeMs": 0,
      "stopTimeMs": 0,
      "exitCode": 0,
      "exeName": "notepad.exe",
      "exePath": "c:\\windows\\system32\\notepad.exe",
      "sessionId": 1,
      "parentPid": 0,
      "lineage": [{"pid": 0, "name": "explorer.exe", "path": "c:\\windows\\explorer.exe"}],
      "windowState": "windowed",
      "consoleHost": false,
      "commandLine": "notepad.exe c:\\notes.txt"
    }
  ]
}
```

`stopTimeMs`, `exitCode`, `rawImagePath`, and `commandLine` are present only when applicable and otherwise omitted rather than sent as `null`. `windowState` is one of `"windowed"`, `"neverWindowed"`, `"unobserved"`, `"running"`. A command line is absent (not the request failing) whenever nothing was captured for that occurrence, capture was off, or decryption fails -- e.g. a machine-key change after a reinstall; that case is logged and counted service-side, never surfaced as a transport error.

`deleteCommandLines` takes no fields and deletes every captured command-line blob -- the user-facing "forget captured command lines" control:

```json
{"command":"deleteCommandLines"}
```

```json
{"deleted": 0}
```

It only ever touches the encrypted command-line table; `launch_events` rows are untouched (they never held a command line to begin with).

`getSnapshot`'s top-level payload carries an additive `launchCapture` object, republished every sample, reporting the capture pipeline's own health:

```json
{
  "startsSeen": 0, "stopsSeen": 0, "persisted": 0,
  "droppedChannel": 0, "etwEventsLost": 0, "eventsLostQueryFailures": 0, "malformedEvents": 0,
  "orphanStops": 0, "stalePendingEvicted": 0,
  "cmdlineSessionActive": false, "cmdlinesCaptured": 0, "cmdlinesRedactedFields": 0,
  "cmdlinesUnmatchedEvicted": 0, "cmdlinesPersistFailures": 0
}
```

`startsSeen`/`stopsSeen`/`persisted` count the ETW start/stop pipeline; `orphanStops` is a stop event with no matching tracked start; `stalePendingEvicted` is a launch dropped after 24h with no stop event ever arriving (its last `"running"` snapshot, if any, remains the honest last-known state). `cmdlineSessionActive` reflects the `captureCommandLines` setting's opt-in MOF session; `cmdlinesCaptured`/`cmdlinesRedactedFields` count what was joined and how much of it was redacted before storage; `cmdlinesUnmatchedEvicted` is captures that aged out or were cap-evicted before any launch row claimed them (ordinary background noise, since the MOF session sees every process on the machine, not just tracked launches); `cmdlinesPersistFailures` is real, unrecoverable loss (DPAPI or the insert itself failed after the join already consumed the capture) and should stay at zero. Snapshots from services older than launch history have no such field and deserialize to the all-zero default, which reads the same as "no launches seen".

Launch-event rows are retained for 7 days; captured command lines are retained on their own, separate clock (`commandLineRetentionHours` in settings, default 24h). `protocolVersion` is unchanged (still 1): all three commands and the `launchCapture` field are additive, and a pre-1.20 service answers the commands with the ordinary unknown-command `invalidRequest` error.

## Hardware inventory

`getSnapshot`'s `hardware` object gained an additive `inventory` field: `HardwareMetrics.inventory: HardwareInventory | null`. It is `null` only until the collector's first inventory probe completes (or entirely absent from a snapshot older than hardware inventory, which old clients simply ignore).

`HardwareInventory` states what hardware *exists*, independent of `HardwareMetrics`'s gauges, which state what is currently *measurable*. The two are deliberately separate: a machine can have a GPU with no working telemetry path (e.g. a non-NVIDIA adapter with no NVML), and inventory must still report it present while the gauge honestly reports unavailable. Missing telemetry never implies missing hardware.

```json
{
  "cpu": {"value": {"manufacturer": "...", "brand": "...", "physicalCores": 0, "logicalProcessors": 0, "baseClockMhz": null, "maxClockMhz": null}, "detail": "", "collectedAtMs": 0},
  "system": {"value": {"manufacturer": "...", "model": "..."}, "detail": "", "collectedAtMs": 0},
  "bios": {"value": {"version": "...", "releaseDate": null}, "detail": "", "collectedAtMs": 0},
  "memory": {"value": {"installedBytes": 0, "moduleCount": 0, "speedMts": null}, "detail": "", "collectedAtMs": 0},
  "storage": {"value": [{"model": "...", "sizeBytes": 0, "busType": "...", "mediaType": "ssd"}], "detail": "", "collectedAtMs": 0},
  "gpus": {"value": [{"name": "...", "vendor": "...", "driverVersion": null, "vramBytes": null}], "detail": "", "collectedAtMs": 0},
  "collectedAtMs": 0
}
```

Each of the six groups (`cpu`, `system`, `bios`, `memory`, `storage`, `gpus`) is independently `{"value": <payload>, "detail": "", "collectedAtMs": ...}` on success, or `{"value": null, "detail": "<reason>", "collectedAtMs": ...}` when that specific WMI class query failed — one group's failure never blanks the others. `detail` is empty on success and non-empty (never a fabricated reading) on failure. `collectedAtMs` is per-group and can lag the top-level `HardwareInventory.collectedAtMs`: a re-probe that fails for one group keeps that group's previous value rather than overwriting it with a stale "unavailable". The top-level `collectedAtMs` is simply when the most recent probe attempt ran, whether or not every group succeeded.

Inventory is probed once at service start and re-probed at most once a day (static facts do not need a live cadence); collection failures never delay or fail the sampling loop.

## Learning state

`getSnapshot`'s top-level payload gained `learning: bool` (default `false`), `learningPercent: number | null` (default `null`), and `learningMinutesLeft: number | null` (default `null`) — all additive and absent-compatible with snapshots from services older than alert calibration.

The learning period is **24 hours of observed time**, not 24 hours of wall clock. The service accumulates observed time one inter-sample gap at a time, and each gap is credited at most 60 seconds, so time the machine spends asleep, hibernating, powered off, or with the service stopped does not count toward maturity. A machine watched for an hour and then suspended overnight wakes up with roughly an hour of learning behind it, not a day's worth.

`learning` is true while the machine-wide baseline has observed less than that period. `learningPercent` is progress as a whole percent (floored, 0–100) and `learningMinutesLeft` is the observed time still owed, in minutes (rounded up) — both `null` once the baseline has matured. Because the countdown is in observed rather than elapsed time, clients should present it as monitoring still to be done rather than as a wall-clock deadline.

During the learning period the notification floor is raised — only a high-confidence Critical incident notifies — while every incident still accrues normally in history.

`terminateProcess` is rejected unless `confirmed` is exactly `true`. The TUI sends it only after the user types the selected process's exact PID. The service independently rejects system/idle PIDs and its own PID.

`saveOptimizationPlan` does not execute any plan step. The service rejects plans that omit the non-execution/confirmation contract, contain an unconfirmed mutating step, or include direct termination commands. Agent context and plan responses remain below the one-MiB protocol cap through bounded rollups.

If any future response still exceeds the cap, the server returns a `responseTooLarge` error on the open pipe. It never drops the connection and leaves the client with a misleading Windows `0x800700E9` dead-pipe error. The TUI uses `getSystemHistory` for long timelines so the chart covers the whole requested window without transferring unused process rows.

Timestamps are Unix epoch milliseconds. Byte counters are unsigned integers; rates and percentages are JSON numbers. Enums use lower camel case (`info`, `warning`, `critical`).
