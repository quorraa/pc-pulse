# Named-pipe protocol

PC Pulse protocol version 1 uses one UTF-8 JSON object per message on `\\.\pipe\PcPulse.v1`. The pipe is local-only, message-mode, duplex, and capped at 1 MiB in both directions. The dashboard opens a fresh connection for each request so service shutdown cannot be held open by an idle client.

Every request has a camel-case `command`. Successful responses are:

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
| `getHistory` | `fromMs`, `toMs`, `limit` | System and process samples; transport-safe limit is clamped to 750 |
| `getSystemHistory` | `fromMs`, `toMs`, `limit` | System-only history downsampled evenly across the requested window; limit is clamped to 800 |
| `getAlerts` | `fromMs`, `limit` | Active/resolved alert history; transport-safe limit is clamped to 300 |
| `getDiagnosticLogs` | `fromMs`, `limit` | Redacted high-signal Application/System event records plus collector health; transport-safe limit is clamped to 200 |
| `getAgentContext` | `windowHours` | Bounded, redacted system/process/log rollups and exact evidence references; 1–24 hours |
| `getOptimizationPlans` | `limit` | Previously validated systems-analyzer plans; transport-safe limit is clamped to 5 |
| `saveOptimizationPlan` | `plan` | Validate and persist a schema-v1 display-only optimization plan |
| `getSettings` | — | Validated detector settings |
| `updateSettings` | `settings` | Saved settings or a validation error |
| `getProcessTree` | — | Current processes nested by parent PID |
| `acknowledgeAlert` | `alertId` | Acknowledgment result |
| `terminateProcess` | `pid`, `confirmed` | Termination result |

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

`terminateProcess` is rejected unless `confirmed` is exactly `true`. The TUI sends it only after the user types the selected process's exact PID. The service independently rejects system/idle PIDs and its own PID.

`saveOptimizationPlan` does not execute any plan step. The service rejects plans that omit the non-execution/confirmation contract, contain an unconfirmed mutating step, or include direct termination commands. Agent context and plan responses remain below the one-MiB protocol cap through bounded rollups.

If any future response still exceeds the cap, the server returns a `responseTooLarge` error on the open pipe. It never drops the connection and leaves the client with a misleading Windows `0x800700E9` dead-pipe error. The TUI uses `getSystemHistory` for long timelines so the chart covers the whole requested window without transferring unused process rows.

Timestamps are Unix epoch milliseconds. Byte counters are unsigned integers; rates and percentages are JSON numbers. Enums use lower camel case (`info`, `warning`, `critical`).
