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

`terminateProcess` is rejected unless `confirmed` is exactly `true`. The TUI sends it only after the user types the selected process's exact PID. The service independently rejects system/idle PIDs and its own PID.

`saveOptimizationPlan` does not execute any plan step. The service rejects plans that omit the non-execution/confirmation contract, contain an unconfirmed mutating step, or include direct termination commands. Agent context and plan responses remain below the one-MiB protocol cap through bounded rollups.

If any future response still exceeds the cap, the server returns a `responseTooLarge` error on the open pipe. It never drops the connection and leaves the client with a misleading Windows `0x800700E9` dead-pipe error. The TUI uses `getSystemHistory` for long timelines so the chart covers the whole requested window without transferring unused process rows.

Timestamps are Unix epoch milliseconds. Byte counters are unsigned integers; rates and percentages are JSON numbers. Enums use lower camel case (`info`, `warning`, `critical`).
