# PC Pulse

[![Windows CI](https://github.com/quorraa/pc-pulse/actions/workflows/ci.yml/badge.svg)](https://github.com/quorraa/pc-pulse/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/quorraa/pc-pulse?display_name=tag)](https://github.com/quorraa/pc-pulse/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-70e1c1.svg)](LICENSE)

> Windows 11 x64 only. PC Pulse is designed for technical users investigating sustained workstation slowdowns and runaway agent workloads.

PC Pulse is a keyboard-first Windows 11 performance attribution tool for finding the process, agent tree, application, or driver-level condition making a workstation slow. A low-overhead Rust service collects ETW, PDH, Win32, and high-signal Windows Event Log evidence, keeps bounded SQLite history, and serves local clients over a secured named pipe. The primary client is a Ratatui terminal interface; a separate tiny native helper provides Windows tray notifications.

PC Pulse uses sustained conditions and learned baseline deviations instead of alerting on isolated spikes. It never terminates a process automatically. A manual termination request requires typing the selected process's exact PID, and the service independently enforces confirmation and refuses protected targets.

## Quick start

1. Download `PcPulse-1.4.3-x64.msi` and `SHA256SUMS.txt` from the [latest release](https://github.com/quorraa/pc-pulse/releases/latest).
2. Verify the MSI's SHA-256 hash against the manifest.
3. Install the MSI from an elevated terminal or Explorer.
4. Open **PC Pulse** from Start. The collector runs as the `PcPulseCollector` Windows service.

Release binaries are currently unsigned. Windows may show an unknown-publisher warning; verify the published checksum before installing. The installed application does not require .NET—the SDK is used only to build the WiX installer.

## What it monitors

- System and per-process CPU, working set, private bytes, handles, threads, and read/write I/O.
- Physical-disk transfer latency, DPC rate, interrupt rate, paged pool, and nonpaged pool.
- Hung top-level windows, ETW process starts, time to first visible window, parent/child trees, and detached idle agent processes.
- The collector's own working set, CPU, and handles against the 25 MB / 0.2% / 250-handle absolute budgets. Working-set growth is evaluated separately only after startup warm-up and a mature multi-segment trend.
- Active and resolved finding history with responsible process where attribution is defensible, supporting evidence, explanation, and safe next actions.
- Redacted warning/error/critical Application and System events, classified and fingerprinted for hardware, storage, graphics, crashes, hangs, resource exhaustion, power, services, networking, and agent runtimes.
- A bounded machine-readable evidence bundle and an embedded systems-analyzer chat that answers questions and proposes validated, display-only optimization actions.

ETW supplies process lifecycle timing, PDH supplies localized system performance counters, and Win32 supplies authoritative process, window, and system snapshots. If policy denies ETW session creation, the collector continues with PDH and Win32, marks ETW as degraded, and retries every minute. The installed LocalSystem service normally has the required ETW privilege.

## Terminal interface

The TUI ships two presentation profiles: **vitals** (default), a patient-monitor identity with top header, tabs, and a bottom footer, and **avionics**, an amber-CRT multi-function display with a left bezel-key rail, a top annunciator strip that keeps one lamp per finding class lit from every page, and an Observe canvas rebuilt around a custom pressure-map treemap — every major process becomes a clickable tile sized by working set and colored/heated by its dominant pressure channel. Start with `PcPulse.exe --theme vitals|avionics` or cycle live with `t`.

The TUI has eight views:

1. **Observe** — an asymmetric runtime-forensics canvas with a shared CPU/memory pressure field, multi-resource suspect ranking, system threshold vectors, a CPU load-composition ribbon on tall terminals, parallel-agent footprint, collector budget, and an owner/evidence incident tape.
2. **Processes** — dense sortable process table, filtering by name/path/PID, and a full process inspector.
3. **Tree** — parent/child ownership for identifying abandoned agent descendants and runaway parallel jobs.
4. **Findings** — active/resolved history with ownership, explanation, evidence, and recommendations.
5. **Timeline** — persisted CPU, memory, and disk-latency charts over configurable windows.
6. **Oracle** — an internal evidence-aware chat with the dedicated systems analyzer, its proposed safe actions, and the live Windows diagnostic feed.
7. **Settings** — all detector thresholds, sustained-sample rules, baseline deviation, agent patterns, and notification state.
8. **Keys** — the complete keyboard reference.

Important keys:

| Key | Action |
|---|---|
| `1`–`8`, `Tab`, `Shift-Tab` | Navigate pages |
| `j`/`k`, arrows, `PgUp`/`PgDn` | Move selection |
| `/` | Filter the process table |
| `o` | Cycle CPU/memory/I/O/handle/thread/age/name sorting |
| `g` | Toggle agent-only process focus |
| `x` | Begin a manual termination request; exact PID entry is required |
| `a` | Acknowledge the selected finding |
| `i` | Investigate the selected finding in Oracle — a new chat opens and the composed question is submitted with the finding's evidence; double-clicking the finding row does the same |
| `[` / `]` | Shorten or lengthen the persisted timeline |
| `Enter` or `/` on Oracle | Ask the embedded systems analyzer |
| `j`/`k`, `PgUp`/`PgDn` on Oracle | Scroll the conversation |
| `[` / `]` on Oracle | Change the fresh evidence window (1–24 hours) |
| `n` or `c` on Oracle | Begin a new chat while retaining the previous session in Chat Vault |
| `h` on Oracle | Focus Chat Vault; use `j`/`k` and `Enter` to restore a previous chat |
| `Esc` while analyzing | Cancel the current Codex run |
| `Enter` / `e` | Edit the selected setting |
| `s` | Save settings |
| `r` | Refresh the current view |
| `m` | Toggle finite TachyonFX motion effects |
| `t` | Cycle presentation profiles (vitals / avionics) |
| `q` / `Ctrl-C` | Exit the TUI; the collector continues |
| Left-click | Select tabs, process/tree/finding rows, settings, or the Oracle prompt |
| Click any table header | Sort the overview suspects, processes, lineage rows, findings, or settings by that column |
| Mouse wheel | Scroll the active table, finding list, or Oracle conversation; zoom Timeline history |
| Right-click a process | Open the existing typed-PID termination confirmation; never terminate directly |

The process table highlights unresponsive applications and suspected agent processes. The active sort header is highlighted. The footer reserves one line for contextual shortcuts and a separate line for status/error messages, so analyzer completion and collector messages never hide controls. [TachyonFX](https://docs.rs/tachyonfx/latest/tachyonfx/fx/index.html) motion is finite and event-scoped: startup, navigation, focus, connection changes, new sustained findings, input modes, and confirmations use distinct compositions. Each new telemetry frame produces only a bounded chromatic scan across signal-colored cells; it never hides or recreates incident rows. Effects reset their clock after idle periods, clamp delayed frames, and return to the event-driven loop when complete. Start with `PcPulse.exe --no-effects` or press `m` for reduced motion.

## Native notification helper

`PcPulse.Notify.exe` is a small Rust/Win32 per-user process. It owns only a notification-area icon and polls the same local named pipe. It primes its alert state at startup, so existing findings are not replayed; it notifies only when a new sustained finding appears. Notifications can be disabled from the TUI settings.

- Double-click the tray icon to open `PcPulse.exe` in a new console.
- Right-click the tray icon to exit the helper.
- The MSI registers the helper in the machine Run key, so it starts for interactive users at their next logon.

The helper is deliberately separate from the LocalSystem collector because Windows services run in session 0 and must not try to display UI in user sessions.

## Detection behavior

A condition must remain true for `sustainedSamples`—five samples, roughly ten seconds by default. CPU, memory, and I/O detectors also compare against an exponentially weighted per-process baseline and deviation band after warm-up. Memory, handle, and thread growth use bounded multi-minute histories. Process identity includes creation time to avoid PID-reuse errors.

| Finding | Ownership and evidence |
|---|---|
| Sustained CPU | Process, current CPU, learned baseline, configured limit |
| Memory / handle / thread growth | Process, absolute growth, observation window |
| Heavy I/O / disk latency | Highest current I/O process, read/write rate, system latency |
| Unresponsive app | Process with a visible window hung for the configured duration |
| Slow launch | ETW process-start time to first visible window |
| Abandoned agent | Pattern match, missing parent, minimum age, sustained low CPU/I/O |
| Kernel-pool growth | System/driver scope, paged/nonpaged evidence, PoolMon guidance |
| DPC / interrupts | System/driver scope; no false blame assigned to a user process |
| Collector budget | Collector process, working set, CPU, handles, observed growth |

See [detector details](docs/detectors.md) and the [named-pipe protocol](docs/protocol.md).

## Embedded systems-analyzer chat

Oracle is a chatbot inside the TUI—no companion command or external chat is needed. Press `Enter`, type a question, and submit it. Every turn receives a fresh, bounded, redacted evidence bundle plus at most 16 local conversation turns. Snapshot collection and screen updates continue while the answer is generated; `Esc` cancels the child analyzer. Chat Vault keeps up to 24 previous sessions: click one to restore it, press `h` for keyboard selection, or press `n`/`c` to begin a new chat.

The collector never invokes AI. The interactive `PcPulse.exe` client runs `pcpulse-systems-analyzer` through the user's saved Codex login in an ephemeral read-only sandbox. PC Pulse requires `codex login status` to report ChatGPT authentication, so Oracle uses ChatGPT subscription access and refuses API-key sessions instead of silently changing billing. The structured answer must cite exact collected references. Direct termination commands and unconfirmed mutations are rejected, and no proposed action is executed.

The older one-shot plan interface remains available for automation and external-agent integration:

```powershell
PcPulse.exe analyze 1
```

Other agents can consume the same contract through `agent-context`, `plan-schema`, `agent-prompt`, and `import-plan`. See the complete [systems-analyzer integration guide](docs/agent-integration.md).

## Repository layout

- `src/PcPulse.Service` — Rust service, ETW/PDH/Win32 collectors, detector engine, SQLite, and named-pipe server.
- `src/PcPulse.Tui` — Ratatui client, shared pipe client, CLI JSON commands, and native Windows notification helper.
- `installer/PcPulse.Installer` — per-machine WiX MSI with automatic service start/recovery, Start Menu shortcut, and notifier logon registration.
- `scripts` — release, setup, IPC smoke test, and collector-budget measurement.
- Rust unit tests live beside the service and TUI modules.

There is no WinUI, Windows App SDK, C# client, or .NET application runtime in the product.

## Prerequisites

- Windows 11 x64.
- Rust stable 1.94 or newer with the MSVC x64 target.
- Visual Studio Build Tools with the Windows 11 SDK and C++ build tools, needed for bundled SQLite.
- .NET SDK 10.0.100 or newer only to run the WiX MSBuild project when creating the MSI. The installed application itself does not use .NET.

## Build and test

```powershell
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo build --workspace --release
```

Create the three Rust executables, MSI, and SHA-256 manifest:

```powershell
.\scripts\Build-Release.ps1 -Architecture x64 -Version 1.4.3
```

For a signed release:

```powershell
.\scripts\Build-Release.ps1 -Version 1.4.3 -CertificateThumbprint YOUR_SHA1_THUMBPRINT
```

Outputs are placed in `artifacts`, including `PcPulse-1.4.3-x64.msi`, `SHA256SUMS.txt`, and:

```text
artifacts\publish\PcPulse.Service.exe
artifacts\publish\PcPulse.exe
artifacts\publish\PcPulse.Notify.exe
```

## Install and run

Install or upgrade from an elevated terminal:

```powershell
msiexec.exe /i .\artifacts\PcPulse-1.4.3-x64.msi
```

Open **PC Pulse** from Start, or run:

```powershell
& "$env:ProgramFiles\PC Pulse\PcPulse.exe"
```

Useful noninteractive commands for scripts and agent runs:

```powershell
PcPulse.exe ping
PcPulse.exe snapshot
PcPulse.exe alerts
PcPulse.exe logs 24
PcPulse.exe agent-context 1
PcPulse.exe analyze 1
PcPulse.exe plan
PcPulse.exe settings
```

All commands emit formatted JSON and tolerate downstream pipe closure. The equivalent development service setup is `scripts\Install-Service.ps1`.

Verify the installed service and IPC:

```powershell
Get-Service PcPulseCollector
.\scripts\Test-Pipe.ps1
```

Run the collector interactively when debugging it directly:

```powershell
.\target\release\pcpulse-collector.exe --console --data-dir .\artifacts\dev-data
```

ETW may be degraded in a non-elevated console.

## Resource-budget validation

Run from an elevated terminal so the service-equivalent ETW path is measured:

```powershell
.\scripts\Measure-CollectorBudget.ps1 -DurationSeconds 600
```

The script samples every two seconds and fails if average normalized collector CPU reaches 0.2%, maximum working set reaches 25 MB, handles reach 250, or working set grows by at least 1 MB across the run.

## Storage, privacy, and security

History and settings remain local:

```text
%ProgramData%\PcPulse\history.db
%ProgramData%\PcPulse\settings.json
%LOCALAPPDATA%\PcPulse\chat-history.json
```

SQLite uses WAL mode, normal durability, bounded sample persistence, daily cleanup, and configurable 1–365 day retention. Chat history is per-user, atomically replaced, and bounded to 24 sessions with 16 messages per session. It stores the conversation and validated response—not raw evidence bundles or Windows event records. The collector itself has no network path; only an explicit Oracle/analyze request sends its redacted evidence bundle to the authenticated Codex session.

Diagnostic event fields are bounded and redacted before persistence. User-profile segments become `%USERPROFILE%`; credential-like fields and inline secret arguments are removed. PC Pulse does not collect the Security event log, process command lines, environment variables, file contents, browser data, or keystrokes. The optional systems analyzer sends only the explicit redacted evidence bundle and bounded conversation to the user's ChatGPT-authenticated Codex session when the user submits a question or runs `analyze`.

The named pipe rejects remote clients, caps messages at one MiB, and grants access only to LocalSystem, administrators, and interactive users. Settings are validated by the service. Termination requires `confirmed: true`; PID 0, PID 4, and the collector itself are always refused.

## Uninstall

Use Apps > Installed apps, or:

```powershell
msiexec.exe /x .\artifacts\PcPulse-1.4.3-x64.msi
```

For development installs, `scripts\Uninstall-Service.ps1` removes the service, notifier startup entry, binaries, settings, and history. Pass `-KeepHistory` to retain `%ProgramData%\PcPulse`.
