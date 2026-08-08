# PC Pulse

<p align="center"><img src="docs/media/logo.svg" alt="PC Pulse — workstation vital signs" width="640"></p>

[![Windows CI](https://github.com/quorraa/pc-pulse/actions/workflows/ci.yml/badge.svg)](https://github.com/quorraa/pc-pulse/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/quorraa/pc-pulse?display_name=tag)](https://github.com/quorraa/pc-pulse/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-70e1c1.svg)](LICENSE)

> Windows 11 x64 only. Built for technical users investigating sustained workstation slowdowns and runaway agent workloads.

PC Pulse is a keyboard-first Windows 11 performance attribution tool for finding the process, agent tree, application, or driver-level condition making a workstation slow. A low-overhead Rust service collects ETW, PDH, Win32, and high-signal Windows Event Log evidence, keeps bounded SQLite history, and serves local clients over a secured named pipe. The primary client is a Ratatui terminal interface; a tiny native helper provides Windows tray notifications.

PC Pulse alerts on sustained conditions and learned baseline deviations, not isolated spikes. It never terminates a process automatically: a manual termination request requires typing the selected process's exact PID, and the service independently enforces confirmation and refuses protected targets.

## Quick start

1. Download `PcPulse-1.5.4-x64.msi` and `SHA256SUMS.txt` from the [latest release](https://github.com/quorraa/pc-pulse/releases/latest).
2. Verify the MSI's SHA-256 hash against the manifest.
3. Install the MSI from an elevated terminal or Explorer.
4. Open **PC Pulse** from Start. The collector runs as the `PcPulseCollector` Windows service.

Release binaries are currently unsigned; Windows may show an unknown-publisher warning, so verify the published checksum before installing.

## What it monitors

- System and per-process CPU, working set, private bytes, handles, threads, and read/write I/O.
- Physical-disk transfer latency, DPC rate, interrupt rate, paged pool, and nonpaged pool.
- Hung top-level windows, ETW process starts, time to first visible window, parent/child trees, and detached idle agent processes.
- Its own collector against absolute budgets (25 MB working set, 0.2% CPU, 250 handles) plus mature working-set growth.
- Redacted warning/error/critical Application and System events, classified and fingerprinted (hardware, storage, graphics, crashes, hangs, resource exhaustion, power, services, networking, agent runtimes).
- Active and resolved finding history with responsible process where attribution is defensible, supporting evidence, explanation, and safe next actions.

If policy denies ETW session creation, the collector continues with PDH and Win32, marks ETW degraded, and retries every minute. See [detector details](docs/detectors.md) for every finding's ownership, evidence, and thresholds, and the [named-pipe protocol](docs/protocol.md) for the IPC contract.

## Terminal interface

The TUI ships two presentation profiles: **vitals** (default), a patient-monitor identity, and **avionics**, an amber-CRT multi-function display with a bezel-key rail, an annunciator strip that keeps one lamp per finding class lit from every page, and a pressure-map treemap where every major process is a clickable tile sized by working set and heated by its dominant pressure channel. Start with `PcPulse.exe --theme vitals|avionics` or cycle live with `t`.

| Vitals (default) | Avionics |
|---|---|
| ![Observe — pressure field, suspect ranking, load ribbon](docs/media/vitals-observe.png) | ![Observe — the pressure-map treemap under the annunciator strip](docs/media/avionics-observe.png) |
| ![Process hunt — sortable spectrum and process lens](docs/media/vitals-hunt.png) | ![Findings — annunciator lamps and the finding archive](docs/media/avionics-incidents.png) |

| Vitals tour | Avionics tour |
|---|---|
| ![Vitals profile tour](docs/media/demo-vitals.gif) | ![Avionics profile tour](docs/media/demo-avionics.gif) |

![Oracle — the embedded systems-analyzer chat](docs/media/vitals-oracle.png)

*Screenshots come from the deterministic render gallery (`cargo test -p pcpulse-tui --lib dev_render_gallery -- --ignored` with `PCPULSE_GALLERY_DIR` set).*

Eight views:

1. **Observe** — shared CPU/memory pressure field, multi-resource suspect ranking, threshold vectors, load ribbon, agent footprint, collector budget, incident tape.
2. **Processes** — dense sortable process table, name/path/PID filtering, full process inspector.
3. **Tree** — parent/child ownership for abandoned agent descendants and runaway parallel jobs.
4. **Findings** — active/resolved history with ownership, explanation, evidence, and recommendations.
5. **Timeline** — persisted CPU, memory, and disk-latency charts over configurable windows.
6. **Oracle** — evidence-aware chat with the dedicated systems analyzer and the live Windows diagnostic feed.
7. **Settings** — all detector thresholds and notification state, plain-language explanations, plus per-user CLIENT settings (theme, motion effects, Oracle time budget).
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
| `e` on Oracle | Recall your latest question into the input for editing; `Enter` resubmits it |
| `r` or `F2` in Chat Vault | Rename the selected chat inline; an explicit title is kept even as the conversation grows |
| `d` or `Del` in Chat Vault | Delete the selected chat — press twice to confirm; deleting the active chat starts a fresh one |
| `y` on Oracle | Copy the latest analyzer answer to the Windows clipboard |
| `Esc` while analyzing | Cancel the current Codex run |
| `Enter` / `e` | Edit the selected setting |
| `s` | Save settings |
| `r` | Refresh the current view |
| `m` | Toggle finite TachyonFX motion effects; the choice is saved per user |
| `t` | Cycle presentation profiles (vitals / avionics); the choice is saved per user |
| `?` | Open the keys overlay on top of any page; `Esc`, `?`, or a click closes it (the Keys page itself stays on `8`) |
| `q` / `Ctrl-C` | Exit the TUI; the collector continues |
| Left-click | Select tabs, process/tree/finding rows, settings, Chat Vault rows, or the Oracle prompt; double-click a Chat Vault row to restore it |
| Click any table header | Sort the overview suspects, processes, lineage rows, findings, or settings by that column |
| Mouse wheel | Scroll the active table, finding list, or Oracle conversation; zoom Timeline history |
| Right-click a process | Open the existing typed-PID termination confirmation; never terminate directly |

[TachyonFX](https://docs.rs/tachyonfx/latest/tachyonfx/fx/index.html) motion is finite and event-scoped; start with `PcPulse.exe --no-effects` or press `m` for reduced motion.

`PcPulse.Notify.exe` is a small per-user tray helper that watches the same pipe and notifies only when a new sustained finding appears; the MSI starts it at logon, and notifications can be disabled from Settings. Double-click its tray icon to open `PcPulse.exe`; right-click to exit the helper.

## Oracle

Oracle is a chatbot inside the TUI — press `Enter` on view `6`, type a question, and submit. Every turn receives a fresh, bounded, redacted evidence bundle; answers must cite exact collected references, and no proposed action is ever executed. The collector never invokes AI: the client runs `pcpulse-systems-analyzer` through the user's Codex CLI in an ephemeral read-only sandbox, and requires `codex login status` to report ChatGPT authentication (API-key sessions are refused rather than silently billed). Press `y` to copy the latest answer, `i` on a finding to investigate it in a new chat, and `r`/`d` in Chat Vault to rename or delete sessions. Analyzer failures are logged to `%LOCALAPPDATA%\PcPulse\analyzer-last-error.log` (overwritten on each failure).

For automation, `PcPulse.exe analyze 1` produces a one-shot plan, and `agent-context`, `plan-schema`, `agent-prompt`, and `import-plan` expose the same contract to other agents — see the [systems-analyzer integration guide](docs/agent-integration.md).

## Build and test

Prerequisites: Windows 11 x64; Rust stable 1.94+ with the MSVC x64 target; Visual Studio Build Tools with the Windows 11 SDK and C++ build tools (for bundled SQLite); .NET SDK 10.0.100+ only to build the WiX MSI — the installed application does not use .NET.

```powershell
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo build --workspace --release
```

Build the three executables, MSI, and SHA-256 manifest (add `-CertificateThumbprint YOUR_SHA1_THUMBPRINT` for a signed release):

```powershell
.\scripts\Build-Release.ps1 -Architecture x64 -Version 1.5.4
```

Outputs land in `artifacts`. `scripts\Measure-CollectorBudget.ps1` validates the collector's resource budgets from an elevated terminal.

Repository layout:

- `src/PcPulse.Service` — Rust service: ETW/PDH/Win32 collectors, detector engine, SQLite, named-pipe server.
- `src/PcPulse.Tui` — Ratatui client, shared pipe client, CLI JSON commands, tray notification helper.
- `installer/PcPulse.Installer` — per-machine WiX MSI.
- `scripts` — release, setup, IPC smoke test, and collector-budget measurement.

## Install and run

```powershell
msiexec.exe /i .\artifacts\PcPulse-1.5.4-x64.msi
```

Open **PC Pulse** from Start, or run `& "$env:ProgramFiles\PC Pulse\PcPulse.exe"`. Verify the service and IPC:

```powershell
Get-Service PcPulseCollector
.\scripts\Test-Pipe.ps1
```

For scripts and agent runs, `PcPulse.exe ping | snapshot | alerts | logs 24 | agent-context 1 | analyze 1 | plan | settings` all emit formatted JSON. The development-equivalent service setup is `scripts\Install-Service.ps1`.

Uninstall via Apps > Installed apps, or:

```powershell
msiexec.exe /x .\artifacts\PcPulse-1.5.4-x64.msi
```

For development installs, `scripts\Uninstall-Service.ps1` removes everything; pass `-KeepHistory` to retain `%ProgramData%\PcPulse`.

## Storage, privacy, and security

Everything stays local: bounded SQLite history and service settings in `%ProgramData%\PcPulse` (`history.db`, `settings.json`; configurable 1–365 day retention), per-user chat history and UI preferences in `%LOCALAPPDATA%\PcPulse` (`chat-history.json`, `ui-prefs.json`). Diagnostic event fields are bounded and redacted before persistence — user-profile paths become `%USERPROFILE%` and credential-like values are removed. PC Pulse never collects the Security event log, process command lines, environment variables, file contents, browser data, or keystrokes. The collector has no network path; only an explicit Oracle question or `analyze` run sends the redacted evidence bundle to the user's ChatGPT-authenticated Codex session. The named pipe rejects remote clients, caps messages at 1 MiB, and grants access only to LocalSystem, administrators, and interactive users; termination requires `confirmed: true` and always refuses PID 0, PID 4, and the collector itself.

## Documentation

- [Detector design](docs/detectors.md) — sustained streaks, baselines, growth windows, attribution limits.
- [Named-pipe protocol](docs/protocol.md) — commands, payloads, and limits.
- [Systems-analyzer integration](docs/agent-integration.md) — Oracle internals, schemas, and external-agent workflow.
