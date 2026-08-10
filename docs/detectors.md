# Detector design

## Sustained state

Each candidate condition has a keyed streak (`kind + process identity`). It becomes an alert only when its streak reaches the configured minimum. When a condition clears, the alert is marked resolved and written back to SQLite. Reoccurrence after resolution creates a new alert ID, preserving a useful incident timeline.

The default sample interval is two seconds and the default streak is five. Hung-window duration is converted to samples from `unresponsiveSeconds`, so reducing the global streak cannot accidentally turn a single hung-window probe into an alert. Slow-launch observations require two consecutive visible-window samples.

## Baselines

CPU, working set, and I/O have a bounded exponentially weighted baseline per `(PID, process creation time)`. The warm-up mean uses a cumulative average; after warm-up, alpha is 0.05. The detector compares a value with:

```text
baseline mean + max(configured sigma × standard deviation, detector minimum delta)
```

This prevents a nearly constant process from generating alerts due to tiny floating-point variance, while still allowing a legitimately variable workload to establish a wider normal band. A process exit removes its baseline and rolling history.

## Growth windows

Per-process memory, handles, and thread counts use a bounded five-minute deque. A candidate must show absolute growth over at least the available minute-scale history and then remain abnormal for the sustained streak. The collector does not retain an unbounded sample list.

Collector self-monitoring treats absolute budgets and growth as different conditions. Working set at or above 25 MB, CPU at or above the configured collector CPU ceiling (default 0.2%), or 600 or more handles creates a critical candidate and lists the breached dimension first. Working-set growth is suppressed during the first ten minutes, requires at least four minutes of history, and must rise by at least 1 MiB across early, middle, and recent window means. A one-time cache allocation or startup settling is not a trend. Confirmed mature growth is a warning until an absolute budget is crossed.

A collector restart closes persisted open findings because monitoring continuity was interrupted. Conditions that remain present must satisfy their sustained streak again after restart.

## Archived findings

Findings can be archived (and recovered) from the client. The flag is presentation-only and orthogonal to the lifecycle above: an archived active finding keeps updating, keeps its streak, and resolves exactly as if it were not archived — nothing about detection, forensics, or attribution changes. Clients hide archived findings from their default list, lamps, tapes, and notices, and the agent-context evidence bundle excludes them so filed-away noise stops reaching the analyzer; explicitly investigating an archived finding still injects it into the bundle.

## Leak forensics

While a handle-growth or thread-growth finding is active — for any process — the collector attaches two extra evidence captures to it:

- **Handle types.** One pass over the system handle table (`NtQuerySystemInformation`, extended handle information) builds a per-type histogram for the flagged PID. Type indexes are resolved to names once via the object-type table. The finding's evidence shows the top three per-type deltas since the finding fired, e.g. `Handle types :: Event +1870 · Section +40 · File +12`. No per-handle query and no handle duplication is ever performed, so handles in blocking states cannot stall the collector.
- **New-thread modules.** Thread IDs are snapshotted when the finding fires; on each capture, threads that appeared since then have their Win32 start address resolved and mapped to the owning module, e.g. `New-thread modules :: xul.dll x34 · nvwgf2umx.dll x3`. Threads whose process denies access are reported as `unattributed`.

Both captures take a baseline when the finding first fires, then refresh at most once per minute while it stays active; a `Forensics window` row states the span the deltas cover. Evidence rows are replaced on each capture, never accumulated, and a finding resolving clears its baselines — with no leak finding active the forensics engine performs no syscalls at all. The multi-megabyte handle-table buffer is bucketed and freed within the capture (bailing with a degraded evidence note past a 64 MB cap), and every process, thread, and snapshot handle a capture opens is closed in the same pass so the collector's 600-handle budget holds.

Privacy boundary: forensics records kernel object type names and module base file names only — never command lines, handle names, window text, or memory content.

## Interrupt attribution

While a `dpcInterrupt` finding is active, the collector answers the question the PDH counters cannot: *which driver* is doing the interrupt work — and, across repeated traces, *which device class* is the most likely root cause. It captures short Windows kernel traces and attaches these evidence rows to the finding:

- `Likely cause :: nvlddmkm.sys — NVIDIA Windows Kernel Mode Driver [gpu]` — the modal top driver across the finding's capture history, enriched with its version-resource description and mapped to a device class (storage, network, gpu, usb, audio, platform, other) by a keyword table over the driver name and description/company strings.
- `Confidence :: high — top in 4/4 traces · 58% mean share` — the verdict tier from the rubric below, with the consistency and dominance figures behind it.
- `Correlation :: gpu activity r=0.81 over 5 m` — the strongest Pearson correlation between the kernel-rate series and the class-matched activity series, or `insufficient signal` when the guards say r would be meaningless.
- `ISR/DPC attribution :: storport.sys 41% · ndis.sys 27% · nvlddmkm.sys 12%` — every interrupt service routine and DPC routine address in the latest trace, bucketed at 64 KiB granularity and mapped to the loaded kernel driver whose base address is nearest at-or-below (`EnumDeviceDrivers`); addresses below every driver base are `unattributed`.
- `Top driver :: storport.sys — Microsoft Storage Port Driver` — the latest trace's leading driver enriched with its version-resource description (or company name).
- `Trace window :: 8 s · 214k events` — the actual span and decoded event count, with `(capped)` when the storm guard ended the capture early.

When a class is identified, the finding's recommendation gains one class-specific sentence (e.g. "Update or roll back the storage driver first."); the `other` class appends nothing.

Repeated tracing and adaptive cadence:

- One capture when the finding fires, then re-captures at **two-minute spacing until the finding holds three successful captures**, then backed off to **once every ten minutes** while it stays active. A failed capture always arms the full ten-minute cooldown, so a denied session is not retried every two minutes. A finding that fires anew starts its own fast phase.
- Each finding keeps a bounded ring of its **last eight successful attributions** (timestamp, per-driver shares, event totals, storm-cap flag). Zero-event and undecodable traces never enter the history.

Correlation basis:

- The runtime feeds the engine a rolling **five-minute window** of the two-second system samples: interrupt rate, DPC rate, disk read+write bytes/s, disk latency, summed network bytes/s (`\Network Interface(*)\Bytes Total/sec`), and the freshest GPU utilization from the hardware sampler when available.
- Pearson r is computed between each kernel-rate series (interrupt rate and DPC rate) and every activity series matched to the verdict's class — storage → disk read+write bytes/s and disk latency; network → network bytes/s; gpu → GPU utilization — and the strongest |r| is reported. usb, audio, platform, and other have no honest activity series and never pretend to correlate.
- Guards: at least **60 aligned samples** and a variance floor on **both** series (standard deviation above 1% of the series' own mean magnitude, with an absolute epsilon for flat series). Anything short of that is reported as `insufficient signal` — r over a near-constant series is numerically defined but meaningless. When NVML reports no GPU utilization, gpu correlation is skipped honestly rather than imputing zeros.

Confidence rubric (verbatim from the implementation):

- **Consistency** is the number of captures where the same driver is top; **dominance** is that driver's mean share and its mean margin over the runner-up; **correlation** is the best class-matched r.
- **HIGH**: the top driver is consistent in ≥ 3 captures with ≥ 45% mean share AND (matching-class correlation r ≥ 0.6 OR dominance margin ≥ 25 points).
- **MEDIUM**: consistent top in ≥ 2 captures with ≥ 30% mean share, or a single capture with ≥ 60% share.
- **LOW**: everything else with at least one successful capture.
- **Never fabricated**: with zero successful captures the finding keeps only the honest degraded note — no verdict rows, no class sentence.

Mechanics and budget:

- **Session isolation.** The capture uses a dedicated short-lived system logger session (`PcPulseIsrDpc`, `EVENT_TRACE_SYSTEM_LOGGER_MODE`, Windows 10 1703+ allows eight concurrently) enabling only the ISR and DPC kernel flags. The collector's long-lived process-lifecycle ETW session is a separate session and is never touched.
- **Bounded window.** Eight seconds of wall time, consumed in real time on a below-normal-priority thread, with a 400,000-event storm guard that stops the capture early and says so in the evidence. The session is stopped and the trace handle closed deterministically on every path, including errors (balance counters assert this in the probe harness).
- **Expected cost.** During a genuine interrupt storm the consumer processes a burst of very small callbacks — a real but brief CPU spike for up to eight seconds, at below-normal priority, at most once per two minutes during the short fast phase and once per ten minutes after it; sustained collector CPU stays far under the 0.2% budget. Metric sampling pauses for the capture window and resumes with the next sample. The bucket map is a few hundred entries at most; ETW buffer memory (≤ 768 KiB) is returned when the session stops. The activity ring and capture histories are pure bounded memory; with no `dpcInterrupt` finding active the engine performs no syscalls at all.
- **Degraded modes.** If the session cannot start — unelevated collector, pre-1703 Windows, policy, or system-logger exhaustion — the finding carries an honest `capture degraded: …` note instead of attribution, exactly like leak forensics. If events arrive but their layout cannot be decoded, the evidence says so rather than guessing. A failed re-capture keeps the verdict earned by earlier successful traces alongside the degraded note.

Privacy boundary: interrupt attribution records driver base file names and version-resource company/description strings only — never routine addresses, process data, or memory content.

## Crash dumps

On a slow cadence — first scan shortly after the collector starts, then every five minutes — the collector enumerates the standard Windows crash-dump locations: `%SystemRoot%\Minidump\*.dmp`, `%SystemRoot%\MEMORY.DMP`, and each user profile's `AppData\Local\CrashDumps\*.dmp` (WER). Profiles the collector cannot enter degrade silently. Each visible dump raises one `crashDump` finding; the finding resolves when the dump file disappears. Finding identity is derived from the dump's path and timestamp, so a collector restart re-attaches to the same persisted row instead of duplicating it.

Native triage is bounded and local:

- **Kernel dumps** (`PAGEDU64`, and 32-bit `PAGEDUMP`) have their bugcheck code and four parameters read from the documented header offsets, with ~35 well-known codes named (`Bugcheck :: 0x133 DPC_WATCHDOG_VIOLATION`, `Parameters :: 0x1 0x1e00 0x0 0x0`). A kernel dump younger than 48 hours makes its finding critical; everything else is a warning.
- **User-mode minidumps** (`MDMP`) have their exception stream and module list hand-parsed to name the exception code and the module containing the faulting address (`Exception :: 0xc0000005 ACCESS_VIOLATION`, `Faulting module :: hermes.dll`). Hang dumps without an exception stream keep honest empty fields. The Mozilla `minidump` crate was evaluated and rejected for this: it pulls ~20 transitive crates into a collector that budgets itself at 25 MB, while the three structures triage needs are a page of offset arithmetic.
- Every finding carries the dump's redacted path, size, and age (`Dump :: %USERPROFILE%\AppData\Local\CrashDumps\… · 43.2 MB · 2 d ago`) and a rolling `Crash count :: N dumps in 30 days` row.

Budget: between scans the engine is a single timestamp comparison. A scan is directory metadata plus one bounded header/stream read per **new** dump — triage is cached by `(path, modified)`, and a dump already triaged costs nothing to rescan. A header that cannot be read surfaces as a `Triage :: degraded: …` note, never a dropped finding.

Privacy boundary: findings carry metadata and codes only — bugcheck numbers, exception codes, module base file names, sizes, and ages. No dump memory content is read beyond the parsed headers and streams, nothing is uploaded, and user-profile path segments are replaced with `%USERPROFILE%` by the same redaction the event-log collector uses.

### Deep analysis (WinDbg tier)

When the Debugging Tools for Windows are installed, the terminal client can run WinDbg's full `!analyze -v` against a specific dump on explicit demand. This tier lives client-side (`crashdump.rs`), never in the service. It locates `cdb.exe` by probing `PCPULSE_CDB_PATH`, the Windows SDK Debugging Tools under both Program Files roots, the winget/Store WinDbg app-execution alias (`cdbX64.exe` under `%LOCALAPPDATA%\Microsoft\WindowsApps`), and finally PATH; runs `cdb -z <dump> -c "!analyze -v; q"` under a timeout (`PCPULSE_CDB_TIMEOUT_SECS`, default 120 s, clamped 30–1800); preserves the full output to a rotated `%LOCALAPPDATA%\PcPulse\crash-analysis-<n>.log`; and parses the headline fields (`FAILURE_BUCKET_ID`, `IMAGE_NAME`, `MODULE_NAME`, `PROCESS_NAME`, `SYMBOL_NAME`, `BUGCHECK_STR`) into bounded evidence rows that also feed the analyzer's evidence bundle.

**Network note:** this is the only diagnostic path in PC Pulse that touches the network, and only when the user explicitly requests a deep analysis — `cdb` is pointed at the Microsoft public symbol server (`msdl.microsoft.com`) with a local cache under `%LOCALAPPDATA%\PcPulse\symbols`. The service-side scanner performs no network access ever. Missing symbols degrade to whatever cdb can still attribute; nothing is fabricated.

## Attribution limits

- Disk latency is a system PDH value. PC Pulse names the process with the greatest current read/write rate as the likely workload owner and phrases the explanation accordingly; it does not claim proof of storage-stack ownership.
- Kernel pool allocations and DPC/interrupt work usually belong to drivers. There is no honest user-process attribution, so these findings are labeled `System / driver`; sustained DPC/interrupt findings additionally gain driver-level ISR/DPC attribution (above), while kernel pool findings recommend OEM driver checks or PoolMon.
- Unresponsive status comes from `IsHungAppWindow` on visible top-level windows.
- Launch time uses ETW process start plus first visible top-level window. Processes that predate the current ETW session are excluded.
- An agent candidate requires a configured name/path fragment, a missing live parent, minimum age, CPU under 1%, and combined I/O under 1 MiB/s for the sustained window.

## Safe actions

Recommendations avoid registry cleaners, blanket service/device disabling, and automatic process killing. The only destructive runtime action is a process termination explicitly requested in the inspector, confirmed in the UI, and revalidated by the service.
