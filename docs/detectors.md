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

Collector self-monitoring treats absolute budgets and growth as different conditions. Working set at or above 25 MB, CPU at or above 0.2%, or 600 or more handles creates a critical candidate and lists the breached dimension first. Working-set growth is suppressed during the first ten minutes, requires at least four minutes of history, and must rise by at least 1 MiB across early, middle, and recent window means. A one-time cache allocation or startup settling is not a trend. Confirmed mature growth is a warning until an absolute budget is crossed.

A collector restart closes persisted open findings because monitoring continuity was interrupted. Conditions that remain present must satisfy their sustained streak again after restart.

## Leak forensics

While a handle-growth or thread-growth finding is active — for any process — the collector attaches two extra evidence captures to it:

- **Handle types.** One pass over the system handle table (`NtQuerySystemInformation`, extended handle information) builds a per-type histogram for the flagged PID. Type indexes are resolved to names once via the object-type table. The finding's evidence shows the top three per-type deltas since the finding fired, e.g. `Handle types :: Event +1870 · Section +40 · File +12`. No per-handle query and no handle duplication is ever performed, so handles in blocking states cannot stall the collector.
- **New-thread modules.** Thread IDs are snapshotted when the finding fires; on each capture, threads that appeared since then have their Win32 start address resolved and mapped to the owning module, e.g. `New-thread modules :: xul.dll x34 · nvwgf2umx.dll x3`. Threads whose process denies access are reported as `unattributed`.

Both captures take a baseline when the finding first fires, then refresh at most once per minute while it stays active; a `Forensics window` row states the span the deltas cover. Evidence rows are replaced on each capture, never accumulated, and a finding resolving clears its baselines — with no leak finding active the forensics engine performs no syscalls at all. The multi-megabyte handle-table buffer is bucketed and freed within the capture (bailing with a degraded evidence note past a 64 MB cap), and every process, thread, and snapshot handle a capture opens is closed in the same pass so the collector's 600-handle budget holds.

Privacy boundary: forensics records kernel object type names and module base file names only — never command lines, handle names, window text, or memory content.

## Interrupt attribution

While a `dpcInterrupt` finding is active, the collector answers the question the PDH counters cannot: *which driver* is doing the interrupt work. It captures a short Windows kernel trace and attaches three evidence rows to the finding:

- `ISR/DPC attribution :: storport.sys 41% · ndis.sys 27% · nvlddmkm.sys 12%` — every interrupt service routine and DPC routine address in the trace, bucketed at 64 KiB granularity and mapped to the loaded kernel driver whose base address is nearest at-or-below (`EnumDeviceDrivers`); addresses below every driver base are `unattributed`.
- `Top driver :: storport.sys — Microsoft Storage Port Driver` — the leading driver enriched with its version-resource description (or company name).
- `Trace window :: 8 s · 214k events` — the actual span and decoded event count, with `(capped)` when the storm guard ended the capture early.

Mechanics and budget:

- **Session isolation.** The capture uses a dedicated short-lived system logger session (`PcPulseIsrDpc`, `EVENT_TRACE_SYSTEM_LOGGER_MODE`, Windows 10 1703+ allows eight concurrently) enabling only the ISR and DPC kernel flags. The collector's long-lived process-lifecycle ETW session is a separate session and is never touched.
- **Trigger and cooldown.** One capture when the finding fires, then at most one every ten minutes while it stays active. A failed capture also starts the cooldown, so a denied session is not retried on every sample. With no `dpcInterrupt` finding active the engine performs no syscalls at all.
- **Bounded window.** Eight seconds of wall time, consumed in real time on a below-normal-priority thread, with a 400,000-event storm guard that stops the capture early and says so in the evidence. The session is stopped and the trace handle closed deterministically on every path, including errors (balance counters assert this in the probe harness).
- **Expected cost.** During a genuine interrupt storm the consumer processes a burst of very small callbacks — a real but brief CPU spike for up to eight seconds, at below-normal priority, at most once per ten minutes; sustained collector CPU stays far under the 0.2% budget. Metric sampling pauses for the capture window and resumes with the next sample. The bucket map is a few hundred entries at most; ETW buffer memory (≤ 768 KiB) is returned when the session stops.
- **Degraded modes.** If the session cannot start — unelevated collector, pre-1703 Windows, policy, or system-logger exhaustion — the finding carries an honest `capture degraded: …` note instead of attribution, exactly like leak forensics. If events arrive but their layout cannot be decoded, the evidence says so rather than guessing.

Privacy boundary: interrupt attribution records driver base file names and version-resource company/description strings only — never routine addresses, process data, or memory content.

## Attribution limits

- Disk latency is a system PDH value. PC Pulse names the process with the greatest current read/write rate as the likely workload owner and phrases the explanation accordingly; it does not claim proof of storage-stack ownership.
- Kernel pool allocations and DPC/interrupt work usually belong to drivers. There is no honest user-process attribution, so these findings are labeled `System / driver`; sustained DPC/interrupt findings additionally gain driver-level ISR/DPC attribution (above), while kernel pool findings recommend OEM driver checks or PoolMon.
- Unresponsive status comes from `IsHungAppWindow` on visible top-level windows.
- Launch time uses ETW process start plus first visible top-level window. Processes that predate the current ETW session are excluded.
- An agent candidate requires a configured name/path fragment, a missing live parent, minimum age, CPU under 1%, and combined I/O under 1 MiB/s for the sustained window.

## Safe actions

Recommendations avoid registry cleaners, blanket service/device disabling, and automatic process killing. The only destructive runtime action is a process termination explicitly requested in the inspector, confirmed in the UI, and revalidated by the service.
