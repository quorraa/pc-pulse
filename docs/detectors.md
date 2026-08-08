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

Collector self-monitoring treats absolute budgets and growth as different conditions. Working set at or above 25 MB, CPU at or above 0.2%, or 250 or more handles creates a critical candidate and lists the breached dimension first. Working-set growth is suppressed during the first ten minutes, requires at least four minutes of history, and must rise by at least 1 MiB across early, middle, and recent window means. A one-time cache allocation or startup settling is not a trend. Confirmed mature growth is a warning until an absolute budget is crossed.

A collector restart closes persisted open findings because monitoring continuity was interrupted. Conditions that remain present must satisfy their sustained streak again after restart.

## Attribution limits

- Disk latency is a system PDH value. PC Pulse names the process with the greatest current read/write rate as the likely workload owner and phrases the explanation accordingly; it does not claim proof of storage-stack ownership.
- Kernel pool allocations and DPC/interrupt work usually belong to drivers. There is no honest user-process attribution, so these findings are labeled `System / driver` and recommend OEM driver checks or PoolMon.
- Unresponsive status comes from `IsHungAppWindow` on visible top-level windows.
- Launch time uses ETW process start plus first visible top-level window. Processes that predate the current ETW session are excluded.
- An agent candidate requires a configured name/path fragment, a missing live parent, minimum age, CPU under 1%, and combined I/O under 1 MiB/s for the sustained window.

## Safe actions

Recommendations avoid registry cleaners, blanket service/device disabling, and automatic process killing. The only destructive runtime action is a process termination explicitly requested in the inspector, confirmed in the UI, and revalidated by the service.
